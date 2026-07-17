use std::collections::HashSet;
use std::convert::TryFrom;
use std::hash::Hash;

use incrementalmerkletree::Retention;
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain};
use subtle::ConditionallySelectable;

use tracing::{debug, trace};
use zcash_note_encryption::batch;
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_protocol::{
    TxId,
    consensus::{self, BlockHeight, NetworkUpgrade, TxIndex},
};

use super::{Nullifiers, PositionTracker, ScanError, ScanningKeys, find_received, find_spent};
use crate::{
    data_api::{BlockMetadata, NoteCommitmentTree, ScannedBlock, ScannedBundles},
    proto::compact_formats::{ChainMetadata, CompactBlock, CompactTx},
    scan::{Batch, BatchRunner, CompactDecryptor, Tasks},
    wallet::{WalletSpend, WalletTx},
};

#[cfg(feature = "orchard")]
use orchard::{
    note_encryption::{CompactAction, OrchardDomain},
    tree::MerkleHashOrchard,
};

#[cfg(not(all(feature = "orchard", zcash_unstable = "nu6.3")))]
use std::marker::PhantomData;

type TaggedSaplingBatch<IvkTag> = Batch<
    IvkTag,
    SaplingDomain,
    sapling::note_encryption::CompactOutputDescription,
    CompactDecryptor,
>;
type TaggedSaplingBatchRunner<IvkTag, Tasks> = BatchRunner<
    IvkTag,
    SaplingDomain,
    sapling::note_encryption::CompactOutputDescription,
    CompactDecryptor,
    Tasks,
>;

#[cfg(feature = "orchard")]
type TaggedOrchardBatch<IvkTag> =
    Batch<IvkTag, OrchardDomain, orchard::note_encryption::CompactAction, CompactDecryptor>;
#[cfg(feature = "orchard")]
type TaggedOrchardBatchRunner<IvkTag, Tasks> = BatchRunner<
    IvkTag,
    OrchardDomain,
    orchard::note_encryption::CompactAction,
    CompactDecryptor,
    Tasks,
>;

fn checked_tree_size_add(
    tree: NoteCommitmentTree,
    at_height: BlockHeight,
    position: u32,
    output_count: usize,
) -> Result<u32, ScanError> {
    let output_count =
        u32::try_from(output_count).map_err(|_| ScanError::TreeSizeOverflow { tree, at_height })?;

    position
        .checked_add(output_count)
        .ok_or(ScanError::TreeSizeOverflow { tree, at_height })
}

fn invalid_compact_encoding(
    at_height: BlockHeight,
    txid: TxId,
    tree: NoteCommitmentTree,
    index: usize,
) -> ScanError {
    ScanError::EncodingInvalid {
        at_height,
        txid,
        tree,
        index,
    }
}

pub(crate) trait SaplingTasks<IvkTag>: Tasks<TaggedSaplingBatch<IvkTag>> {}
impl<IvkTag, T: Tasks<TaggedSaplingBatch<IvkTag>>> SaplingTasks<IvkTag> for T {}

#[cfg(not(feature = "orchard"))]
pub(crate) trait OrchardTasks<IvkTag> {}
#[cfg(not(feature = "orchard"))]
impl<IvkTag, T> OrchardTasks<IvkTag> for T {}

#[cfg(feature = "orchard")]
pub(crate) trait OrchardTasks<IvkTag>: Tasks<TaggedOrchardBatch<IvkTag>> {}
#[cfg(feature = "orchard")]
impl<IvkTag, T: Tasks<TaggedOrchardBatch<IvkTag>>> OrchardTasks<IvkTag> for T {}

pub(crate) struct BatchRunners<IvkTag, TS: SaplingTasks<IvkTag>, TO: OrchardTasks<IvkTag>> {
    sapling: TaggedSaplingBatchRunner<IvkTag, TS>,
    #[cfg(feature = "orchard")]
    orchard: TaggedOrchardBatchRunner<IvkTag, TO>,
    #[cfg(not(feature = "orchard"))]
    orchard: PhantomData<TO>,
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    ironwood: TaggedOrchardBatchRunner<IvkTag, TO>,
    #[cfg(not(all(feature = "orchard", zcash_unstable = "nu6.3")))]
    ironwood: PhantomData<TO>,
}

impl<IvkTag, TS, TO> BatchRunners<IvkTag, TS, TO>
where
    IvkTag: Clone + Send + 'static,
    TS: SaplingTasks<IvkTag>,
    TO: OrchardTasks<IvkTag>,
{
    pub(crate) fn for_keys<AccountId>(
        batch_size_threshold: usize,
        scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    ) -> Self {
        BatchRunners {
            sapling: BatchRunner::new(
                batch_size_threshold,
                scanning_keys
                    .sapling()
                    .iter()
                    .map(|(id, key)| (id.clone(), key.prepare())),
            ),
            #[cfg(feature = "orchard")]
            orchard: BatchRunner::new(
                batch_size_threshold,
                scanning_keys
                    .orchard()
                    .iter()
                    .map(|(id, key)| (id.clone(), key.prepare())),
            ),
            #[cfg(not(feature = "orchard"))]
            orchard: PhantomData,
            #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
            ironwood: BatchRunner::new(
                batch_size_threshold,
                scanning_keys
                    .orchard()
                    .iter()
                    .map(|(id, key)| (id.clone(), key.prepare())),
            ),
            #[cfg(not(all(feature = "orchard", zcash_unstable = "nu6.3")))]
            ironwood: PhantomData,
        }
    }

    pub(crate) fn flush(&mut self) {
        self.sapling.flush();
        #[cfg(feature = "orchard")]
        self.orchard.flush();
        #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
        self.ironwood.flush();
    }

    #[tracing::instrument(skip_all, fields(height = block.height))]
    pub(crate) fn add_block<P>(&mut self, params: &P, block: CompactBlock) -> Result<(), ScanError>
    where
        P: consensus::Parameters + Send + 'static,
        IvkTag: Copy + Send + 'static,
    {
        let block_hash = block.hash();
        let block_height = block.height();
        let zip212_enforcement = zip212_enforcement(params, block_height);

        for tx in block.vtx.into_iter() {
            let txid = tx.txid();

            self.sapling.add_outputs(
                block_hash,
                txid,
                |_| SaplingDomain::new(zip212_enforcement),
                tx.outputs
                    .iter()
                    .enumerate()
                    .map(|(i, output)| {
                        CompactOutputDescription::try_from(output).map_err(|_| {
                            invalid_compact_encoding(
                                block_height,
                                txid,
                                NoteCommitmentTree::Sapling,
                                i,
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            #[cfg(feature = "orchard")]
            self.orchard.add_outputs(
                block_hash,
                txid,
                OrchardDomain::for_compact_action,
                tx.actions
                    .iter()
                    .enumerate()
                    .map(|(i, action)| {
                        CompactAction::try_from(action).map_err(|_| {
                            invalid_compact_encoding(
                                block_height,
                                txid,
                                NoteCommitmentTree::Orchard,
                                i,
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
            self.ironwood.add_outputs(
                block_hash,
                txid,
                OrchardDomain::for_compact_action,
                tx.ironwood_actions
                    .iter()
                    .enumerate()
                    .map(|(i, action)| {
                        CompactAction::try_from(action).map_err(|_| {
                            invalid_compact_encoding(
                                block_height,
                                txid,
                                NoteCommitmentTree::Ironwood,
                                i,
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }

        Ok(())
    }
}

#[tracing::instrument(skip_all, fields(height = block.height))]
pub(crate) fn scan_block_with_runners<P, AccountId, IvkTag, TS, TO>(
    params: &P,
    block: CompactBlock,
    scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    nullifiers: &Nullifiers<AccountId>,
    prior_block_metadata: Option<&BlockMetadata>,
    mut batch_runners: Option<&mut BatchRunners<IvkTag, TS, TO>>,
) -> Result<ScannedBlock<AccountId>, ScanError>
where
    P: consensus::Parameters + Send + 'static,
    AccountId: Default + Eq + Hash + ConditionallySelectable + Send + Sync + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
    TS: SaplingTasks<IvkTag> + Sync,
    TO: OrchardTasks<IvkTag> + Sync,
{
    fn check_hash_continuity(
        block: &CompactBlock,
        prior_block_metadata: Option<&BlockMetadata>,
    ) -> Option<ScanError> {
        if let Some(prev) = prior_block_metadata {
            if block.height() != prev.block_height() + 1 {
                debug!(
                    "Block height discontinuity at {:?}, previous was {:?} ",
                    block.height(),
                    prev.block_height()
                );
                return Some(ScanError::BlockHeightDiscontinuity {
                    prev_height: prev.block_height(),
                    new_height: block.height(),
                });
            }

            if block.prev_hash() != prev.block_hash() {
                debug!("Block hash discontinuity at {:?}", block.height());
                return Some(ScanError::PrevHashMismatch {
                    at_height: block.height(),
                });
            }
        }

        None
    }

    if let Some(scan_error) = check_hash_continuity(&block, prior_block_metadata) {
        return Err(scan_error);
    }

    trace!("Block continuity okay at {:?}", block.height());

    let cur_height = block.height();
    let cur_hash = block.hash();
    let zip212_enforcement = zip212_enforcement(params, cur_height);

    let mut pos_tracker = PositionTracker::for_compact_block(params, &block, prior_block_metadata)?;

    let mut wtxs: Vec<WalletTx<AccountId>> = vec![];

    let mut sapling_nullifier_map = Vec::with_capacity(block.vtx.len());
    let mut sapling_note_commitments: Vec<(sapling::Node, Retention<BlockHeight>)> = vec![];

    #[cfg(feature = "orchard")]
    let mut orchard_nullifier_map = Vec::with_capacity(block.vtx.len());
    #[cfg(feature = "orchard")]
    let mut orchard_note_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = vec![];
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    let mut ironwood_nullifier_map = Vec::with_capacity(block.vtx.len());
    #[cfg(all(feature = "orchard", not(zcash_unstable = "nu6.3")))]
    let ironwood_nullifier_map = Vec::with_capacity(block.vtx.len());
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    let mut ironwood_note_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = vec![];
    #[cfg(all(feature = "orchard", not(zcash_unstable = "nu6.3")))]
    let ironwood_note_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = vec![];

    for tx in block.vtx.into_iter() {
        let txid = tx.txid();
        let tx_index =
            TxIndex::try_from(tx.index).expect("Cannot fit more than 2^16 transactions in a block");

        let sapling_spend_nullifiers = tx
            .spends
            .iter()
            .enumerate()
            .map(|(i, spend)| {
                spend.nf().map_err(|_| {
                    invalid_compact_encoding(cur_height, txid, NoteCommitmentTree::Sapling, i)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (sapling_spends, sapling_unlinked_nullifiers) = find_spent(
            &sapling_spend_nullifiers,
            &nullifiers.sapling,
            |nf| *nf,
            WalletSpend::from_parts,
        );

        sapling_nullifier_map.push((tx_index, txid, sapling_unlinked_nullifiers));

        #[cfg(feature = "orchard")]
        let orchard_spends = {
            let orchard_action_nullifiers = tx
                .actions
                .iter()
                .enumerate()
                .map(|(i, spend)| {
                    spend.nf().map_err(|_| {
                        invalid_compact_encoding(cur_height, txid, NoteCommitmentTree::Orchard, i)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (orchard_spends, orchard_unlinked_nullifiers) = find_spent(
                &orchard_action_nullifiers,
                &nullifiers.orchard,
                |nf| *nf,
                WalletSpend::from_parts,
            );
            orchard_nullifier_map.push((tx_index, txid, orchard_unlinked_nullifiers));
            orchard_spends
        };
        #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
        let ironwood_spends = {
            let ironwood_action_nullifiers = tx
                .ironwood_actions
                .iter()
                .enumerate()
                .map(|(i, spend)| {
                    spend.nf().map_err(|_| {
                        invalid_compact_encoding(cur_height, txid, NoteCommitmentTree::Ironwood, i)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (ironwood_spends, ironwood_unlinked_nullifiers) = find_spent(
                &ironwood_action_nullifiers,
                &nullifiers.orchard,
                |nf| *nf,
                |index, nf, account_id| {
                    WalletSpend::from_parts(tx.actions.len() + index, nf, account_id)
                },
            );
            ironwood_nullifier_map.push((tx_index, txid, ironwood_unlinked_nullifiers));
            ironwood_spends
        };
        #[cfg(all(feature = "orchard", not(zcash_unstable = "nu6.3")))]
        let ironwood_spends: Vec<WalletSpend<orchard::note::Nullifier, AccountId>> = Vec::new();

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts = sapling_spends.iter().map(|spend| spend.account_id());
        #[cfg(feature = "orchard")]
        let spent_from_accounts = spent_from_accounts
            .chain(orchard_spends.iter().map(|spend| spend.account_id()))
            .chain(ironwood_spends.iter().map(|spend| spend.account_id()));
        let spent_from_accounts = spent_from_accounts.copied().collect::<HashSet<_>>();

        let (sapling_outputs, mut sapling_nc) = find_received(
            cur_height,
            pos_tracker.compact_tx_contains_last_sapling_outputs_in_block(cur_height, &tx)?,
            txid,
            NoteCommitmentTree::Sapling,
            |output_idx| output_idx,
            |output_idx| pos_tracker.sapling_note_position(output_idx),
            &scanning_keys.sapling,
            &spent_from_accounts,
            &tx.outputs
                .iter()
                .enumerate()
                .map(|(i, output)| {
                    Ok((
                        SaplingDomain::new(zip212_enforcement),
                        CompactOutputDescription::try_from(output).map_err(|_| {
                            invalid_compact_encoding(
                                cur_height,
                                txid,
                                NoteCommitmentTree::Sapling,
                                i,
                            )
                        })?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
            batch_runners
                .as_mut()
                .map(|runners| |txid| runners.sapling.collect_results(cur_hash, txid)),
            |ivks, outputs| {
                batch::try_compact_note_decryption(ivks, outputs)
                    .into_iter()
                    .map(|opt| opt.map(|((note, recipient), i)| ((note, recipient, ()), i)))
                    .collect()
            },
            |output| sapling::Node::from_cmu(&output.cmu),
        );
        sapling_note_commitments.append(&mut sapling_nc);
        let has_sapling = !(sapling_spends.is_empty() && sapling_outputs.is_empty());

        #[cfg(feature = "orchard")]
        let (mut orchard_outputs, mut orchard_nc) = find_received(
            cur_height,
            pos_tracker.compact_tx_contains_last_orchard_actions_in_block(cur_height, &tx)?,
            txid,
            NoteCommitmentTree::Orchard,
            |output_idx| output_idx,
            |output_idx| pos_tracker.orchard_note_position(output_idx),
            &scanning_keys.orchard,
            &spent_from_accounts,
            &tx.actions
                .iter()
                .enumerate()
                .map(|(i, action)| {
                    let action = CompactAction::try_from(action).map_err(|_| {
                        invalid_compact_encoding(cur_height, txid, NoteCommitmentTree::Orchard, i)
                    })?;
                    Ok((OrchardDomain::for_compact_action(&action), action))
                })
                .collect::<Result<Vec<_>, _>>()?,
            batch_runners
                .as_mut()
                .map(|runners| |txid| runners.orchard.collect_results(cur_hash, txid)),
            |ivks, outputs| {
                batch::try_compact_note_decryption(ivks, outputs)
                    .into_iter()
                    .map(|opt| opt.map(|((note, recipient), i)| ((note, recipient, ()), i)))
                    .collect()
            },
            |output| MerkleHashOrchard::from_cmx(&output.cmx()),
        );
        #[cfg(feature = "orchard")]
        orchard_note_commitments.append(&mut orchard_nc);

        #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
        let (mut ironwood_outputs, mut ironwood_nc) = find_received(
            cur_height,
            pos_tracker.compact_tx_contains_last_ironwood_actions_in_block(cur_height, &tx)?,
            txid,
            NoteCommitmentTree::Ironwood,
            // Ironwood is represented as Orchard-shaped V3 outputs at this API boundary. Offset
            // Ironwood action indices by the Orchard action count so mixed-bundle transactions have
            // unique Orchard output identifiers.
            |output_idx| tx.actions.len() + output_idx,
            |output_idx| pos_tracker.ironwood_note_position(output_idx),
            &scanning_keys.orchard,
            &spent_from_accounts,
            &tx.ironwood_actions
                .iter()
                .enumerate()
                .map(|(i, action)| {
                    let action = CompactAction::try_from(action).map_err(|_| {
                        invalid_compact_encoding(cur_height, txid, NoteCommitmentTree::Ironwood, i)
                    })?;
                    Ok((OrchardDomain::for_compact_action(&action), action))
                })
                .collect::<Result<Vec<_>, _>>()?,
            batch_runners
                .as_mut()
                .map(|runners| |txid| runners.ironwood.collect_results(cur_hash, txid)),
            |ivks, outputs| {
                batch::try_compact_note_decryption(ivks, outputs)
                    .into_iter()
                    .map(|opt| opt.map(|((note, recipient), i)| ((note, recipient, ()), i)))
                    .collect()
            },
            |output| MerkleHashOrchard::from_cmx(&output.cmx()),
        );
        #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
        {
            ironwood_note_commitments.append(&mut ironwood_nc);
        }
        #[cfg(all(feature = "orchard", not(zcash_unstable = "nu6.3")))]
        let mut ironwood_outputs = Vec::new();
        #[cfg(feature = "orchard")]
        let has_orchard = !(orchard_spends.is_empty()
            && ironwood_spends.is_empty()
            && orchard_outputs.is_empty()
            && ironwood_outputs.is_empty());
        #[cfg(not(feature = "orchard"))]
        let has_orchard = false;

        if has_sapling || has_orchard {
            #[cfg(feature = "orchard")]
            let mut wallet_orchard_spends = orchard_spends;
            #[cfg(feature = "orchard")]
            wallet_orchard_spends.extend(ironwood_spends);
            #[cfg(feature = "orchard")]
            orchard_outputs.append(&mut ironwood_outputs);

            wtxs.push(WalletTx::new(
                txid,
                tx_index,
                // TODO: Scan transparent data in CompactTx if present.
                // https://github.com/zcash/librustzcash/issues/2187
                vec![],
                sapling_spends,
                sapling_outputs,
                #[cfg(feature = "orchard")]
                wallet_orchard_spends,
                #[cfg(feature = "orchard")]
                orchard_outputs,
            ));
        }

        pos_tracker.increment_over_compact_tx(cur_height, &tx)?;
    }

    pos_tracker.check_end_of_compact_block_consistency(cur_height, block.chain_metadata)?;

    Ok(ScannedBlock::from_parts(
        cur_height,
        cur_hash,
        block.time,
        wtxs,
        ScannedBundles::new(
            pos_tracker.sapling_final_tree_size,
            sapling_note_commitments,
            sapling_nullifier_map,
        ),
        #[cfg(feature = "orchard")]
        ScannedBundles::new(
            pos_tracker.orchard_final_tree_size,
            orchard_note_commitments,
            orchard_nullifier_map,
        ),
        #[cfg(feature = "orchard")]
        ScannedBundles::new(
            pos_tracker.ironwood_final_tree_size,
            ironwood_note_commitments,
            ironwood_nullifier_map,
        ),
    ))
}

impl PositionTracker {
    fn for_compact_block<P>(
        params: &P,
        block: &CompactBlock,
        prior_block_metadata: Option<&BlockMetadata>,
    ) -> Result<Self, ScanError>
    where
        P: consensus::Parameters,
    {
        /// Returns the size of the given shielded protocol's note commitment tree before and
        /// after the application of the given block.
        #[allow(clippy::too_many_arguments)]
        fn tree_sizes_around<P>(
            params: &P,
            block: &CompactBlock,
            prior_block_metadata: Option<&BlockMetadata>,
            tree: NoteCommitmentTree,
            activation_nu: NetworkUpgrade,
            prior_tree_size: impl Fn(&BlockMetadata) -> Option<u32>,
            tx_output_count: impl Fn(&CompactTx) -> usize,
            final_tree_size: impl Fn(&ChainMetadata) -> u32,
        ) -> Result<(u32, u32), ScanError>
        where
            P: consensus::Parameters,
        {
            let at_height = block.height();
            let overflow = || ScanError::TreeSizeOverflow { tree, at_height };
            let output_count = block.vtx.iter().try_fold(0u32, |acc, tx| {
                let tx_outputs = u32::try_from(tx_output_count(tx)).map_err(|_| overflow())?;
                acc.checked_add(tx_outputs).ok_or_else(overflow)
            })?;

            let start_tree_size = prior_block_metadata.and_then(prior_tree_size).map_or_else(
                || {
                    block.chain_metadata.as_ref().map_or_else(
                        || {
                            // If we're below the protocol's activation height, or it is
                            // not set, the tree size is zero.
                            params.activation_height(activation_nu).map_or_else(
                                || Ok(0),
                                |activation_height| {
                                    if at_height < activation_height {
                                        Ok(0)
                                    } else {
                                        Err(ScanError::TreeSizeUnknown { tree, at_height })
                                    }
                                },
                            )
                        },
                        |m| {
                            // The default for `final_tree_size(m)` is zero, so we need to
                            // check that the subtraction will not underflow; if it would
                            // do so, we were given invalid chain metadata for a block
                            // with outputs in this shielded protocol.
                            final_tree_size(m)
                                .checked_sub(output_count)
                                .ok_or(ScanError::TreeSizeInvalid { tree, at_height })
                        },
                    )
                },
                Ok,
            )?;

            // We pre-compute the end tree size here so we can determine when we reach the
            // last transaction in the block that adds notes to the tree. This enables us
            // to correctly set the tree checkpoint in `find_received`.
            let end_tree_size = start_tree_size
                .checked_add(output_count)
                .ok_or_else(overflow)?;

            Ok((start_tree_size, end_tree_size))
        }

        let (sapling_prior_tree_size, sapling_final_tree_size) = tree_sizes_around(
            params,
            block,
            prior_block_metadata,
            NoteCommitmentTree::Sapling,
            NetworkUpgrade::Sapling,
            |m| m.sapling_tree_size(),
            |tx| tx.outputs.len(),
            |m| m.sapling_commitment_tree_size,
        )?;

        #[cfg(feature = "orchard")]
        let (orchard_prior_tree_size, orchard_final_tree_size) = tree_sizes_around(
            params,
            block,
            prior_block_metadata,
            NoteCommitmentTree::Orchard,
            NetworkUpgrade::Nu5,
            |m| m.orchard_tree_size(),
            |tx| tx.actions.len(),
            |m| m.orchard_commitment_tree_size,
        )?;

        #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
        let (ironwood_prior_tree_size, ironwood_final_tree_size) = tree_sizes_around(
            params,
            block,
            prior_block_metadata,
            NoteCommitmentTree::Ironwood,
            NetworkUpgrade::Nu6_3,
            |m| m.ironwood_tree_size(),
            |tx| tx.ironwood_actions.len(),
            |m| m.ironwood_commitment_tree_size,
        )?;
        #[cfg(all(feature = "orchard", not(zcash_unstable = "nu6.3")))]
        let ironwood_final_tree_size = 0;

        Ok(Self {
            sapling_tree_position: sapling_prior_tree_size,
            sapling_final_tree_size,
            #[cfg(feature = "orchard")]
            orchard_tree_position: orchard_prior_tree_size,
            #[cfg(feature = "orchard")]
            orchard_final_tree_size,
            #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
            ironwood_tree_position: ironwood_prior_tree_size,
            #[cfg(feature = "orchard")]
            ironwood_final_tree_size,
        })
    }

    fn compact_tx_contains_last_sapling_outputs_in_block(
        &self,
        at_height: BlockHeight,
        tx: &CompactTx,
    ) -> Result<bool, ScanError> {
        checked_tree_size_add(
            NoteCommitmentTree::Sapling,
            at_height,
            self.sapling_tree_position,
            tx.outputs.len(),
        )
        .map(|position| position == self.sapling_final_tree_size)
    }

    #[cfg(feature = "orchard")]
    fn compact_tx_contains_last_orchard_actions_in_block(
        &self,
        at_height: BlockHeight,
        tx: &CompactTx,
    ) -> Result<bool, ScanError> {
        checked_tree_size_add(
            NoteCommitmentTree::Orchard,
            at_height,
            self.orchard_tree_position,
            tx.actions.len(),
        )
        .map(|position| position == self.orchard_final_tree_size)
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn compact_tx_contains_last_ironwood_actions_in_block(
        &self,
        at_height: BlockHeight,
        tx: &CompactTx,
    ) -> Result<bool, ScanError> {
        checked_tree_size_add(
            NoteCommitmentTree::Ironwood,
            at_height,
            self.ironwood_tree_position,
            tx.ironwood_actions.len(),
        )
        .map(|position| position == self.ironwood_final_tree_size)
    }

    fn increment_over_compact_tx(
        &mut self,
        at_height: BlockHeight,
        tx: &CompactTx,
    ) -> Result<(), ScanError> {
        self.sapling_tree_position = checked_tree_size_add(
            NoteCommitmentTree::Sapling,
            at_height,
            self.sapling_tree_position,
            tx.outputs.len(),
        )?;

        #[cfg(feature = "orchard")]
        {
            self.orchard_tree_position = checked_tree_size_add(
                NoteCommitmentTree::Orchard,
                at_height,
                self.orchard_tree_position,
                tx.actions.len(),
            )?;
        }
        #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
        {
            self.ironwood_tree_position = checked_tree_size_add(
                NoteCommitmentTree::Ironwood,
                at_height,
                self.ironwood_tree_position,
                tx.ironwood_actions.len(),
            )?;
        }

        Ok(())
    }

    fn check_end_of_compact_block_consistency(
        &self,
        at_height: BlockHeight,
        chain_metadata: Option<ChainMetadata>,
    ) -> Result<(), ScanError> {
        // It is a programming error to construct `PositionTracker` from a `CompactBlock`
        // and then not call `PositionTracker::increment_over_tx` on every transaction
        // within the block.
        assert_eq!(self.sapling_tree_position, self.sapling_final_tree_size);
        #[cfg(feature = "orchard")]
        assert_eq!(self.orchard_tree_position, self.orchard_final_tree_size);
        #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
        assert_eq!(self.ironwood_tree_position, self.ironwood_final_tree_size);

        if let Some(chain_meta) = chain_metadata {
            if chain_meta.sapling_commitment_tree_size != self.sapling_tree_position {
                return Err(ScanError::TreeSizeMismatch {
                    tree: NoteCommitmentTree::Sapling,
                    at_height,
                    given: chain_meta.sapling_commitment_tree_size,
                    computed: self.sapling_tree_position,
                });
            }

            #[cfg(feature = "orchard")]
            if chain_meta.orchard_commitment_tree_size != self.orchard_tree_position {
                return Err(ScanError::TreeSizeMismatch {
                    tree: NoteCommitmentTree::Orchard,
                    at_height,
                    given: chain_meta.orchard_commitment_tree_size,
                    computed: self.orchard_tree_position,
                });
            }

            #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
            if chain_meta.ironwood_commitment_tree_size != self.ironwood_tree_position {
                return Err(ScanError::TreeSizeMismatch {
                    tree: NoteCommitmentTree::Ironwood,
                    at_height,
                    given: chain_meta.ironwood_commitment_tree_size,
                    computed: self.ironwood_tree_position,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::convert::Infallible;

    use incrementalmerkletree::{Marking, Position, Retention};
    use sapling::Nullifier;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{
        consensus::{BlockHeight, Network},
        value::Zatoshis,
    };
    use zip32::AccountId;

    use super::{BatchRunners, scan_block_with_runners};
    use crate::{
        data_api::{BlockMetadata, NoteCommitmentTree},
        scanning::{Nullifiers, ScanError, ScanningKeys, scan_block, testing::fake_compact_block},
    };

    #[test]
    fn scan_block_with_my_tx() {
        fn go(scan_multithreaded: bool) {
            let network = Network::TestNetwork;
            let account = AccountId::ZERO;
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
            let ufvk = usk.to_unified_full_viewing_key();
            let sapling_dfvk = ufvk.sapling().expect("Sapling key is present").clone();
            let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &sapling_dfvk,
                Zatoshis::const_from_u64(5),
                false,
                None,
            );
            assert_eq!(cb.vtx.len(), 2);

            let mut batch_runners = if scan_multithreaded {
                let mut runners = BatchRunners::<_, (), ()>::for_keys(10, &scanning_keys);
                runners
                    .add_block(&Network::TestNetwork, cb.clone())
                    .unwrap();
                runners.flush();

                Some(runners)
            } else {
                None
            };

            let scanned_block = scan_block_with_runners(
                &network,
                cb,
                &scanning_keys,
                &Nullifiers::empty(),
                Some(&BlockMetadata::from_parts(
                    BlockHeight::from(0),
                    BlockHash([0u8; 32]),
                    Some(0),
                    #[cfg(feature = "orchard")]
                    Some(0),
                    #[cfg(feature = "orchard")]
                    Some(0),
                )),
                batch_runners.as_mut(),
            )
            .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.block_index(), 1.into());
            assert_eq!(tx.sapling_spends().len(), 0);
            assert_eq!(tx.sapling_outputs().len(), 1);
            assert_eq!(tx.sapling_outputs()[0].index(), 0);
            assert_eq!(tx.sapling_outputs()[0].account_id(), &account);
            assert_eq!(tx.sapling_outputs()[0].note().value().inner(), 5);
            assert_eq!(
                tx.sapling_outputs()[0].note_commitment_tree_position(),
                Position::from(1)
            );

            assert_eq!(scanned_block.sapling().final_tree_size(), 2);
            assert_eq!(
                scanned_block
                    .sapling()
                    .commitments()
                    .iter()
                    .map(|(_, retention)| *retention)
                    .collect::<Vec<_>>(),
                vec![
                    Retention::Ephemeral,
                    Retention::Checkpoint {
                        id: scanned_block.height(),
                        marking: Marking::Marked
                    }
                ]
            );
        }

        go(false);
        go(true);
    }

    #[test]
    fn scan_block_with_txs_after_my_tx() {
        fn go(scan_multithreaded: bool) {
            let network = Network::TestNetwork;
            let account = AccountId::ZERO;
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
            let ufvk = usk.to_unified_full_viewing_key();
            let sapling_dfvk = ufvk.sapling().expect("Sapling key is present").clone();
            let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &sapling_dfvk,
                Zatoshis::const_from_u64(5),
                true,
                Some((0, 0)),
            );
            assert_eq!(cb.vtx.len(), 3);

            let mut batch_runners = if scan_multithreaded {
                let mut runners = BatchRunners::<_, (), ()>::for_keys(10, &scanning_keys);
                runners
                    .add_block(&Network::TestNetwork, cb.clone())
                    .unwrap();
                runners.flush();

                Some(runners)
            } else {
                None
            };

            let scanned_block = scan_block_with_runners(
                &network,
                cb,
                &scanning_keys,
                &Nullifiers::empty(),
                None,
                batch_runners.as_mut(),
            )
            .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.block_index(), 1.into());
            assert_eq!(tx.sapling_spends().len(), 0);
            assert_eq!(tx.sapling_outputs().len(), 1);
            assert_eq!(tx.sapling_outputs()[0].index(), 0);
            assert_eq!(tx.sapling_outputs()[0].account_id(), &AccountId::ZERO);
            assert_eq!(tx.sapling_outputs()[0].note().value().inner(), 5);

            assert_eq!(
                scanned_block
                    .sapling()
                    .commitments()
                    .iter()
                    .map(|(_, retention)| *retention)
                    .collect::<Vec<_>>(),
                vec![
                    Retention::Ephemeral,
                    Retention::Marked,
                    Retention::Checkpoint {
                        id: scanned_block.height(),
                        marking: Marking::None
                    }
                ]
            );
        }

        go(false);
        go(true);
    }

    #[test]
    fn scan_block_with_my_spend() {
        let network = Network::TestNetwork;
        let account = AccountId::try_from(12).unwrap();
        let usk = UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
        let ufvk = usk.to_unified_full_viewing_key();
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();

        let nf = Nullifier([7; 32]);
        let nullifiers = Nullifiers::new(
            vec![(account, nf)],
            #[cfg(feature = "orchard")]
            vec![],
        );

        let cb = fake_compact_block(
            1u32.into(),
            BlockHash([0; 32]),
            nf,
            ufvk.sapling().unwrap(),
            Zatoshis::const_from_u64(5),
            false,
            Some((0, 0)),
        );
        assert_eq!(cb.vtx.len(), 2);

        let scanned_block = scan_block(&network, cb, &scanning_keys, &nullifiers, None).unwrap();
        let txs = scanned_block.transactions();
        assert_eq!(txs.len(), 1);

        let tx = &txs[0];
        assert_eq!(tx.block_index(), 1.into());
        assert_eq!(tx.sapling_spends().len(), 1);
        assert_eq!(tx.sapling_outputs().len(), 0);
        assert_eq!(tx.sapling_spends()[0].index(), 0);
        assert_eq!(tx.sapling_spends()[0].nf(), &nf);
        assert_eq!(tx.sapling_spends()[0].account_id(), &account);

        assert_eq!(
            scanned_block
                .sapling()
                .commitments()
                .iter()
                .map(|(_, retention)| *retention)
                .collect::<Vec<_>>(),
            vec![
                Retention::Ephemeral,
                Retention::Checkpoint {
                    id: scanned_block.height(),
                    marking: Marking::None
                }
            ]
        );
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn malformed_ironwood_action_block() -> crate::proto::compact_formats::CompactBlock {
        use crate::proto::compact_formats::{ChainMetadata, CompactBlock, CompactOrchardAction};

        CompactBlock {
            proto_version: 4,
            height: 1,
            hash: vec![0; 32],
            prev_hash: vec![1; 32],
            time: 0,
            header: vec![],
            vtx: vec![crate::proto::compact_formats::CompactTx {
                index: 0,
                txid: vec![2; 32],
                fee: 0,
                spends: vec![],
                outputs: vec![],
                actions: vec![],
                vin: vec![],
                vout: vec![],
                ironwood_actions: vec![CompactOrchardAction {
                    nullifier: vec![3; 32],
                    cmx: vec![4; 31],
                    ephemeral_key: vec![5; 32],
                    ciphertext: vec![6; 52],
                }],
            }],
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: 0,
                ironwood_commitment_tree_size: 1,
            }),
        }
    }

    fn malformed_sapling_spend_block() -> crate::proto::compact_formats::CompactBlock {
        use crate::proto::compact_formats::{CompactBlock, CompactSaplingSpend, CompactTx};

        CompactBlock {
            proto_version: 4,
            height: 1,
            hash: vec![0; 32],
            prev_hash: vec![1; 32],
            time: 0,
            header: vec![],
            vtx: vec![CompactTx {
                index: 0,
                txid: vec![2; 32],
                fee: 0,
                spends: vec![CompactSaplingSpend { nf: vec![3; 31] }],
                outputs: vec![],
                actions: vec![],
                vin: vec![],
                vout: vec![],
                ironwood_actions: vec![],
            }],
            chain_metadata: None,
        }
    }

    fn malformed_sapling_output_block() -> crate::proto::compact_formats::CompactBlock {
        use crate::proto::compact_formats::{CompactBlock, CompactSaplingOutput, CompactTx};

        CompactBlock {
            proto_version: 4,
            height: 1,
            hash: vec![0; 32],
            prev_hash: vec![1; 32],
            time: 0,
            header: vec![],
            vtx: vec![CompactTx {
                index: 0,
                txid: vec![2; 32],
                fee: 0,
                spends: vec![],
                outputs: vec![CompactSaplingOutput {
                    cmu: vec![3; 31],
                    ephemeral_key: vec![4; 32],
                    ciphertext: vec![5; 52],
                }],
                actions: vec![],
                vin: vec![],
                vout: vec![],
                ironwood_actions: vec![],
            }],
            chain_metadata: None,
        }
    }

    #[cfg(feature = "orchard")]
    fn malformed_orchard_nullifier_block() -> crate::proto::compact_formats::CompactBlock {
        use crate::proto::compact_formats::{CompactBlock, CompactOrchardAction, CompactTx};

        CompactBlock {
            proto_version: 4,
            height: 1,
            hash: vec![0; 32],
            prev_hash: vec![1; 32],
            time: 0,
            header: vec![],
            vtx: vec![CompactTx {
                index: 0,
                txid: vec![2; 32],
                fee: 0,
                spends: vec![],
                outputs: vec![],
                actions: vec![CompactOrchardAction {
                    nullifier: vec![3; 31],
                    cmx: vec![4; 32],
                    ephemeral_key: vec![5; 32],
                    ciphertext: vec![6; 52],
                }],
                vin: vec![],
                vout: vec![],
                ironwood_actions: vec![],
            }],
            chain_metadata: None,
        }
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn malformed_ironwood_nullifier_block() -> crate::proto::compact_formats::CompactBlock {
        use crate::proto::compact_formats::{ChainMetadata, CompactBlock, CompactOrchardAction};

        CompactBlock {
            proto_version: 4,
            height: 1,
            hash: vec![0; 32],
            prev_hash: vec![1; 32],
            time: 0,
            header: vec![],
            vtx: vec![crate::proto::compact_formats::CompactTx {
                index: 0,
                txid: vec![2; 32],
                fee: 0,
                spends: vec![],
                outputs: vec![],
                actions: vec![],
                vin: vec![],
                vout: vec![],
                ironwood_actions: vec![CompactOrchardAction {
                    nullifier: vec![3; 31],
                    cmx: vec![4; 32],
                    ephemeral_key: vec![5; 32],
                    ciphertext: vec![6; 52],
                }],
            }],
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: 0,
                ironwood_commitment_tree_size: 1,
            }),
        }
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn empty_block_with_ironwood_tree_size(
        ironwood_tree_size: u32,
    ) -> crate::proto::compact_formats::CompactBlock {
        use crate::proto::compact_formats::{ChainMetadata, CompactBlock};

        CompactBlock {
            proto_version: 4,
            height: 1,
            hash: vec![0; 32],
            prev_hash: vec![1; 32],
            time: 0,
            header: vec![],
            vtx: vec![],
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: 0,
                ironwood_commitment_tree_size: ironwood_tree_size,
            }),
        }
    }

    fn block_with_one_sapling_output() -> crate::proto::compact_formats::CompactBlock {
        use crate::proto::compact_formats::{CompactBlock, CompactSaplingOutput, CompactTx};

        CompactBlock {
            proto_version: 4,
            height: 1,
            hash: vec![0; 32],
            prev_hash: vec![1; 32],
            time: 0,
            header: vec![],
            vtx: vec![CompactTx {
                index: 0,
                txid: vec![2; 32],
                fee: 0,
                spends: vec![],
                outputs: vec![CompactSaplingOutput::default()],
                actions: vec![],
                vin: vec![],
                vout: vec![],
                ironwood_actions: vec![],
            }],
            chain_metadata: None,
        }
    }

    fn assert_decode_error(err: &ScanError, expected_tree: NoteCommitmentTree) {
        match err {
            ScanError::EncodingInvalid { tree, index, .. } => {
                assert_eq!(*tree, expected_tree);
                assert_eq!(*index, 0);
            }
            err => panic!("expected a compact decoding error, got {err:?}"),
        }

        assert!(
            err.to_string()
                .contains(&format!("{expected_tree:?} compact item 0"))
        );
    }

    #[test]
    fn scan_block_reports_sapling_tree_size_overflow() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let err = match scan_block(
            &Network::TestNetwork,
            block_with_one_sapling_output(),
            &scanning_keys,
            &Nullifiers::empty(),
            Some(&BlockMetadata::from_parts(
                BlockHeight::from(0),
                BlockHash([1; 32]),
                Some(u32::MAX),
                #[cfg(feature = "orchard")]
                Some(0),
                #[cfg(feature = "orchard")]
                Some(0),
            )),
        ) {
            Ok(_) => panic!("overflowing Sapling tree size should fail"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            ScanError::TreeSizeOverflow {
                tree: NoteCommitmentTree::Sapling,
                ..
            }
        ));
    }

    #[test]
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn scan_block_reports_ironwood_tree_size_overflow() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let err = match scan_block(
            &Network::TestNetwork,
            malformed_ironwood_action_block(),
            &scanning_keys,
            &Nullifiers::empty(),
            Some(&BlockMetadata::from_parts(
                BlockHeight::from(0),
                BlockHash([1; 32]),
                Some(0),
                Some(0),
                Some(u32::MAX),
            )),
        ) {
            Ok(_) => panic!("overflowing Ironwood tree size should fail"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            ScanError::TreeSizeOverflow {
                tree: NoteCommitmentTree::Ironwood,
                ..
            }
        ));
    }

    #[test]
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn scan_block_reports_ironwood_tree_size_mismatch() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let err = match scan_block(
            &Network::TestNetwork,
            empty_block_with_ironwood_tree_size(1),
            &scanning_keys,
            &Nullifiers::empty(),
            Some(&BlockMetadata::from_parts(
                BlockHeight::from(0),
                BlockHash([1; 32]),
                Some(0),
                Some(0),
                Some(0),
            )),
        ) {
            Ok(_) => panic!("incorrect Ironwood final tree size should fail"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            ScanError::TreeSizeMismatch {
                tree: NoteCommitmentTree::Ironwood,
                given: 1,
                computed: 0,
                ..
            }
        ));
    }

    #[test]
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn scan_block_reports_ironwood_tree_size_invalid() {
        let mut block = malformed_ironwood_action_block();
        block
            .chain_metadata
            .as_mut()
            .unwrap()
            .ironwood_commitment_tree_size = 0;

        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let err = match scan_block(
            &Network::TestNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        ) {
            Ok(_) => panic!("invalid Ironwood tree size metadata should fail before decoding"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            ScanError::TreeSizeInvalid {
                tree: NoteCommitmentTree::Ironwood,
                ..
            }
        ));
    }

    #[test]
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn scan_block_reports_ironwood_decode_error() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let err = match scan_block(
            &Network::TestNetwork,
            malformed_ironwood_action_block(),
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        ) {
            Ok(_) => panic!("malformed Ironwood action should fail decoding"),
            Err(err) => err,
        };

        assert_decode_error(&err, NoteCommitmentTree::Ironwood);
    }

    #[test]
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn batch_runners_report_ironwood_decode_error() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let mut runners = BatchRunners::<_, (), ()>::for_keys(10, &scanning_keys);
        let err = runners
            .add_block(&Network::TestNetwork, malformed_ironwood_action_block())
            .expect_err("malformed Ironwood action should fail decoding");

        assert_decode_error(&err, NoteCommitmentTree::Ironwood);
    }

    #[test]
    fn scan_block_reports_malformed_sapling_spend_nullifier() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let err = match scan_block(
            &Network::TestNetwork,
            malformed_sapling_spend_block(),
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        ) {
            Ok(_) => panic!("malformed Sapling spend nullifier should fail decoding"),
            Err(err) => err,
        };

        assert_decode_error(&err, NoteCommitmentTree::Sapling);
    }

    #[test]
    fn scan_block_reports_malformed_sapling_output_cmu() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let err = match scan_block(
            &Network::TestNetwork,
            malformed_sapling_output_block(),
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        ) {
            Ok(_) => panic!("malformed Sapling output commitment should fail decoding"),
            Err(err) => err,
        };

        assert_decode_error(&err, NoteCommitmentTree::Sapling);
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_block_reports_malformed_orchard_nullifier() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let err = match scan_block(
            &Network::TestNetwork,
            malformed_orchard_nullifier_block(),
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        ) {
            Ok(_) => panic!("malformed Orchard nullifier should fail decoding"),
            Err(err) => err,
        };

        assert_decode_error(&err, NoteCommitmentTree::Orchard);
    }

    #[test]
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn scan_block_reports_malformed_ironwood_nullifier() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let err = match scan_block(
            &Network::TestNetwork,
            malformed_ironwood_nullifier_block(),
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        ) {
            Ok(_) => panic!("malformed Ironwood nullifier should fail decoding"),
            Err(err) => err,
        };

        assert_decode_error(&err, NoteCommitmentTree::Ironwood);
    }

    #[test]
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn batch_runners_report_malformed_ironwood_nullifier() {
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let mut runners = BatchRunners::<_, (), ()>::for_keys(10, &scanning_keys);
        let err = runners
            .add_block(&Network::TestNetwork, malformed_ironwood_nullifier_block())
            .expect_err("malformed Ironwood nullifier should fail decoding");

        assert_decode_error(&err, NoteCommitmentTree::Ironwood);
    }
}
