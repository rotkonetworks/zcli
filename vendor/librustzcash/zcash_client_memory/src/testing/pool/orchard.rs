use crate::testing;

use orchard::note::NoteVersion;
use zcash_client_backend::data_api::testing::orchard::OrchardPoolTester;
use zcash_client_backend::data_api::testing::sapling::SaplingPoolTester;
#[cfg(zcash_unstable = "nu6.3")]
use zcash_client_backend::data_api::{
    ORCHARD_SHARD_HEIGHT, SAPLING_SHARD_HEIGHT, TargetValue, scanning::ScanPriority,
    wallet::TargetHeight,
};
use zcash_client_backend::{
    data_api::{
        Account as _,
        testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
        wallet::ConfirmationsPolicy,
    },
    wallet::Note,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::value::Zatoshis;

#[cfg(zcash_unstable = "nu6.3")]
use incrementalmerkletree::Address;

use crate::testing::{MemBlockCache, TestMemDbFactory};

#[test]
fn wallet_summary_counts_v3_notes_as_ironwood() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestMemDbFactory::new())
        .with_block_cache(MemBlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = OrchardPoolTester::test_account_fvk(&st);
    let value = Zatoshis::const_from_u64(50000);
    let (height, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(height, 1);

    let summary = st.get_wallet_summary(ConfirmationsPolicy::MIN).unwrap();
    let balance = summary.account_balances().get(&account.id()).unwrap();
    assert_eq!(balance.orchard_balance().total(), value);
    assert_eq!(balance.ironwood_balance().total(), Zatoshis::ZERO);
    assert_eq!(balance.spendable_value(), value);

    let received_note = st
        .wallet_mut()
        .received_notes
        .0
        .iter_mut()
        .find(|note| matches!(note.note, Note::Orchard(_)))
        .unwrap();
    if let Note::Orchard(note) = received_note.note {
        received_note.note = Note::Orchard(
            orchard::Note::from_parts(
                note.recipient(),
                note.value(),
                note.rho(),
                *note.rseed(),
                NoteVersion::V3,
            )
            .into_option()
            .unwrap(),
        );
    }

    let summary = st.get_wallet_summary(ConfirmationsPolicy::MIN).unwrap();
    let balance = summary.account_balances().get(&account.id()).unwrap();
    assert_eq!(balance.orchard_balance().total(), Zatoshis::ZERO);
    assert_eq!(balance.ironwood_balance().total(), value);
    if cfg!(zcash_unstable = "nu6.3") {
        assert_eq!(balance.spendable_value(), value);
    } else {
        assert_eq!(balance.spendable_value(), Zatoshis::ZERO);
    }
}

#[test]
#[cfg(zcash_unstable = "nu6.3")]
fn v3_ironwood_notes_in_ironwood_unscanned_ranges_are_not_spendable() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestMemDbFactory::new())
        .with_block_cache(MemBlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().unwrap();
    let dfvk = OrchardPoolTester::test_account_fvk(&st);
    let value = Zatoshis::const_from_u64(50000);
    let (height, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(height, 1);

    let note_position = {
        let received_note = st
            .wallet_mut()
            .received_notes
            .0
            .iter_mut()
            .find(|note| matches!(note.note, Note::Orchard(_)))
            .unwrap();
        if let Note::Orchard(note) = received_note.note {
            received_note.note = Note::Orchard(
                orchard::Note::from_parts(
                    note.recipient(),
                    note.value(),
                    note.rho(),
                    *note.rseed(),
                    NoteVersion::V3,
                )
                .into_option()
                .unwrap(),
            );
        }
        received_note.commitment_tree_position.unwrap()
    };

    let scan_start = height;
    let scan_end = height + 1;
    let wallet = st.wallet_mut();
    wallet
        .scan_queue
        .0
        .push((scan_start, scan_end, ScanPriority::Historic));

    let sapling_shard_index =
        Address::above_position(SAPLING_SHARD_HEIGHT.into(), note_position).index() + 1;
    wallet.sapling_tree_shard_end_heights.insert(
        Address::from_parts(SAPLING_SHARD_HEIGHT.into(), sapling_shard_index),
        scan_start.saturating_sub(1),
    );
    wallet.sapling_tree_shard_end_heights.insert(
        Address::from_parts(SAPLING_SHARD_HEIGHT.into(), sapling_shard_index + 1),
        scan_end,
    );

    let ironwood_shard_index =
        Address::above_position(ORCHARD_SHARD_HEIGHT.into(), note_position).index();
    wallet.ironwood_tree_shard_end_heights.insert(
        Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), ironwood_shard_index),
        scan_start.saturating_sub(1),
    );
    wallet.ironwood_tree_shard_end_heights.insert(
        Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), ironwood_shard_index + 1),
        scan_end,
    );

    let summary = st.get_wallet_summary(ConfirmationsPolicy::MIN).unwrap();
    let balance = summary.account_balances().get(&account.id()).unwrap();
    assert_eq!(balance.orchard_balance().total(), Zatoshis::ZERO);
    assert_eq!(balance.ironwood_balance().total(), value);
    assert_eq!(balance.ironwood_balance().spendable_value(), Zatoshis::ZERO);
    assert_eq!(balance.spendable_value(), Zatoshis::ZERO);

    let spendable = OrchardPoolTester::select_spendable_notes(
        &st,
        account.id(),
        TargetValue::AtLeast(value),
        TargetHeight::from(height + 1),
        ConfirmationsPolicy::MIN,
        &[],
    )
    .unwrap();
    assert!(spendable.is_empty());
}

#[test]
fn send_single_step_proposed_transfer() {
    testing::pool::send_single_step_proposed_transfer::<OrchardPoolTester>()
}

#[test]
fn scan_full_block_detects_outputs() {
    testing::pool::scan_full_block_detects_outputs::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
#[cfg(feature = "transparent-inputs")]
fn send_multi_step_proposed_transfer() {
    testing::pool::send_multi_step_proposed_transfer::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
#[cfg(feature = "transparent-inputs")]
fn proposal_fails_if_not_all_ephemeral_outputs_consumed() {
    testing::pool::proposal_fails_if_not_all_ephemeral_outputs_consumed::<OrchardPoolTester>()
}

#[test]
#[allow(deprecated)]
fn create_to_address_fails_on_incorrect_usk() {
    testing::pool::create_to_address_fails_on_incorrect_usk::<OrchardPoolTester>()
}

#[test]
#[allow(deprecated)]
fn proposal_fails_with_no_blocks() {
    testing::pool::proposal_fails_with_no_blocks::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn spend_fails_on_unverified_notes() {
    testing::pool::spend_fails_on_unverified_notes::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn spend_fails_on_locked_notes() {
    testing::pool::spend_fails_on_locked_notes::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn ovk_policy_prevents_recovery_from_chain() {
    testing::pool::ovk_policy_prevents_recovery_from_chain::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn spend_succeeds_to_t_addr_zero_change() {
    testing::pool::spend_succeeds_to_t_addr_zero_change::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn change_note_spends_succeed() {
    testing::pool::change_note_spends_succeed::<OrchardPoolTester>()
}

#[test]
fn external_address_change_spends_detected_in_restore_from_seed() {
    testing::pool::external_address_change_spends_detected_in_restore_from_seed::<OrchardPoolTester>(
    )
}

#[test]
#[ignore] // FIXME: #1316 This requires support for dust outputs.
fn zip317_spend() {
    testing::pool::zip317_spend::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
#[cfg(feature = "transparent-inputs")]
fn shield_transparent() {
    testing::pool::shield_transparent::<OrchardPoolTester>()
}

#[test]
fn birthday_in_anchor_shard() {
    testing::pool::birthday_in_anchor_shard::<OrchardPoolTester>()
}

#[test]
fn checkpoint_gaps() {
    testing::pool::checkpoint_gaps::<OrchardPoolTester>()
}

#[test]
#[cfg(feature = "orchard")]
fn pool_crossing_required() {
    testing::pool::pool_crossing_required::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
#[cfg(feature = "orchard")]
fn fully_funded_fully_private() {
    testing::pool::fully_funded_fully_private::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
#[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
#[ignore] //FIXME
fn fully_funded_send_to_t() {
    testing::pool::fully_funded_send_to_t::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
#[cfg(feature = "orchard")]
fn multi_pool_checkpoint() {
    testing::pool::multi_pool_checkpoint::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
#[cfg(feature = "orchard")]
fn multi_pool_checkpoints_with_pruning() {
    testing::pool::multi_pool_checkpoints_with_pruning::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
fn valid_chain_states() {
    testing::pool::valid_chain_states::<OrchardPoolTester>()
}

#[test]
fn invalid_chain_cache_disconnected() {
    testing::pool::invalid_chain_cache_disconnected::<OrchardPoolTester>()
}

#[test]
fn data_db_truncation() {
    testing::pool::data_db_truncation::<OrchardPoolTester>()
}

#[test]
fn scan_cached_blocks_allows_blocks_out_of_order() {
    testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<OrchardPoolTester>()
}

#[test]
fn scan_cached_blocks_finds_received_notes() {
    testing::pool::scan_cached_blocks_finds_received_notes::<OrchardPoolTester>()
}

#[test]
fn scan_cached_blocks_finds_change_notes() {
    testing::pool::scan_cached_blocks_finds_change_notes::<OrchardPoolTester>()
}

#[test]
fn scan_cached_blocks_detects_spends_out_of_order() {
    testing::pool::scan_cached_blocks_detects_spends_out_of_order::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn receive_two_notes_with_same_value() {
    testing::pool::receive_two_notes_with_same_value::<OrchardPoolTester>()
}
