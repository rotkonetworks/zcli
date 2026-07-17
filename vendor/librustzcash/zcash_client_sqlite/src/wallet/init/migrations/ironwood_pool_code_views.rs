//! Updates public wallet views to expose Ironwood outputs as a distinct SQLite pool code.

use std::collections::HashSet;

#[cfg(zcash_unstable = "nu6.3")]
use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;
#[cfg(zcash_unstable = "nu6.3")]
use zcash_protocol::consensus::BlockHeight;

#[cfg(zcash_unstable = "nu6.3")]
use crate::error::SqliteClientError;
#[cfg(zcash_unstable = "nu6.3")]
use crate::wallet::parse_tx;
use crate::wallet::{
    db,
    init::{
        WalletMigrationError,
        migrations::{ironwood_shardtree, v_tx_outputs_key_scopes},
    },
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xf6fb571a_2e78_4218_a2d2_241b4f787cbf);

const DEPENDENCIES: &[Uuid] = &[
    ironwood_shardtree::MIGRATION_ID,
    v_tx_outputs_key_scopes::MIGRATION_ID,
];

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Updates wallet output views to expose Ironwood rows as pool code 4."
    }
}

impl<P: consensus::Parameters> Migration<P> {
    #[cfg(zcash_unstable = "nu6.3")]
    fn backfill_sent_ironwood_pool_codes(
        &self,
        transaction: &rusqlite::Transaction,
    ) -> Result<(), WalletMigrationError> {
        let mut stmt_transactions = transaction.prepare(
            "SELECT DISTINCT
                t.id_tx, t.raw, t.mined_height, t.expiry_height
             FROM sent_notes sn
             JOIN transactions t ON t.id_tx = sn.transaction_id
             WHERE sn.output_pool = 3
             AND t.raw IS NOT NULL",
        )?;
        let rows = stmt_transactions.query_map([], |row| {
            Ok((
                row.get::<_, i64>("id_tx")?,
                row.get::<_, Vec<u8>>("raw")?,
                row.get::<_, Option<u32>>("mined_height")?
                    .map(BlockHeight::from),
                row.get::<_, Option<u32>>("expiry_height")?
                    .map(BlockHeight::from),
            ))
        })?;

        let mut tx_ranges = vec![];
        for row in rows {
            let (id_tx, raw, mined_height, expiry_height) = row?;
            let (_, tx) = parse_tx(&self.params, &raw, mined_height, expiry_height).map_err(
                |err| match err {
                    SqliteClientError::CorruptedData(msg) => {
                        WalletMigrationError::CorruptedData(msg)
                    }
                    SqliteClientError::DbError(err) => WalletMigrationError::DbError(err),
                    other => WalletMigrationError::CorruptedData(format!(
                        "An error was encountered decoding transaction data: {other:?}"
                    )),
                },
            )?;

            let orchard_action_count = tx
                .orchard_bundle()
                .map_or(0, |bundle| bundle.actions().len());
            let ironwood_action_count = tx
                .ironwood_bundle()
                .map_or(0, |bundle| bundle.actions().len());
            if ironwood_action_count > 0 {
                tx_ranges.push((
                    id_tx,
                    i64::try_from(orchard_action_count).expect("action count fits in i64"),
                    i64::try_from(orchard_action_count + ironwood_action_count)
                        .expect("action count fits in i64"),
                ));
            }
        }

        let mut stmt_update = transaction.prepare(
            "UPDATE sent_notes
             SET output_pool = 4
             WHERE transaction_id = :transaction_id
             AND output_pool = 3
             AND output_index >= :ironwood_start
             AND output_index < :ironwood_end",
        )?;
        for (id_tx, ironwood_start, ironwood_end) in tx_ranges {
            stmt_update.execute(named_params! {
                ":transaction_id": id_tx,
                ":ironwood_start": ironwood_start,
                ":ironwood_end": ironwood_end,
            })?;
        }

        Ok(())
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_tx_outputs;
             DROP VIEW v_transactions;
             DROP VIEW v_received_output_spends;
             DROP VIEW v_received_outputs;",
        )?;

        transaction.execute(
            "UPDATE sent_notes
             SET output_pool = 4
             WHERE output_pool = 3
             AND EXISTS (
                SELECT 1
                FROM orchard_received_notes rn
                WHERE rn.transaction_id = sent_notes.transaction_id
                AND rn.action_index = sent_notes.output_index
                AND rn.note_version = 3
             )",
            [],
        )?;

        #[cfg(zcash_unstable = "nu6.3")]
        self.backfill_sent_ironwood_pool_codes(transaction)?;
        #[cfg(not(zcash_unstable = "nu6.3"))]
        let _ = &self.params;

        transaction.execute_batch(db::VIEW_RECEIVED_OUTPUTS)?;
        transaction.execute_batch(db::VIEW_RECEIVED_OUTPUT_SPENDS)?;
        transaction.execute_batch(db::VIEW_TRANSACTIONS)?;
        transaction.execute_batch(db::VIEW_TX_OUTPUTS)?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }
}
