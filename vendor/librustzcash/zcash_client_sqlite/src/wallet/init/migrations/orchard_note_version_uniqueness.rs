//! Allows Orchard and Ironwood notes to have the same action index.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::witness_stabilized_notes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x2aa44e8e_e8a7_4760_8de4_501956c969ac);

const DEPENDENCIES: &[Uuid] = &[witness_stabilized_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds note version to Orchard received-note uniqueness."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP INDEX IF EXISTS idx_orchard_received_notes_account;
             DROP INDEX IF EXISTS idx_orchard_received_notes_address;
             DROP INDEX IF EXISTS idx_orchard_received_notes_tx;
             DROP INDEX IF EXISTS idx_orchard_received_notes_witness_stabilized;
             DROP INDEX IF EXISTS orchard_received_notes_account;
             DROP INDEX IF EXISTS orchard_received_notes_tx;

             PRAGMA legacy_alter_table = ON;

             CREATE TABLE orchard_received_notes_new (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL
                     REFERENCES transactions(id_tx) ON DELETE CASCADE,
                 action_index INTEGER NOT NULL,
                 account_id INTEGER NOT NULL
                     REFERENCES accounts(id) ON DELETE CASCADE,
                 diversifier BLOB NOT NULL,
                 value INTEGER NOT NULL,
                 rho BLOB NOT NULL,
                 rseed BLOB NOT NULL,
                 nf BLOB UNIQUE,
                 is_change INTEGER NOT NULL,
                 memo BLOB,
                 commitment_tree_position INTEGER,
                 recipient_key_scope INTEGER,
                 address_id INTEGER
                     REFERENCES addresses(id) ON DELETE CASCADE,
                 witness_stabilized INTEGER NOT NULL DEFAULT 0,
                 note_version INTEGER NOT NULL DEFAULT 2,
                 UNIQUE (transaction_id, action_index, note_version)
             );

             INSERT INTO orchard_received_notes_new (
                 id, transaction_id, action_index, account_id,
                 diversifier, value, rho, rseed, nf, is_change, memo,
                 commitment_tree_position, recipient_key_scope, address_id,
                 witness_stabilized, note_version
             )
             SELECT
                 id, transaction_id, action_index, account_id,
                 diversifier, value, rho, rseed, nf, is_change, memo,
                 commitment_tree_position, recipient_key_scope, address_id,
                 witness_stabilized, 2
             FROM orchard_received_notes;

             DROP TABLE orchard_received_notes;
             ALTER TABLE orchard_received_notes_new RENAME TO orchard_received_notes;

             CREATE INDEX idx_orchard_received_notes_account
                 ON orchard_received_notes (account_id ASC);
             CREATE INDEX idx_orchard_received_notes_address
                 ON orchard_received_notes (address_id ASC);
             CREATE INDEX idx_orchard_received_notes_tx
                 ON orchard_received_notes (transaction_id ASC);
             CREATE INDEX idx_orchard_received_notes_witness_stabilized
                 ON orchard_received_notes (witness_stabilized);

             PRAGMA legacy_alter_table = OFF;",
        )?;

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
