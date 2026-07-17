mod received;
mod sent;

pub(crate) use received::{
    ReceievedNoteSpends, ReceivedNote, ReceivedNoteTable, to_spendable_notes,
};
#[cfg(test)]
pub(crate) use sent::SentNoteId;
pub(crate) use sent::{SentNote, SentNoteTable};

mod serialization {
    use crate::error::Error;
    use crate::proto::memwallet::{self as proto};
    use crate::read_optional;
    use jubjub::Fr;
    use zcash_client_backend::wallet::{Note, NoteId};

    impl From<NoteId> for proto::NoteId {
        fn from(note_id: NoteId) -> Self {
            Self {
                tx_id: Some(note_id.txid().into()),
                pool: match note_id.protocol() {
                    zcash_protocol::ShieldedProtocol::Sapling => {
                        proto::PoolType::ShieldedSapling.into()
                    }
                    #[cfg(feature = "orchard")]
                    zcash_protocol::ShieldedProtocol::Orchard => {
                        proto::PoolType::ShieldedOrchard.into()
                    }
                    #[cfg(not(feature = "orchard"))]
                    zcash_protocol::ShieldedProtocol::Orchard => panic!(
                        "Attempting to deserialize orchard supporting wallet using library built without orchard feature"
                    ),
                },
                output_index: u32::from(note_id.output_index()),
            }
        }
    }

    impl TryFrom<proto::NoteId> for NoteId {
        type Error = Error;
        fn try_from(note_id: proto::NoteId) -> Result<Self, Self::Error> {
            Ok(Self::new(
                read_optional!(note_id.clone(), tx_id)?.try_into()?,
                match note_id.pool() {
                    proto::PoolType::ShieldedSapling => zcash_protocol::ShieldedProtocol::Sapling,
                    #[cfg(feature = "orchard")]
                    proto::PoolType::ShieldedOrchard => zcash_protocol::ShieldedProtocol::Orchard,
                    _ => panic!("invalid pool"),
                },
                note_id.output_index.try_into()?,
            ))
        }
    }

    impl From<Note> for proto::Note {
        fn from(note: Note) -> Self {
            match note {
                Note::Sapling(note) => Self {
                    protocol: proto::ShieldedProtocol::Sapling.into(),
                    recipient: note.recipient().to_bytes().to_vec(),
                    value: note.value().inner(),
                    rseed: match note.rseed() {
                        sapling::Rseed::AfterZip212(inner) => Some(proto::RSeed {
                            rseed_type: Some(proto::RSeedType::AfterZip212 as i32),
                            payload: inner.to_vec(),
                        }),
                        sapling::Rseed::BeforeZip212(inner) => Some(proto::RSeed {
                            rseed_type: Some(proto::RSeedType::BeforeZip212 as i32),
                            payload: inner.to_bytes().to_vec(),
                        }),
                    },
                    rho: None,
                    orchard_note_version: None,
                },
                #[cfg(feature = "orchard")]
                Note::Orchard(note) => Self {
                    protocol: proto::ShieldedProtocol::Orchard.into(),
                    recipient: note.recipient().to_raw_address_bytes().to_vec(),
                    value: note.value().inner(),
                    rseed: Some(proto::RSeed {
                        rseed_type: None,
                        payload: note.rseed().as_bytes().to_vec(),
                    }),
                    rho: Some(note.rho().to_bytes().to_vec()),
                    orchard_note_version: Some(match note.version() {
                        orchard::note::NoteVersion::V2 => 2,
                        orchard::note::NoteVersion::V3 => 3,
                    }),
                },
            }
        }
    }

    impl From<proto::Note> for Note {
        fn from(note: proto::Note) -> Self {
            match note.protocol() {
                proto::ShieldedProtocol::Sapling => {
                    let recipient =
                        sapling::PaymentAddress::from_bytes(&note.recipient.try_into().unwrap())
                            .unwrap();
                    let value = sapling::value::NoteValue::from_raw(note.value);
                    let rseed = match note.rseed {
                        Some(proto::RSeed {
                            rseed_type: Some(0),
                            payload,
                        }) => sapling::Rseed::BeforeZip212(
                            Fr::from_bytes(&payload.try_into().unwrap()).unwrap(),
                        ),
                        Some(proto::RSeed {
                            rseed_type: Some(1),
                            payload,
                        }) => sapling::Rseed::AfterZip212(payload.try_into().unwrap()),
                        _ => panic!("rseed is required"),
                    };
                    Self::Sapling(sapling::Note::from_parts(recipient, value, rseed))
                }
                #[cfg(feature = "orchard")]
                proto::ShieldedProtocol::Orchard => {
                    let recipient = orchard::Address::from_raw_address_bytes(
                        &note.recipient.try_into().unwrap(),
                    )
                    .unwrap();
                    let value = orchard::value::NoteValue::from_raw(note.value);
                    let rho =
                        orchard::note::Rho::from_bytes(&note.rho.unwrap().try_into().unwrap())
                            .unwrap();
                    let rseed = orchard::note::RandomSeed::from_bytes(
                        note.rseed.unwrap().payload.try_into().unwrap(),
                        &rho,
                    )
                    .unwrap();
                    let note_version = match note.orchard_note_version.unwrap_or(2) {
                        2 => orchard::note::NoteVersion::V2,
                        3 => orchard::note::NoteVersion::V3,
                        _ => panic!("invalid Orchard note version"),
                    };
                    Self::Orchard(
                        orchard::Note::from_parts(recipient, value, rho, rseed, note_version)
                            .unwrap(),
                    )
                }
                #[cfg(not(feature = "orchard"))]
                _ => panic!("invalid protocol"),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::proto::memwallet as proto;

        #[test]
        fn test_note_roundtrip() {
            let note = Note::Sapling(sapling::note::Note::from_parts(
                sapling::PaymentAddress::from_bytes(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8e,
                    0x11, 0x9d, 0x72, 0x99, 0x2b, 0x56, 0x0d, 0x26, 0x50, 0xff, 0xe0, 0xbe, 0x7f,
                    0x35, 0x42, 0xfd, 0x97, 0x00, 0x3c, 0xb7, 0xcc, 0x3a, 0xbf, 0xf8, 0x1a, 0x7f,
                    0x90, 0x37, 0xf3, 0xea,
                ])
                .unwrap(),
                sapling::value::NoteValue::from_raw(99),
                sapling::Rseed::AfterZip212([0; 32]),
            ));

            let proto_note: proto::Note = note.clone().into();
            let recovered: Note = proto_note.into();

            assert_eq!(note, recovered);
        }

        #[cfg(feature = "orchard")]
        #[test]
        fn orchard_note_roundtrip_preserves_note_version() {
            let sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
            let recipient = orchard::keys::FullViewingKey::from(&sk)
                .address_at(0u32, orchard::keys::Scope::External);
            let value = orchard::value::NoteValue::from_raw(99);
            let rho = orchard::note::Rho::from_bytes(&[1; 32]).unwrap();
            let rseed = (0u8..=255)
                .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
                .expect("at least one test rseed is valid");
            let note = Note::Orchard(
                orchard::Note::from_parts(
                    recipient,
                    value,
                    rho,
                    rseed,
                    orchard::note::NoteVersion::V3,
                )
                .unwrap(),
            );

            let proto_note: proto::Note = note.clone().into();
            assert_eq!(proto_note.orchard_note_version, Some(3));
            let recovered: Note = proto_note.clone().into();

            assert_eq!(note, recovered);

            let recovered_legacy: Note = proto::Note {
                orchard_note_version: None,
                ..proto_note
            }
            .into();
            match recovered_legacy {
                Note::Orchard(note) => assert_eq!(note.version(), orchard::note::NoteVersion::V2),
                Note::Sapling(_) => panic!("expected Orchard note"),
            }
        }
    }
}
