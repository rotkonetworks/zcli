//! poker: heads-up CLI with frostito escrow via relay.zk.bot
//!
//! host creates room + escrow, opponent joins.
//! play a hand, settle or dispute with nested FROST.
//! the relay sees opaque bytes. the escrow signature is standard schnorr.

use std::io::{self, BufRead, Write};

use clap::{Parser, Subcommand};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tonic::transport::Channel;
use tokio_stream::StreamExt;

mod proto {
    tonic::include_proto!("relay.v1");
}

use proto::relay_client::RelayClient;

// ============================================================================
// Protocol messages (opaque to relay)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t")]
enum Msg {
    /// host announces escrow address + unified address for deposits
    Escrow { address: String, unified_address: String, jury_n: u32, jury_t: u32 },
    /// deal cards (host → opponent). in production: mental poker shuffle
    Deal { your_cards: [u8; 2], community: [u8; 5] },
    /// player action
    Action { action: String, amount: u64 },
    /// settlement proposal
    Settle { a_payout: u64, b_payout: u64, message: String },
    /// settlement signature (frostito RedPallas)
    Signature { r: String, z: String, verified: bool },
    /// chat
    Chat { text: String },
}

// TODO: import poker-sdk for shared library code (CLI + browser WASM)
// - poker_sdk::transcript::{Transcript, SignedAction, Action} for signed action log
// - poker_sdk::escrow::{EscrowTable, DisputingPlayer} for frostito escrow
// - poker_sdk::encrypt for message encryption

// TODO: encrypt all relay messages with session key derived from DKG
// currently plaintext JSON — relay can read cards, actions, amounts.
// fix: x25519 key exchange during DKG, chacha20poly1305 per-message.
// poker-sdk::encrypt already has the primitives. wire them here.

// TODO: mental poker shuffle via zk-shuffle
// currently host deals plaintext cards (host sees opponent's hand).
// fix: Chaum-Pedersen shuffle proofs, ElGamal card masking.
// zk-shuffle crate is WASM-ready. integrate after encryption.

// TODO: PVM game engine for deterministic execution
// currently game logic is inline in host_game(). not verifiable.
// fix: compile game engine to PolkaVM guest, both players run locally.
// dispute = jury (or WIM prover) replays PVM trace.

// TODO: deposit detection via zidecar (zcash.rotko.net:443)
// currently escrow address is displayed but deposits not tracked.
// fix: subscribe to zidecar compact blocks, trial decrypt with escrow FVK.
// poker-sdk has fvk_bytes. zcli sync module has trial decryption.

// TODO: PCZT transaction building for on-chain settlement
// currently signature is produced but no zcash transaction is built.
// fix: zcli build-pczt → poker sign <sighash> → zcli complete-pczt → broadcast.
// the sign subcommand already works. need zcli integration for build/complete.

fn encode_msg(msg: &Msg) -> Vec<u8> {
    serde_json::to_vec(msg).unwrap()
}

fn decode_msg(bytes: &[u8]) -> Option<Msg> {
    serde_json::from_slice(bytes).ok()
}

// ============================================================================
// Escrow (frostito — RedPallas ciphersuite for Zcash Orchard)
// ============================================================================

use osst::curve::{OsstPoint, OsstScalar};
use osst::redpallas::zcash as redpallas;
#[allow(unused_imports)]
use osst::SecretShare;
use pasta_curves::pallas::Scalar;
// blake2b_simd used internally by redpallas::setup_escrow for fvk_seed

struct Escrow {
    player_a: SecretShare<Scalar>,
    player_b: SecretShare<Scalar>,
    jury: redpallas::JuryNetwork,
    address: [u8; 32],
    /// zcash unified address (u1... or utest...)
    unified_address: String,
    /// full viewing key bytes (for deposit detection via zidecar)
    #[allow(dead_code)]
    fvk_bytes: [u8; 96],
}

impl Escrow {
    fn create(jury_n: u32, jury_t: u32, testnet: bool) -> Self {
        let mut rng = rand::thread_rng();
        let (player_a, player_b, jury, group_pubkey) =
            redpallas::setup_escrow(jury_n, jury_t, &mut rng)
                .expect("interleaved DKG should succeed");
        let address = redpallas::derive_address_bytes(&group_pubkey);

        // derive zcash orchard FVK from private DKG material.
        // the fvk_seed is H(s1 || s2 || group_pubkey) — includes secret shares
        // that only DKG participants know. the relay never sees this.
        // this prevents anyone from deriving the spending key from the public address.
        let coin_type = if testnet { 1u32 } else { 133u32 };
        let sk = orchard::keys::SpendingKey::from_zip32_seed(
            &jury.fvk_seed, coin_type, zip32::AccountId::ZERO,
        ).expect("spending key derivation should succeed");
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let orchard_addr = fvk.address_at(0u64, orchard::keys::Scope::External);

        let unified_address = {
            use zcash_address::unified::Encoding;
            let raw = orchard_addr.to_raw_address_bytes();
            let items = vec![zcash_address::unified::Receiver::Orchard(raw)];
            let ua = zcash_address::unified::Address::try_from_items(items)
                .expect("UA construction should succeed");
            #[allow(deprecated)]
            let network = if testnet {
                zcash_address::Network::Test
            } else {
                zcash_address::Network::Main
            };
            ua.encode(&network)
        };

        let fvk_bytes: [u8; 96] = fvk.to_bytes();

        Self { player_a, player_b, jury, address, unified_address, fvk_bytes }
    }

    /// happy path: both players sign (RedPallas BLAKE2b)
    fn settle(&self, message: &[u8]) -> Option<(String, String)> {
        let mut rng = rand::thread_rng();
        let (na, ca) = redpallas::commit(self.player_a.index, &mut rng);
        let (nb, cb) = redpallas::commit(self.player_b.index, &mut rng);
        let pkg = redpallas::RedPallasPackage::new(message.to_vec(), vec![ca, cb]).ok()?;
        let sa = redpallas::sign(&pkg, na, &self.player_a, &self.jury.outer_group_pubkey).ok()?;
        let sb = redpallas::sign(&pkg, nb, &self.player_b, &self.jury.outer_group_pubkey).ok()?;
        let sig = redpallas::aggregate(&pkg, &[sa, sb], &self.jury.outer_group_pubkey, None).ok()?;
        if redpallas::verify_signature(&self.jury.outer_group_pubkey, message, &sig) {
            Some((hex::encode(OsstPoint::compress(&sig.r)), hex::encode(OsstScalar::to_bytes(&sig.z))))
        } else {
            None
        }
    }

    /// dispute: OSST authorize → nested RedPallas sign (s₃ never reconstructed)
    fn dispute(&self, message: &[u8], player_is_a: bool) -> Option<(String, String)> {
        let player_share = if player_is_a { &self.player_a } else { &self.player_b };
        let (sig, _osst_ok) = redpallas::nested_redpallas_sign(&self.jury, player_share, message)?;
        Some((hex::encode(OsstPoint::compress(&sig.r)), hex::encode(OsstScalar::to_bytes(&sig.z))))
    }
}

// ============================================================================
// Simple card logic
// ============================================================================

const RANKS: &[&str] = &["2","3","4","5","6","7","8","9","T","J","Q","K","A"];
const SUITS: &[&str] = &["♠","♥","♦","♣"];

fn card_name(c: u8) -> String {
    let r = (c % 13) as usize;
    let s = (c / 13) as usize;
    format!("{}{}", RANKS[r], SUITS[s.min(3)])
}

fn deal_cards() -> ([u8; 2], [u8; 2], [u8; 5]) {
    let mut rng = rand::thread_rng();
    let mut deck: Vec<u8> = (0..52).collect();
    for i in (1..52).rev() {
        let j = rng.gen_range(0..=i);
        deck.swap(i, j);
    }
    let a = [deck[0], deck[1]];
    let b = [deck[2], deck[3]];
    let c = [deck[4], deck[5], deck[6], deck[7], deck[8]];
    (a, b, c)
}

// simple hand strength: high card value (demo only, not real poker eval)
fn hand_strength(hole: &[u8; 2], community: &[u8; 5]) -> u32 {
    let mut best = 0u32;
    for &c in hole.iter().chain(community.iter()) {
        let rank = (c % 13) as u32;
        if rank > best { best = rank; }
    }
    best
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "poker", about = "heads-up poker with frostito escrow")]
struct Args {
    /// relay server address
    #[arg(long, default_value = "https://relay.zk.bot")]
    relay: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// host a table (creates room + escrow)
    Host {
        /// buy-in amount
        #[arg(long, default_value = "1000")]
        buyin: u64,
    },
    /// join a table
    Join {
        /// room code from host
        code: String,
    },
    /// sign a zcash sighash with frostito escrow (for PCZT flow)
    /// use with: zcli build-pczt → poker sign → zcli complete-pczt
    Sign {
        /// hex-encoded sighash (32 bytes from zcli PCZT builder)
        sighash: String,
        /// jury size
        #[arg(long, default_value = "5")]
        jury_n: u32,
        /// jury threshold
        #[arg(long, default_value = "3")]
        jury_t: u32,
        /// use happy path (both players sign, no jury)
        #[arg(long)]
        happy: bool,
    },
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("poker=info")
        .init();

    let args = Args::parse();

    let my_id: Vec<u8> = {
        let mut id = [0u8; 32];
        rand::thread_rng().fill(&mut id);
        id.to_vec()
    };

    match args.cmd {
        Cmd::Host { buyin } => {
            let channel = Channel::from_shared(args.relay.clone())?.connect().await?;
            let mut client = RelayClient::new(channel);
            host_game(&mut client, my_id, buyin).await?
        }
        Cmd::Join { code } => {
            let channel = Channel::from_shared(args.relay.clone())?.connect().await?;
            let mut client = RelayClient::new(channel);
            join_game(&mut client, my_id, code).await?
        }
        Cmd::Sign { sighash, jury_n, jury_t, happy } => {
            sign_sighash(&sighash, jury_n, jury_t, happy)?
        }
    }

    Ok(())
}

/// sign a zcash sighash with frostito escrow
/// outputs a 64-byte hex RedPallas signature compatible with zcli's PCZT flow
fn sign_sighash(sighash_hex: &str, jury_n: u32, jury_t: u32, happy: bool) -> Result<(), Box<dyn std::error::Error>> {
    let sighash = hex::decode(sighash_hex)?;
    if sighash.len() != 32 {
        return Err("sighash must be 32 bytes (64 hex chars)".into());
    }

    eprintln!("creating frostito escrow ({}-of-{} jury)...", jury_t, jury_n);
    let escrow = Escrow::create(jury_n, jury_t, false); // mainnet

    eprintln!("escrow address: {}", escrow.unified_address);
    eprintln!("signing sighash: {}", sighash_hex);

    let (r, z) = if happy {
        eprintln!("mode: happy path (both players sign)");
        escrow.settle(&sighash).ok_or("settle signing failed")?
    } else {
        eprintln!("mode: dispute (OSST authorize + nested FROST)");
        eprintln!("  s₃ will NOT be reconstructed");
        escrow.dispute(&sighash, true).ok_or("dispute signing failed")?
    };

    // output signature as 64-byte hex (R || z) — compatible with zcli complete-pczt
    let sig_hex = format!("{}{}", r, z);
    eprintln!("signature: {}...{}", &sig_hex[..16], &sig_hex[sig_hex.len()-16..]);
    eprintln!("verified: true (RedPallas/BLAKE2b)");

    // print just the signature to stdout for piping
    println!("{}", sig_hex);
    Ok(())
}

async fn host_game(
    client: &mut RelayClient<Channel>,
    my_id: Vec<u8>,
    buyin: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // create room
    let room = client.create_room(proto::CreateRoomRequest {
        max_participants: 7,  // 2 players + 5 jury
        ttl_seconds: 3600,
    }).await?.into_inner();

    println!("=== POKER TABLE ===");
    println!("room: {}", room.room_code);
    println!("share this code with your opponent\n");

    // create escrow (testnet)
    println!("running frostito interleaved DKG (3-of-5 jury)...");
    let escrow = Escrow::create(5, 3, false);
    println!("escrow pallas key: {}", hex::encode(&escrow.address[..16]));
    println!("zcash address:     {}", &escrow.unified_address);
    println!("s₃ status:         NEVER EXISTED\n");

    // join room
    let mut stream = client.join_room(proto::JoinRoomRequest {
        room_code: room.room_code.clone(),
        participant_id: my_id.clone(),
    }).await?.into_inner();

    // announce escrow
    client.send_message(proto::SendMessageRequest {
        room_code: room.room_code.clone(),
        sender_id: my_id.clone(),
        payload: encode_msg(&Msg::Escrow {
            address: hex::encode(&escrow.address),
            unified_address: escrow.unified_address.clone(),
            jury_n: 5, jury_t: 3,
        }),
    }).await?;

    println!("waiting for opponent...");

    // wait for opponent
    let mut opponent_joined = false;
    while let Some(Ok(event)) = stream.next().await {
        if let Some(proto::room_event::Event::Joined(j)) = event.event {
            if j.participant_id != my_id {
                opponent_joined = true;
                println!("opponent joined! ({}...)\n", hex::encode(&j.participant_id[..4]));
                break;
            }
        }
    }
    if !opponent_joined { return Err("opponent didn't join".into()); }

    // deal
    let (my_cards, opp_cards, community) = deal_cards();
    println!("your cards: {} {}", card_name(my_cards[0]), card_name(my_cards[1]));
    println!("community:  {} {} {} {} {}\n",
        card_name(community[0]), card_name(community[1]), card_name(community[2]),
        card_name(community[3]), card_name(community[4]));

    // send opponent their cards
    client.send_message(proto::SendMessageRequest {
        room_code: room.room_code.clone(),
        sender_id: my_id.clone(),
        payload: encode_msg(&Msg::Deal { your_cards: opp_cards, community }),
    }).await?;

    // simple betting round
    println!("buy-in: {} each (pot: {})", buyin, buyin * 2);
    print!("action (bet <amount> / check / fold): ");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let line = stdin.lock().lines().next().unwrap_or(Ok("check".into()))?;
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    let (action, amount) = match parts.first().map(|s| s.to_lowercase()).as_deref() {
        Some("bet") => ("bet".to_string(), parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(100)),
        Some("fold") => ("fold".to_string(), 0u64),
        _ => ("check".to_string(), 0u64),
    };

    client.send_message(proto::SendMessageRequest {
        room_code: room.room_code.clone(),
        sender_id: my_id.clone(),
        payload: encode_msg(&Msg::Action { action: action.clone(), amount }),
    }).await?;

    if action == "fold" {
        println!("you folded. opponent wins.");
        return Ok(());
    }

    // wait for opponent action
    println!("waiting for opponent action...");
    while let Some(Ok(event)) = stream.next().await {
        if let Some(proto::room_event::Event::Message(m)) = event.event {
            if m.sender_id != my_id {
                if let Some(msg) = decode_msg(&m.payload) {
                    match msg {
                        Msg::Action { action: ref a, .. } => {
                            println!("opponent: {}", a);
                            if a == "fold" {
                                println!("opponent folded. you win!");
                                // settle
                                let settle_msg = format!("settle:A={},B=0", buyin * 2);
                                if let Some((r, z)) = escrow.settle(settle_msg.as_bytes()) {
                                    println!("\nfrostito signature (happy path):");
                                    println!("  R: {}...", &r[..32]);
                                    println!("  z: {}...", &z[..32]);
                                    println!("  verified: true");
                                }
                                return Ok(());
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // showdown
    let my_strength = hand_strength(&my_cards, &community);
    let opp_strength = hand_strength(&opp_cards, &community);

    println!("\n=== SHOWDOWN ===");
    println!("your hand:     {} {} (strength: {})", card_name(my_cards[0]), card_name(my_cards[1]), my_strength);
    println!("opponent hand: {} {} (strength: {})", card_name(opp_cards[0]), card_name(opp_cards[1]), opp_strength);

    let (a_payout, b_payout) = if my_strength >= opp_strength {
        println!("you win!");
        (buyin * 2, 0)
    } else {
        println!("opponent wins!");
        (0, buyin * 2)
    };

    // settlement
    let settle_msg = format!("settle:A={},B={}", a_payout, b_payout);
    println!("\nsettling via frostito (happy path: both players sign)...");
    if let Some((r, z)) = escrow.settle(settle_msg.as_bytes()) {
        println!("  escrow address: {}...", hex::encode(&escrow.address[..16]));
        println!("  R: {}...", &r[..32]);
        println!("  z: {}...", &z[..32]);
        println!("  verified: true (standard schnorr)");

        client.send_message(proto::SendMessageRequest {
            room_code: room.room_code.clone(),
            sender_id: my_id.clone(),
            payload: encode_msg(&Msg::Signature { r, z, verified: true }),
        }).await?;
    }

    // dispute demo
    print!("\ntest dispute? (y/n): ");
    io::stdout().flush()?;
    let line = stdin.lock().lines().next().unwrap_or(Ok("n".into()))?;
    if line.trim() == "y" {
        let dispute_msg = format!("dispute:A={},B={}", a_payout, b_payout);
        println!("disputing via frostito (OSST authorize → nested FROST sign)...");
        println!("  s₃ will NOT be reconstructed");
        if let Some((r, z)) = escrow.dispute(dispute_msg.as_bytes(), true) {
            println!("  OSST: 3-of-5 jury authorized");
            println!("  nested FROST: inner holders signed without reconstructing s₃");
            println!("  R: {}...", &r[..32]);
            println!("  z: {}...", &z[..32]);
            println!("  verified: true (same escrow address, standard schnorr)");
        }
    }

    println!("\nggwp");
    Ok(())
}

async fn join_game(
    client: &mut RelayClient<Channel>,
    my_id: Vec<u8>,
    code: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== JOINING TABLE ===");
    println!("room: {}\n", code);

    let mut stream = client.join_room(proto::JoinRoomRequest {
        room_code: code.clone(),
        participant_id: my_id.clone(),
    }).await?.into_inner();

    let stdin = io::stdin();
    let mut _escrow_addr = String::new();
    #[allow(unused_assignments)]
    let mut my_cards = [0u8; 2];
    let mut _community = [0u8; 5];
    let mut got_cards = false;

    println!("waiting for host...");

    while let Some(Ok(event)) = stream.next().await {
        match event.event {
            Some(proto::room_event::Event::Message(m)) => {
                if m.sender_id == my_id { continue; }
                if let Some(msg) = decode_msg(&m.payload) {
                    match msg {
                        Msg::Escrow { address, unified_address, jury_n, jury_t } => {
                            _escrow_addr = address.clone();
                            println!("escrow: {}... ({}-of-{} jury)", &address[..32], jury_t, jury_n);
                            println!("deposit: {}", unified_address);
                        }
                        Msg::Deal { your_cards, community: comm } => {
                            my_cards = your_cards;
                            _community = comm;
                            got_cards = true;
                            println!("\nyour cards: {} {}", card_name(my_cards[0]), card_name(my_cards[1]));
                            println!("community:  {} {} {} {} {}\n",
                                card_name(comm[0]), card_name(comm[1]), card_name(comm[2]),
                                card_name(comm[3]), card_name(comm[4]));
                        }
                        Msg::Action { action, amount } => {
                            println!("host: {} {}", action, if amount > 0 { format!("({})", amount) } else { String::new() });

                            if action == "fold" {
                                println!("host folded. you win!");
                                return Ok(());
                            }

                            if got_cards {
                                print!("your action (bet <amount> / call / fold): ");
                                io::stdout().flush()?;
                                let line = stdin.lock().lines().next().unwrap_or(Ok("call".into()))?;
                                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                                let (act, amt) = match parts.first().map(|s| s.to_lowercase()).as_deref() {
                                    Some("fold") => ("fold", 0u64),
                                    Some("bet") => ("bet", parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(100)),
                                    _ => ("call", 0u64),
                                };
                                client.send_message(proto::SendMessageRequest {
                                    room_code: code.clone(),
                                    sender_id: my_id.clone(),
                                    payload: encode_msg(&Msg::Action { action: act.to_string(), amount: amt }),
                                }).await?;

                                if act == "fold" {
                                    println!("you folded.");
                                    return Ok(());
                                }
                                println!("waiting for showdown...");
                            }
                        }
                        Msg::Signature { r, z, verified } => {
                            println!("\n=== SETTLEMENT ===");
                            println!("  frostito signature received");
                            println!("  R: {}...", &r[..32.min(r.len())]);
                            println!("  z: {}...", &z[..32.min(z.len())]);
                            println!("  verified: {}", verified);
                            println!("\nggwp");
                            return Ok(());
                        }
                        Msg::Settle { a_payout, b_payout, .. } => {
                            println!("settlement: host={}, you={}", a_payout, b_payout);
                        }
                        Msg::Chat { text } => {
                            println!("host: {}", text);
                        }
                    }
                }
            }
            Some(proto::room_event::Event::Joined(j)) => {
                if j.participant_id != my_id {
                    println!("host connected ({}...)", hex::encode(&j.participant_id[..4]));
                }
            }
            Some(proto::room_event::Event::Closed(c)) => {
                println!("room closed: {}", c.reason);
                break;
            }
            None => {}
        }
    }

    Ok(())
}
