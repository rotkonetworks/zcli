// A real 2-of-3 FROST ceremony, end to end, over a real frostd.
//
// Everything else we have is a unit test: the cipher round-trips, the router
// answers, the DKG completes in memory. None of that proves two participants
// can actually complete a ceremony, which is the only claim anyone cares
// about. This test does the whole thing:
//
//   * a genuine frostd server, in-process (upstream's router, not a mock)
//   * three participants, each with their own FrostdTransport and cipher
//   * DKG rounds 1, 2 and 3 with every message relayed and encrypted
//   * a 2-of-3 spend signature, also fully relayed
//   * and a check that the relay saw no plaintext at any point
//
// If this passes, the transport works. If it fails, nothing else mattered.

use std::net::SocketAddr;

use frost_spend::orchestrate::{
    dkg_part1, dkg_part2, dkg_part3, sign_round1, spend_aggregate, spend_sign_round2,
};
use zecli::frostd_transport::FrostdTransport;

async fn spawn_frostd() -> SocketAddr {
    let state = frostd::AppState::new().await.expect("frostd state");
    let app = frostd::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Drain until `want` messages have arrived, so a participant does not race
/// ahead of peers that have not sent yet.
async fn receive_n(t: &mut FrostdTransport, want: usize) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for _ in 0..200 {
        for (sender, msg) in t.receive(false).await.expect("receive") {
            out.push((hex::encode(&sender.0), msg));
        }
        if out.len() >= want {
            return out;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {want} messages, got {}", out.len());
}

#[tokio::test]
async fn a_full_2of3_ceremony_completes_over_the_relay() {
    let addr = spawn_frostd().await;
    let host = format!("http://{addr}");

    // ── identities ──
    let (sk_a, pk_a) = FrostdTransport::generate_keypair().expect("keypair a");
    let (sk_b, pk_b) = FrostdTransport::generate_keypair().expect("keypair b");
    let (sk_c, pk_c) = FrostdTransport::generate_keypair().expect("keypair c");

    // each participant's cipher peers are the OTHER two
    let mut a = FrostdTransport::connect(
        host.clone(),
        sk_a,
        pk_a.clone(),
        vec![pk_b.clone(), pk_c.clone()],
    )
    .await
    .expect("connect a");
    let mut b = FrostdTransport::connect(
        host.clone(),
        sk_b,
        pk_b.clone(),
        vec![pk_a.clone(), pk_c.clone()],
    )
    .await
    .expect("connect b");
    let mut c = FrostdTransport::connect(
        host.clone(),
        sk_c,
        pk_c.clone(),
        vec![pk_a.clone(), pk_b.clone()],
    )
    .await
    .expect("connect c");

    // A coordinates but is also a participant, so it is in the pubkey list
    let session = a
        .create_session(vec![pk_a.clone(), pk_b.clone(), pk_c.clone()], 3)
        .await
        .expect("create session");
    b.join_session(session);
    c.join_session(session);

    // ── DKG round 1: broadcast commitments ──
    let r1_a = dkg_part1(3, 2).expect("part1 a");
    let r1_b = dkg_part1(3, 2).expect("part1 b");
    let r1_c = dkg_part1(3, 2).expect("part1 c");

    a.send(
        vec![pk_b.clone(), pk_c.clone()],
        r1_a.broadcast_hex.clone().into_bytes(),
    )
    .await
    .expect("a bcast");
    b.send(
        vec![pk_a.clone(), pk_c.clone()],
        r1_b.broadcast_hex.clone().into_bytes(),
    )
    .await
    .expect("b bcast");
    c.send(
        vec![pk_a.clone(), pk_b.clone()],
        r1_c.broadcast_hex.clone().into_bytes(),
    )
    .await
    .expect("c bcast");

    let bc_a: Vec<String> = receive_n(&mut a, 2)
        .await
        .into_iter()
        .map(|(_, m)| String::from_utf8(m).expect("utf8"))
        .collect();
    let bc_b: Vec<String> = receive_n(&mut b, 2)
        .await
        .into_iter()
        .map(|(_, m)| String::from_utf8(m).expect("utf8"))
        .collect();
    let bc_c: Vec<String> = receive_n(&mut c, 2)
        .await
        .into_iter()
        .map(|(_, m)| String::from_utf8(m).expect("utf8"))
        .collect();

    // ── DKG round 2: sealed per-recipient packages ──
    let r2_a = dkg_part2(&r1_a.secret_hex, &bc_a).expect("part2 a");
    let r2_b = dkg_part2(&r1_b.secret_hex, &bc_b).expect("part2 b");
    let r2_c = dkg_part2(&r1_c.secret_hex, &bc_c).expect("part2 c");

    // Every package goes to everyone; dkg_part3 keeps the ones addressed to
    // it and Noise_K means the rest will not open for anyone else.
    for (t, peers, r2) in [
        (&mut a, vec![pk_b.clone(), pk_c.clone()], &r2_a),
        (&mut b, vec![pk_a.clone(), pk_c.clone()], &r2_b),
        (&mut c, vec![pk_a.clone(), pk_b.clone()], &r2_c),
    ] {
        let joined = r2.peer_packages.join("\n");
        t.send(peers, joined.into_bytes()).await.expect("send r2");
    }

    async fn collect_r2(t: &mut FrostdTransport) -> Vec<String> {
        receive_n(t, 2)
            .await
            .into_iter()
            .flat_map(|(_, m)| {
                String::from_utf8(m)
                    .expect("utf8")
                    .split('\n')
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    let mut all_r2 = collect_r2(&mut a).await;
    all_r2.extend(r2_a.peer_packages.clone());
    let mut all_r2_b = collect_r2(&mut b).await;
    all_r2_b.extend(r2_b.peer_packages.clone());
    let _ = collect_r2(&mut c).await;

    // ── DKG round 3 ──
    let r3_a = dkg_part3(&r2_a.secret_hex, &bc_a, &all_r2).expect("part3 a");
    let r3_b = dkg_part3(&r2_b.secret_hex, &bc_b, &all_r2_b).expect("part3 b");

    assert_eq!(
        r3_a.public_key_package_hex, r3_b.public_key_package_hex,
        "participants disagree on the group key — the ceremony did not converge"
    );

    // ── sign 2-of-3, commitments relayed ──
    let sighash = [0xcc; 32];
    let mut alpha = [0u8; 32];
    alpha[0] = 0x02;

    let mut seed_a = [0u8; 32];
    seed_a.copy_from_slice(&hex::decode(&r3_a.ephemeral_seed_hex).expect("seed a"));
    let mut seed_b = [0u8; 32];
    seed_b.copy_from_slice(&hex::decode(&r3_b.ephemeral_seed_hex).expect("seed b"));

    let (nonces_a, commit_a) = sign_round1(&seed_a, &r3_a.key_package_hex).expect("round1 a");
    let (nonces_b, commit_b) = sign_round1(&seed_b, &r3_b.key_package_hex).expect("round1 b");

    a.send(vec![pk_b.clone()], commit_a.clone().into_bytes())
        .await
        .expect("a commit");
    b.send(vec![pk_a.clone()], commit_b.clone().into_bytes())
        .await
        .expect("b commit");

    let got_a = receive_n(&mut a, 1).await;
    let got_b = receive_n(&mut b, 1).await;
    assert_eq!(
        String::from_utf8(got_a[0].1.clone()).unwrap(),
        commit_b,
        "A did not receive B's commitment intact"
    );
    assert_eq!(
        String::from_utf8(got_b[0].1.clone()).unwrap(),
        commit_a,
        "B did not receive A's commitment intact"
    );

    let all_commits = vec![commit_a, commit_b];
    let share_a = spend_sign_round2(
        &r3_a.key_package_hex,
        &nonces_a,
        &sighash,
        &alpha,
        &all_commits,
    )
    .expect("share a");
    let share_b = spend_sign_round2(
        &r3_b.key_package_hex,
        &nonces_b,
        &sighash,
        &alpha,
        &all_commits,
    )
    .expect("share b");

    // shares travel over the relay too
    b.send(vec![pk_a.clone()], share_b.clone().into_bytes())
        .await
        .expect("b share");
    let got = receive_n(&mut a, 1).await;
    let relayed_share_b = String::from_utf8(got[0].1.clone()).expect("utf8");
    assert_eq!(relayed_share_b, share_b, "share corrupted in transit");

    let sig = spend_aggregate(
        &r3_a.public_key_package_hex,
        &sighash,
        &alpha,
        &all_commits,
        &[share_a, relayed_share_b],
    )
    .expect("aggregate");

    assert_eq!(sig.len(), 128, "not a 64-byte signature");

    a.close().await.expect("close");
}

/// The claim that makes an untrusted relay acceptable: it never sees
/// plaintext. Asserted against what actually crosses the wire, by logging in
/// as B with a second raw HTTP client and reading the queue the server holds
/// — bypassing our own decryption entirely.
#[tokio::test]
async fn the_relay_never_sees_ceremony_plaintext() {
    use frost_client::api;

    let addr = spawn_frostd().await;
    let host = format!("http://{addr}");

    let (sk_a, pk_a) = FrostdTransport::generate_keypair().expect("keypair a");
    let (sk_b, pk_b) = FrostdTransport::generate_keypair().expect("keypair b");
    let sk_b_raw = sk_b.clone();

    let mut a = FrostdTransport::connect(host.clone(), sk_a, pk_a.clone(), vec![pk_b.clone()])
        .await
        .expect("connect a");
    let mut b = FrostdTransport::connect(host.clone(), sk_b, pk_b.clone(), vec![pk_a.clone()])
        .await
        .expect("connect b");

    let session = a
        .create_session(vec![pk_a.clone(), pk_b.clone()], 1)
        .await
        .expect("session");
    b.join_session(session);

    // a round-1 broadcast is real ceremony material
    let r1 = dkg_part1(2, 2).expect("part1");
    a.send(vec![pk_b.clone()], r1.broadcast_hex.clone().into_bytes())
        .await
        .expect("send");

    // log in again as B, raw, so we read exactly what the server stores
    let http = reqwest::Client::new();
    let challenge: api::ChallengeOutput = http
        .post(format!("{host}/challenge"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("challenge")
        .json()
        .await
        .expect("challenge json");
    let sig = sk_b_raw
        .sign(challenge.challenge.as_bytes(), &mut rand::rngs::OsRng)
        .expect("sign challenge");
    let login: api::LoginOutput = http
        .post(format!("{host}/login"))
        .json(&api::LoginArgs {
            challenge: challenge.challenge,
            pubkey: pk_b.clone(),
            signature: sig.to_vec(),
        })
        .send()
        .await
        .expect("login")
        .json()
        .await
        .expect("login json");

    let raw = http
        .post(format!("{host}/receive"))
        .bearer_auth(login.access_token.to_string())
        .json(&serde_json::json!({ "session_id": session, "as_coordinator": false }))
        .send()
        .await
        .expect("raw receive")
        .text()
        .await
        .expect("body");

    assert!(
        !raw.contains(&r1.broadcast_hex),
        "the relay is holding ceremony plaintext"
    );
    // and a message really is in there, so the assertion is not vacuous
    assert!(raw.contains("\"msg\""), "no message in the queue at all: {raw}");
}

/// Our wasm-side challenge signing must satisfy the real frostd login, not
/// just look plausible. zafu signs with frost_spend::relay_cipher because
/// frost-client will not build for wasm32; if the two ever disagree, the
/// browser silently cannot log in.
#[tokio::test]
async fn our_wasm_signature_is_accepted_by_a_real_frostd() {
    use frost_client::api;
    use frost_spend::relay_cipher::{generate_keypair, sign_challenge};

    let addr = spawn_frostd().await;
    let host = format!("http://{addr}");
    let (sk, pk) = generate_keypair().expect("keypair");

    let http = reqwest::Client::new();
    let challenge: api::ChallengeOutput = http
        .post(format!("{host}/challenge"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("challenge")
        .json()
        .await
        .expect("challenge json");

    // signed the way the browser will sign it
    let sig = sign_challenge(&sk, challenge.challenge.as_bytes(), &mut rand::rngs::OsRng)
        .expect("sign");

    let res = http
        .post(format!("{host}/login"))
        .json(&api::LoginArgs {
            challenge: challenge.challenge,
            pubkey: api::PublicKey(pk.to_vec()),
            signature: sig.to_vec(),
        })
        .send()
        .await
        .expect("login");

    assert!(
        res.status().is_success(),
        "frostd rejected our signature: {}",
        res.status()
    );
    let out: api::LoginOutput = res.json().await.expect("login json");
    assert!(!out.access_token.is_nil(), "no access token issued");
}

/// Three connected participants in one session, A the coordinator.
async fn three_in_a_session(
    host: &str,
) -> [(FrostdTransport, Vec<frost_client::cipher::PublicKey>); 3] {
    let keys: Vec<_> = (0..3)
        .map(|_| FrostdTransport::generate_keypair().expect("keypair"))
        .collect();
    let pks: Vec<_> = keys.iter().map(|(_, pk)| pk.clone()).collect();
    let mut out = Vec::new();
    for (i, (sk, pk)) in keys.into_iter().enumerate() {
        let peers: Vec<_> = pks
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, p)| p.clone())
            .collect();
        let t = FrostdTransport::connect(host.to_string(), sk, pk, peers.clone())
            .await
            .expect("connect");
        out.push((t, peers));
    }
    let session = out[0]
        .0
        .create_session(pks.clone(), 3)
        .await
        .expect("create session");
    out[1].0.join_session(session);
    out[2].0.join_session(session);
    out.try_into().ok().expect("three")
}

/// A joiner that listens first still completes zcli's own ceremony: the
/// detection must not cost the wire it replaced anything.
#[tokio::test]
async fn a_joiner_detects_zcli_s_own_wire() {
    use zecli::frost_ceremony::{detect_dialect, run_dkg, run_dkg_with, Dialect};
    let host = format!("http://{}", spawn_frostd().await);
    let [(mut a, pa), (b, pb), (c, pc)] = three_in_a_session(&host).await;
    let joiner = |mut t: FrostdTransport, peers| async move {
        let (dialect, mailbox) = detect_dialect(&mut t).await.expect("detect");
        assert_eq!(dialect, Dialect::Zcli);
        run_dkg_with(&mut t, mailbox, peers, 2, 3).await.expect("joiner dkg")
    };
    let (ha, hb, hc) = tokio::join!(
        async { run_dkg(&mut a, pa, 2, 3).await.expect("host dkg") },
        joiner(b, pb),
        joiner(c, pc),
    );
    assert_eq!(ha.public_key_package_hex, hb.public_key_package_hex);
    assert_eq!(ha.public_key_package_hex, hc.public_key_package_hex);
}

/// zafu's tagged wire, as the zk.poker escrow hosts it: zcli joiners detect
/// it from the host's R1, finish the ceremony, and land on the host's vault.
#[tokio::test]
async fn a_joiner_detects_and_joins_the_tagged_wire() {
    use zcash_protocol::consensus::NetworkType;
    use zecli::frost_ceremony::{collect, detect_dialect, Dialect, Mailbox};
    use zecli::frost_tagged;

    let host = format!("http://{}", spawn_frostd().await);
    let [(mut a, pa), (b, pb), (c, pc)] = three_in_a_session(&host).await;

    // the host, as poker-escrow's frost_dkg::run_dkg runs it
    let tagged_host = async move {
        let sk = "07".repeat(32);
        let r1 = dkg_part1(3, 2).unwrap();
        a.send(pa.clone(), format!("R1:2:3:SK:{sk}:{}", r1.broadcast_hex).into_bytes())
            .await
            .unwrap();
        let mut m = Mailbox::default();
        let bcs = collect(&mut a, &mut m, "R1", 2, "r1").await.unwrap();
        let r2 = dkg_part2(&r1.secret_hex, &bcs).unwrap();
        for p in &r2.peer_packages {
            a.send(pa.clone(), format!("R2:{p}").into_bytes()).await.unwrap();
        }
        let pkgs = collect(&mut a, &mut m, "R2", 4, "r2").await.unwrap();
        let r3 = dkg_part3(&r2.secret_hex, &bcs, &pkgs).unwrap();
        let (ua, ufvk, _) =
            frost_tagged::vault_keys(&r3.public_key_package_hex, &sk, NetworkType::Test).unwrap();
        a.send(pa.clone(), format!("FVK:{ufvk}").into_bytes()).await.unwrap();
        for theirs in collect(&mut a, &mut m, "FVK", 2, "fvk").await.unwrap() {
            assert_eq!(theirs, ufvk);
        }
        (ua, r3.public_key_package_hex)
    };
    // (t, n) as the room said it; 0/0 = the room did not, learn it from the host
    let joiner = |mut t: FrostdTransport, peers, (min, max)| async move {
        let (dialect, mailbox) = detect_dialect(&mut t).await.expect("detect");
        assert_eq!(dialect, Dialect::Tagged);
        frost_tagged::run_dkg(&mut t, mailbox, peers, min, max, NetworkType::Test)
            .await
            .expect("tagged joiner")
    };
    let ((ua, pkg), jb, jc) =
        tokio::join!(tagged_host, joiner(b, pb, (2, 3)), joiner(c, pc, (0, 0)));
    assert_eq!((jc.min_signers, jc.max_signers), (2, 3), "learned from the host's R1");
    assert_eq!(jb.address, ua, "joiner b lands on the host's vault");
    assert_eq!(jc.address, ua, "joiner c lands on the host's vault");
    assert_eq!(jb.public_key_package_hex, pkg);
    assert_eq!(jb.sk_hex, "07".repeat(32));
    assert_ne!(jb.key_package_hex, jc.key_package_hex, "distinct shares");
}
