# Review request: FROST DKG sealing and relay transport

Status: **unreviewed**. Everything below is our own analysis and our own
tests. It touches the path that establishes spend authority, so "our tests
pass" is not the standard it should be held to.

The intent is to make reviewing cheap: each claim below names the file and the
test that is supposed to back it, so a reviewer can go straight at the ones
they doubt.

## What changed, in one paragraph

DKG round-2 packages used to travel signed but not encrypted, displayed on a
QR. They now travel sealed with Noise_K. Separately, the relay transport moved
from three bespoke protocols (a gRPC room service, a WebSocket room service, a
poker WebSocket) to ZF's frostd, with ZF's frost-client on the zcli side and a
byte-compatible reimplementation on the wasm side.

## The claims, and what backs each

| # | Claim | Where | Test |
|---|---|---|---|
| 1 | Round-2 packages carry no plaintext share | `frost-spend/src/orchestrate.rs` | `round2_wire_bytes_do_not_contain_the_share` |
| 2 | A sealed package cannot be replayed into another ceremony | `sealed.rs` (Noise prologue) | `a_package_from_another_ceremony_does_not_open` |
| 3 | A package cannot be reattributed to another sender | `sealed.rs` (Noise `ss`) | `a_message_cannot_be_reattributed_to_another_sender` |
| 4 | A v1 peer cannot join a v2 ceremony | `orchestrate.rs` version gate | `a_v1_round1_broadcast_is_rejected` |
| 5 | Our wasm cipher is byte-compatible with ZF's | `frost-spend/src/relay_cipher.rs` | `our_wasm_cipher_interoperates_with_upstream` |
| 6 | Our challenge signature satisfies a real frostd | `relay_cipher::sign_challenge` | `our_wasm_signature_is_accepted_by_a_real_frostd` |
| 7 | A full 2-of-3 ceremony completes over the relay | end to end | `a_full_2of3_ceremony_completes_over_the_relay` |
| 8 | The relay holds no ceremony plaintext | end to end | `the_relay_never_sees_ceremony_plaintext` |

## Where we would look first if we were attacking it

- **The transcript is hashed over `serde_json` output**, which is not
  canonical. Both sides serialize the same struct with the same serde, so the
  bytes agree in practice — but that is an implementation detail holding up a
  security property. Documented in `relay_cipher.rs`.
- **`relay_cipher.rs` is a reimplementation.** It exists only because
  frost-client will not build for wasm32 (message-io, rpassword, tokio). The
  interop test is what keeps it honest, and it is the single point of failure
  for that argument.
- **We derive the X25519 key from the session's ed25519 seed by HKDF**, where
  ZF reuses one key via XEdDSA. Different choice, same goal; worth a second
  opinion on whether ours buys anything.
- **Noise sessions are stateful and the relay is poll-based.** Messages must
  be consumed in order per peer. Three concurrent CLI processes already found
  one ordering bug that no unit test caught (rounds are now tagged); we would
  not assume that was the last one.

## What is NOT protected

Wallets from ceremonies run before this are not retroactively protected — the
packages were already displayed. Where a ceremony could have been observed,
the remedy is a fresh DKG and moving funds, not an upgrade.

## Running it

    cargo test -p frost-spend          # sealing, cipher, transcript
    cargo test -p zecli                # transport, ceremony, interop
    cargo test -p zidecar              # the mounted frostd router
