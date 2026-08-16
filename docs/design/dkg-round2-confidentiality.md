# DKG round-2 packages need a confidential channel

Status: **open**. Found 2026-08-16. Affects zigner, zafu and zcli, since all
three share `frost-spend`.

## What happens today

`orchestrate::dkg_part2` builds one message per peer
(`crates/frost-spend/src/orchestrate.rs`):

```rust
payload = {"recipient": <id>, "package": <round2 package hex>}
peer_packages.push(SignedMessage::sign(&sk, &payload))
```

`SignedMessage` is `{pk, sig, payload}` (`src/message.rs`) and stores
`payload` verbatim. The round-2 packages are **signed but not encrypted**.

zigner then renders the whole array as a QR for the next participant to
scan (`FrostDkgScreen.kt`, round 2 branch):

```kotlin
qrData = json.getJSONArray("peer_packages").toString()
```

So every round-2 package is displayed, in the clear, on a screen.

## Why this is not merely untidy

A round-2 package carries participant *i*'s secret polynomial evaluated at
participant *j*. Participant *j*'s final signing share is the sum of those
evaluations over all *i*.

With *n* participants and threshold *t*, each dealer's polynomial has degree
*t−1*, so it is determined by *t* points. An observer of the full round-2
traffic sees *n−1* evaluations of each polynomial. Whenever **n > t** those
polynomials can be interpolated outright — and the group secret follows.

2-of-3, our flagship configuration, satisfies n > t.

The correct statement is therefore not "shares could leak". It is: **passive
observation of the DKG ceremony recovers the group signing key**, and with it
spend authority.

RFC 9591 and frost-core's own documentation both require the round-2 channel
to be authenticated *and* confidential. We have authentication only.

## Threat model

For an in-person QR ceremony the attacker must see the screens: a camera in
the room, a photograph, a shoulder, a screen-share. None of that is exotic.

The sharper framing: a threshold scheme exists so that compromising one
participant is not enough. Here, observing the *setup* compromises every
participant simultaneously, so against that attacker the threshold buys
nothing at all.

It gets worse if DKG is ever coordinated through a relay. A relay would see
every round-2 package in clear and could reconstruct the group key on its
own. `relay_url` already exists in the wallet record, so this is a direction
the code can plausibly grow.

## Proposed fix

Round 1 already broadcasts each participant's identity key as
`SignedMessage.pk`, so by round 2 the sender holds every recipient's public
key. Seal each package to its recipient — sign, then encrypt per-recipient —
instead of signing and publishing.

Three constraints:

1. **Use a fresh X25519 key, not the ed25519 signing key.** Add a dedicated
   encryption public key to the round-1 broadcast. 32 extra bytes avoids
   making one keypair both a signature key and a decryption key.
2. **Version the QR protocol.** The `{"frost":"dkg1"}` envelopes need a
   version field or new tags, so an old participant and a new one fail
   loudly rather than silently completing a ceremony with one side in
   cleartext.
3. **Raw sealed box, not age armor.** These travel as QR frames where
   capacity is the binding constraint; armor costs base64 plus a couple
   hundred bytes per package. X25519 + ChaCha20-Poly1305 directly is
   tighter, and both primitives are already in the tree.

## Existing wallets

**No production wallets are affected.** The multisig path never shipped to
users, so there is no ceremony in the wild whose packages were exposed and
nothing to re-key.

Recording that explicitly because the fix is a hard wire break, and a reader
finding this later would otherwise reasonably assume there were compromised
wallets to chase. Had it shipped, the remedy would have been a fresh DKG and
a move of funds — a patch could not have helped, since the packages were
already displayed.
