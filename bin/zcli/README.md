# zcli

zcash wallet CLI. uses your ssh ed25519 key as wallet seed — no new
mnemonics to back up. if you already protect your ssh key, your zcash
wallet is already backed up.

also supports standard bip39 mnemonics via `--mnemonic`.

syncs against [zidecar](https://github.com/rotkonetworks/zeratul) for
trustless compact block scanning with ligerito header proofs.

## install

```
cargo install --git https://github.com/rotkonetworks/zcli
```

## usage

```
# show addresses (uses ~/.ssh/id_ed25519 by default)
zcli address

# receive — prints QR code in terminal
zcli receive

# sync chain (resumes from last position)
zcli sync

# check balance
zcli balance

# shield transparent funds to orchard
zcli shield

# send (z→t or z→z, auto-detected from address)
zcli send -a 0.01 -t u1address...

# send with memo
zcli send -a 0.01 -t u1address... -m "gm"

# use a different ssh key
zcli -i ~/.ssh/id_work balance

# use bip39 mnemonic instead
zcli --mnemonic "abandon abandon ... art" balance

# custom endpoint
zcli --endpoint https://your-zidecar.example.com sync

# json output for scripting
zcli --script balance
```

## key derivation

**ssh key mode** (default): reads your ed25519 private key, derives a
zcash-specific seed via `BLAKE2b-512("ZcliWalletSeed" || ed25519_seed)`.
your ssh key passphrase is prompted if the key is encrypted. set
`ZCLI_PASSPHRASE` for non-interactive use.

**mnemonic mode**: standard bip39 seed derivation, compatible with other
zcash wallets.

both modes derive:
- orchard spending key via ZIP-32 (`m/32'/133'/0'`)
- transparent key via BIP-44 (`m/44'/133'/0'/0/0`)

## wallet storage

notes and sync state stored in sled at `~/.zcli/wallet`. delete to
resync from scratch.

## privacy

- trial decryption: downloads all compact blocks, decrypts locally.
  the server never learns which notes are yours.
- orchard shielded pool only (no sapling legacy).
- ZIP-317 fee calculation.

## environment variables

| variable | description |
|---|---|
| `ZCLI_IDENTITY` | path to ed25519 ssh key (default: `~/.ssh/id_ed25519`) |
| `ZCLI_MNEMONIC` | bip39 mnemonic (overrides ssh key) |
| `ZCLI_ENDPOINT` | zidecar gRPC endpoint (default: `https://zcash.rotko.net`) |
| `ZCLI_PASSPHRASE` | ssh key passphrase (non-interactive) |
| `ZCLI_SCRIPT` | enable json output |

## license

MIT
