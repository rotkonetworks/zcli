# zcli

zcash wallet for agents & humans. uses your ssh ed25519 key as wallet seed —
no new mnemonics to back up. if you already protect your ssh key, your zcash
wallet is already backed up.

also supports standard bip39 mnemonics via `--mnemonic`.

syncs against [zidecar](https://github.com/rotkonetworks/zcli/tree/master/bin/zidecar)
for trustless compact block scanning with ligerito header proofs.

## install

```
cargo install zecli
```

or grab a binary from [releases](https://github.com/rotkonetworks/zcli/releases):

```sh
curl -fsSL https://github.com/rotkonetworks/zcli/releases/latest/download/zcli-linux-amd64 -o zcli
chmod +x zcli && sudo mv zcli /usr/local/bin/
```

## commands

```
zcash wallet CLI - ssh keys as wallet seed

Usage: zcli [OPTIONS] <COMMAND>

Commands:
  address     show wallet addresses
  balance     show wallet balance
  shield      shield transparent funds (t→z)
  send        send zcash
  receive     print receiving address
  sync        scan chain for wallet notes
  export      export wallet keys (requires confirmation)
  notes       list all received notes
  history     show transaction history (received + sent)
  board       run board: sync loop + HTTP API serving notes as JSON
  scan        scan QR code from webcam
  import-fvk  import FVK from zigner QR (watch-only wallet)
  verify      verify proofs: header chain, commitment proofs, nullifier proofs
  tree-info   show orchard tree info at a height (for --position)
  merchant    merchant payment acceptance + cold storage forwarding
  help        Print this message or the help of the given subcommand(s)

Options:
  -i, --identity <IDENTITY>
          path to ed25519 ssh private key [default: ~/.ssh/id_ed25519]
      --mnemonic <MNEMONIC>
          use bip39 mnemonic instead of ssh key
      --endpoint <ENDPOINT>
          zidecar gRPC endpoint [default: https://zcash.rotko.net]
      --verify-endpoints <VERIFY_ENDPOINTS>
          lightwalletd endpoints for cross-verification [default: https://zec.rocks]
      --json
          machine-readable json output, no prompts/progress/qr
      --mainnet
          use mainnet (default)
      --testnet
          use testnet
  -h, --help
          Print help
```

## usage

```sh
zcli address                              # show addresses
zcli sync                                 # scan chain
zcli balance                              # check funds
zcli send 0.01 u1...                      # send shielded
zcli shield                               # t-addr → shielded
zcli verify                               # verify chain proofs
zcli notes --json                         # list received notes
zcli history                              # tx history
zcli merchant --forward u1cold...         # accept payments, forward to cold
```

all commands accept `--json` for machine-readable output.
set `ZCLI_IDENTITY`, `ZCLI_ENDPOINT` as env vars for headless operation.

## air-gapped signing with zigner

[zigner](https://zigner.rotko.net) is an air-gapped signing app for android.
keys never leave the device — communication happens entirely through QR codes.

```
  zigner (offline)                  zcli (online)
  ┌──────────────┐                 ┌──────────────┐
  │ generate keys │    FVK QR      │ import-fvk   │
  │ hold spend key│ ──────────────▸ │ watch-only   │
  └──────────────┘                 │ sync & build │
  ┌──────────────┐    unsigned tx  │              │
  │ verify & sign │ ◂────────────── │ send --cam   │
  │ display QR   │ ──────────────▸ │ broadcast    │
  └──────────────┘    signed tx    └──────────────┘
```

```sh
zcli import-fvk --cam                     # scan zigner's FVK QR
zcli sync --wallet zigner                 # sync the watch wallet
zcli send 1.0 u1... --wallet zigner --cam # build tx, scan signed QR back
```

## key derivation

**ssh key mode** (default): reads your ed25519 private key, derives a
zcash-specific seed via `BLAKE2b-512("ZcliWalletSeed" || ed25519_seed)`.
your ssh key passphrase is prompted if the key is encrypted. set
`SSH_PASSPHRASE` for non-interactive use.

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
| `ZCLI_VERIFY_ENDPOINTS` | lightwalletd endpoints for cross-verification (default: `https://zec.rocks`) |
| `SSH_PASSPHRASE` | ssh key passphrase (non-interactive) |
| `ZCLI_JSON` | enable json output |

## license

MIT
