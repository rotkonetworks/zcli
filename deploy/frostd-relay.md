# Running a FROST relay (frostd) at relay.zafu.pro

The relay forwards opaque blobs between signers. It is **designed to be
untrusted**: every message is end-to-end encrypted with Noise_K before it
leaves a participant's device, so a relay operator — including us — cannot
read a ceremony, forge a message, or join one.

That is what makes it reasonable to run one for other people, and to let them
run their own. It is also why the deployment below is boring: there is no key
material on this host.

## What the operator CAN see

Worth being explicit, because "cannot read the ceremony" is not "sees
nothing":

- **who is talking to whom** — participant public keys per session, and the
  timing and size of their messages
- **that a group of N is forming or signing**, and roughly when

Not the recipient, amount, sighash, PCZT, or any key material. If session
metadata matters to a user, that is the reason to run their own — the
`relay` field in the UI exists for exactly that.

## TLS is not optional

frostd serves plain HTTP. Terminate TLS in front of it and bind frostd to
loopback only.

Without TLS the bearer token and the participant list are visible to anyone
on the path, and a stolen token lets someone drain a peer's queue and inject
rubbish into a session. Ceremony *contents* stay safe either way — they are
encrypted before they reach the wire — but that is not a reason to skip it.

zidecar enforces this: `--frostd-listen` refuses a non-loopback address
unless `--frostd-insecure` is passed, precisely so a misconfiguration fails
at startup rather than quietly serving plaintext.

## Caddy

Matching `Caddyfile.zidecar` in this directory — same pattern, ACME handled
automatically. See `Caddyfile.frostd`.

    relay.zafu.pro {
        reverse_proxy 127.0.0.1:2744 {
            # frostd holds queued messages until a peer polls; do not cut a
            # ceremony short because a participant is slow to answer
            transport http {
                read_timeout 300s
            }
        }

        request_body {
            max_size 2MB          # frostd caps messages at 1 MiB
        }
    }

## systemd

    [Unit]
    Description=frostd FROST relay
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    User=frostd
    Group=frostd
    # loopback only: caddy terminates TLS
    ExecStart=/usr/local/bin/frostd --ip 127.0.0.1 --port 2744 --no-tls-very-insecure
    Restart=on-failure
    RestartSec=5

    # There are no secrets on this host and nothing to persist. Lock it down
    # accordingly - a compromised relay should gain an attacker nothing, and
    # this makes that true of the machine as well as the protocol.
    NoNewPrivileges=true
    PrivateTmp=true
    ProtectSystem=strict
    ProtectHome=true
    ReadWritePaths=
    PrivateDevices=true
    ProtectKernelTunables=true
    ProtectKernelModules=true
    ProtectControlGroups=true
    RestrictAddressFamilies=AF_INET AF_INET6
    MemoryDenyWriteExecute=true

    [Install]
    WantedBy=multi-user.target

## Alternatively, via zidecar

If you already run zidecar, it mounts the same upstream router:

    zidecar --frostd-listen 127.0.0.1:2744 ...

Same server, one less process. The relay starts before the zebrad connection
on purpose — a ceremony has nothing to do with the chain node, and should not
stall because it is down.

## Verifying a deployment

    curl -s -X POST https://relay.zafu.pro/challenge \
      -H 'content-type: application/json' -d '{}'

Should return `{"challenge":"<uuid>"}`. That is the whole health check: if
the challenge endpoint answers, sessions work.

## State

frostd keeps sessions in memory and expires them. There is no database, no
backup, and nothing to migrate. A restart drops in-flight ceremonies —
participants simply start again — so restart freely.
