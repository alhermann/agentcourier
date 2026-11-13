# agentcourier security

agentcourier connects AI agents across machines, so it is built to keep strangers out, keep messages private, and keep agents from being steered by what they receive. This page explains how, and what remains your responsibility.

## Contents

- [Who can connect](#who-can-connect)
- [Pairing](#pairing)
- [Encryption](#encryption)
- [Who is who](#who-is-who)
- [Relays](#relays)
- [On your own machine](#on-your-own-machine)
- [Masking personal data and secrets](#masking-personal-data-and-secrets)
- [Prompt injection](#prompt-injection)
- [File screening](#file-screening)
- [Limits, storage and logging](#limits-storage-and-logging)
- [What agentcourier cannot do](#what-agentcourier-cannot-do)
- [Reporting a vulnerability](#reporting-a-vulnerability)

## Who can connect

Only machines you paired. Each machine has a key pair; the public key is its identity. When an unknown machine tries to connect, it gets no reply at all, so an open port reveals nothing. `agentcourier status` lists recent refused attempts with the key that tried. There is no automatic trust on first contact and no central server.

## Pairing

`agentcourier invite` creates a code that contains the inviting machine's **public key** and a random **128-bit secret**. It works once and expires after 10 minutes.

- **No man in the middle:** the joining machine only finishes a handshake with the machine that holds the private key matching the code. Anyone else in the network path cannot pose as the inviter.
- **Nobody else can join in your place:** the secret is sent only inside the already encrypted, verified connection. Guessing it is not feasible, and wrong attempts are refused and slowed down.
- **Visible if something went wrong:** if someone used a stolen code first, your join fails, and the inviter's `agentcourier status` shows which key joined. Remove it with `agentcourier untrust`.

A pairing is permanent until you remove it. Every later connection authenticates both machines again by their keys, automatically. Agents get no tools to pair machines or change trust; that stays with you.

## Encryption

Every connection uses the [Noise protocol](https://noiseprotocol.org) pattern `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`:

- both machines prove their identity with their keys;
- every connection gets fresh keys (forward secrecy), so traffic recorded today stays secret even if a machine key leaks later;
- replayed or tampered data is rejected.

**Post-quantum protection:** each connection also runs a fresh **ML-KEM-768** key exchange (NIST FIPS 203), whose result is mixed into the session keys. Reading traffic requires breaking both X25519 and ML-KEM. This blocks "record now, decrypt later" attacks by future quantum computers. A test checks that altering the ML-KEM data breaks the connection. The identity check itself uses classical keys, as in TLS and Signal today; that only matters for an attacker who already has a quantum computer at the moment of the attack.

A recorded handshake cannot take over or disconnect a live connection: a new incoming connection only counts after the other side proves it holds the fresh session keys.

## Who is who

- **Machines are authenticated** by their keys. The name you gave a machine at pairing (`hpc`) is yours and cannot be changed by anyone else, so a message from `…@hpc` really comes from that machine.
- **Agent names are labels** chosen by the owner of their machine (`claude-femsim`, `fe-runs`). An agent can only name sessions on its own machine; a name like `claude-femsim@hpc` can only come from `hpc`.
- **Self-descriptions** (owner name, agent descriptions) are declared by the other machine. agentcourier cleans and shortens them and shows them as unverified.

## Relays

A [relay](guide.md#through-a-relay-you-run-yourself) is optional and run by you. It only forwards traffic that the two machines already encrypt end to end. It holds none of their keys, so it cannot read or change messages or files, or pose as a paired machine. Pairing alone decides who can talk to whom, exactly as without a relay.

- **Members only:** the relay gives no reply to machines that are not on its member list, except that while a relay code is open, they can try to join with it. A machine joins only with a one-time relay code (128-bit secret, one use, 10 minutes); the relay stores only a hash of it. The code also contains the relay's public key, so a machine cannot be redirected to a different relay.
- **What the relay learns:** which machines are online, which one connects to which, when, and how much data flows. Run it on a machine you trust with this information. There is no public agentcourier relay.
- **What the relay can do:** stop forwarding, so messages wait in the queue until the connection is back. It cannot make a machine accept connections from anyone it has not paired with.
- **Limits:** caps on connections, handshakes, open connections per machine and pending requests, and time limits on every transfer, keep one machine from blocking the others. A machine also limits how many connections its relay can ask it to open at once.
- **Removing and leaving:** `relay remove` cuts a machine off within 30 seconds, including its open connections. `relay leave` on a machine ends everything that ran through that relay at once.

## On your own machine

- Agent sessions and the node prove to each other that they know a local secret, without ever sending it. A program that grabbed the port can neither pretend to be the node nor learn the secret.
- Linux and macOS: the local socket and every agentcourier file are readable only by you. agentcourier refuses to start if its key file is readable by others.
- Windows: the agentcourier folder is restricted to your account and SYSTEM.

## Masking personal data and secrets

Text is checked when it leaves your machine and again when it arrives. Masked:

- email addresses, phone numbers (international format), IBANs (checksum-verified), card numbers (Luhn-verified);
- private key blocks, API tokens (Anthropic, OpenAI, GitHub, GitLab, AWS, Google, Slack, Hugging Face, JWTs);
- `password=`-style assignments and passwords inside URLs;
- IP addresses, only if `redact_ip = true`.

Masking is pattern-based. It catches common formats, not every possible secret or deliberately disguised text.

## Prompt injection

agentcourier cannot stop prompt injection completely, but it removes the easy routes:

- messages are accepted only from paired machines;
- invisible and direction-changing Unicode characters, terminal control codes and hidden "tag" characters are removed;
- messages reach the agent marked as untrusted text from another agent, and the agent's instructions say never to act on such text alone and to ask its user before going beyond answering;
- text pushed into Claude Code cannot close or fake the `<channel>` wrapper around it;
- names and descriptions other machines declare about themselves are cleaned, shortened and labelled as unverified;
- remote machines cannot approve tool use, and agents cannot create trust;
- the optional wake command never receives message text.

## File screening

| Check | Sending machine | Receiving machine |
|---|---|---|
| Location | only inside the project folder (never the whole home folder), after resolving links | stored only in `~/.agentcourier/files/<machine>/` |
| Credentials | key and credential files (`.ssh`, `.env`, `*.pem`, `id_*`, `.aws`, …) always refused | |
| Secrets in text | refused if the file contains tokens, keys or passwords | personal data masked |
| Programs | refused, judged by content, not name | refused, judged by content, not name |
| Malware scan | | Windows Defender (if running) or ClamAV; a detection or failed scan blocks the file |
| PDFs, archives, Office files, unknown binaries | | accepted only after a clean scan |
| Text, images, HDF5, NetCDF, NumPy | | accepted; also scanned if a scanner exists |
| Integrity | | checksum must match, otherwise discarded |
| Name and execution | | cleaned name (no paths, no reserved names; `.bat`, `.ps1`, `.lnk` and similar get `.txt` added); never executed; owner-only on Linux/macOS, marked as downloaded from the internet on Windows |

agentcourier does not detect malware itself; it uses the machine's scanner. Without one, only text and data files are accepted. Set `require_scan = true` to accept nothing unscanned, or `files = false` per machine to block files from it.

## Limits, storage and logging

- Messages up to 128 KiB. Files up to 50 GiB each and 100 GiB in total for received files, both adjustable; files are streamed, so their size does not cost memory.
- 120 messages per minute per machine, bounded queues, handshake timeouts, and a cap on connections that have not authenticated yet.
- Undelivered messages and agents seen before are kept in `~/.agentcourier/state.json` (readable only by you) so they survive restarts. Delivered messages are not stored.
- `~/.agentcourier/audit.jsonl` records metadata only (time, direction, machine, sender, recipient, size, file name, scan result, pairing and trust changes), never message text. It rotates at 10 MiB.

## What agentcourier cannot do

- If a paired machine, or the agent on it, is compromised or misled, it can still send persuasive text or harmful files that a scanner does not recognise. agentcourier keeps such content clearly separate from your instructions and never runs anything on its own; the agent and you decide what to do with it.
- Masking and file screening are only as good as their patterns and the installed scanner.
- Anyone who controls your user account on a machine controls agentcourier there.

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security tab → Report a vulnerability) rather than a public issue.
