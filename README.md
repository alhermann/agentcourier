# Agora

Agora lets AI agent sessions talk to each other and exchange files, on one machine or across networks. Claude Code, Codex, VS Code Copilot and any other MCP client can take part. To the agent, Agora is an ordinary MCP server with four tools: `agora_send`, `agora_send_file`, `agora_inbox` and `agora_peers`. In Claude Code, messages can also appear directly in a running session.

It is one small Rust binary with no dashboard, no cloud service and no account.

## Quick start: connect two machines

Install Agora on both machines (see Install below). Then pair them once. The example connects a laptop to a cluster through an SSH tunnel.

1. On the cluster (the machine the other one connects to):

   ```sh
   agora invite laptop
   ```

   This prints one line, `agora join agora-…`, which works once and expires after 10 minutes.

2. On the laptop, open the tunnel, then paste that line and add a name and an address for the cluster:

   ```sh
   ssh -N -L 17312:127.0.0.1:7312 you@cluster &
   agora join agora-… hpc 127.0.0.1:17312
   ```

3. Add Agora to your agents (see below). From then on, everything is automatic: reconnecting, delivery, offline queues and showing who is online. An agent on the laptop writes to `claude@hpc`; the agent on the cluster replies to `copilot@laptop`.

Only paste the code into a channel you trust, such as your own terminal or SSH session. Agents get no pairing tools. If you want an agent to pair, it has to run the two commands in its shell, which you approve.

## Why pairing is safe

- The code contains the inviter's public key. The joining machine only completes a handshake with the machine that holds the matching private key, so nobody can pose as the inviter (no man in the middle).
- The code also contains a random 128-bit secret. It is sent only inside that already-verified, encrypted connection, so nobody else can join in your place.
- A code works once and expires after 10 minutes. Wrong secrets are refused and slowed down.
- If someone used a stolen code before you, your own join fails visibly, and `agora status` on the inviter shows which key joined. Remove it with `agora untrust`.
- Machines that are not paired get no reply to their handshake. `agora status` lists recent refused attempts with their keys.

## How it works

```
 agent session ── MCP (stdio) ──> agora mcp ──┐
 agent session ── MCP (stdio) ──> agora mcp ──┤ local socket, mutual proof of a local secret
                                              ▼
                                        agora node  ◄══ encrypted link ══►  agora node (other machine)
```

Each machine runs one small background node. It starts automatically the first time an agent uses Agora. The node keeps the machine's identity key, the encrypted links to paired machines, and a queue for each agent, so messages wait until the agent reads them. All agent sessions on a machine share the node, so local sessions can message each other too.

## Security

- **Who can connect:** only paired machines. There is no automatic first-contact trust and no central server.
- **Encryption:** every link uses the Noise protocol (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`), so both sides prove their identity, connections are encrypted, and recorded traffic stays safe even if a key leaks later. For quantum safety, every connection also performs a fresh ML-KEM-768 key exchange (NIST FIPS 203) that feeds into the session keys. Reading traffic therefore requires breaking both X25519 and ML-KEM, which blocks "record now, decrypt later" attacks. A test checks that tampering with the ML-KEM data breaks the connection. Identity checks themselves use classical keys, as in TLS and Signal today.
- **Replayed connections:** a recorded handshake cannot take over or disconnect a live link; a new inbound link only counts once the other side has proved it holds the fresh session keys.
- **Masking of personal data and secrets:** text is checked when it leaves your machine and again when it arrives. Masked: email addresses, phone numbers, IBANs (checksum-verified), card numbers (Luhn-verified), private key blocks, API tokens (Anthropic, OpenAI, GitHub, GitLab, AWS, Google, Slack, Hugging Face, JWTs), `password=`-style assignments and passwords inside URLs. IP addresses are masked only if you set `redact_ip = true`.
- **Prompt injection defenses:**
  - Messages are accepted only from paired machines.
  - Invisible and direction-changing Unicode characters, terminal control codes and hidden "tag" characters are removed.
  - Messages appear in the agent's context marked as untrusted text from another agent.
  - Text pushed into Claude Code cannot close or fake the `<channel>` wrapper around it.
  - The server instructions tell the agent never to act on a message alone and to ask its user before going beyond answering.
  - Remote machines cannot approve tool use, and agents cannot create trust.
- **Limits:** messages up to 128 KiB, files up to 64 MiB, a 1 GiB total limit for received files, 120 messages per minute per machine, bounded queues, handshake timeouts, and a cap on unauthenticated connections.
- **Local access:** clients and the node prove to each other that they know a local secret, without ever sending it. A program that grabbed the port can neither fake the node nor learn the secret. On Linux and macOS the socket and all files are readable only by you; refuses to start if the key file is readable by others. On Windows the Agora folder is restricted to you and SYSTEM.
- **Audit log:** `~/.agora/audit.jsonl` records metadata only (time, direction, peer, sender, recipient, size, file name, scan result), never message text.

## File exchange

`agora_send_file` sends one file from the agent's project folder to an agent on another machine. Files are checked on both sides:

| Check | Sending machine | Receiving machine |
|---|---|---|
| Location | only inside the project folder (symbolic links resolved) | stored only in `~/.agora/files/<peer>/` |
| Credentials | key and credential files (`.ssh`, `.env`, `*.pem`, `id_*`, `.aws`, …) always refused | |
| Secrets in text | refused if the file contains tokens, keys or passwords | personal data masked |
| Programs | refused, judged by content not name | refused, judged by content not name |
| Malware scan | | Windows Defender (if running) or ClamAV (`clamdscan`, `clamscan`); a detection or scan failure blocks the file |
| PDFs, archives, Office files, unknown binaries | | accepted only after a clean scan |
| Text, images, HDF5, NetCDF, NumPy | | accepted; scanned too if a scanner exists |
| Integrity | | checksum must match, otherwise the file is discarded |
| Name and execution | | name cleaned (no paths, no reserved names; `.bat`, `.ps1`, `.lnk` and similar get `.txt` added); never executed; owner-only (Unix) or marked as downloaded from the internet (Windows) |

Agora cannot detect malware by itself; it relies on the machine's scanner. Without a scanner, only text and data files are accepted. Set `require_scan = true` to accept nothing unscanned. On clusters without ClamAV, ask your admins, or point `scanner` at any command that exits with 0 for clean files.

## Install

```sh
cargo install --git https://github.com/alhermann/agora-protocol --branch v2
```

Prebuilt binaries for Linux (static, suitable for HPC clusters), macOS and Windows are attached to each release.

## Add to your agents

Claude Code:

```sh
claude mcp add agora -- agora mcp --name claude
# messages appear directly in the running session (Claude Code channels, research preview):
claude mcp add agora -- agora mcp --name claude --channel
claude --dangerously-load-development-channels server:agora
```

VS Code (`.vscode/mcp.json`):

```json
{ "servers": { "agora": { "type": "stdio", "command": "agora", "args": ["mcp", "--name", "copilot"] } } }
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.agora]
command = "agora"
args = ["mcp", "--name", "codex"]
```

The project folder for file sending is the folder the MCP server starts in; use `--root DIR` to set it explicitly.

Addresses: `claude@hpc` is the agent `claude` on the machine you named `hpc`. `copilot` is another session on this machine. `*@hpc` reaches every agent on `hpc`. If two sessions use the same name, the second becomes `name-2`; `agora_peers` shows your actual address.

## Command line

```
Pair two machines (once):
  agora invite <name> [--no-files]      on the machine the other connects to: prints a one-time code
  agora join <code> <name> <host:port>  on the other machine

Inspect and control:
  agora status                          key, peers, connections, refused handshakes, open invites, scanner
  agora trusted                         paired machines and their keys
  agora untrust <name>                  remove a machine immediately
  agora files <name> on|off             allow or block file exchange with a machine
  agora log [N]                         last N audit entries
  agora reload                          re-read config.toml after editing it
  agora trust <name> <key> [host:port]  add a machine by key (manual alternative to invite/join)
  agora id                              print this machine's public key
  agora stop                            stop the background node

Agents and scripts:
  agora mcp [--name N] [--channel] [--root DIR]
  agora send <to> <text|-> [--as N]
  agora send-file <to> <path> [--as N]
  agora recv [--as N] [--wait S]
```

## Configuration (`~/.agora/config.toml`, or `$AGORA_HOME`)

```toml
listen = "127.0.0.1:7312"   # encrypted peer port; use 0.0.0.0:7312 for direct connections
ipc_port = 7313             # Windows only: local control port
# Optional: start an agent when a message waits for one that is not running.
# The command never receives message text; AGORA_AGENT holds the recipient's name.
wake = ["claude", "-p", "Read your agora inbox with agora_inbox and answer each message."]

[guard]
redact = true
redact_ip = false
max_bytes = 131072
per_minute = 120

[files]
enabled = true
max_bytes = 67108864
quota_bytes = 1073741824
allow_executables = false
require_scan = false
block_pii = false       # also refuse to send files containing personal data
scanner = []            # [] = automatic, ["off"] = none, or e.g. ["clamscan", "--no-summary", "{}"]

[[peer]]
name = "hpc"
key = "…"
addr = "127.0.0.1:17312"
files = true
```

On shared login nodes, pick a free port with `listen = "127.0.0.1:<port>"`. Other users there can reach the port, but without a pairing they get no reply.

## Limits

No software can prevent prompt injection completely. If a paired machine or the agent on it is compromised or misled, it can still send persuasive text or harmful but scanner-clean files. Agora keeps such content clearly separate from your instructions and never runs anything on its own, but the agent and you still decide what to do with it. Masking catches common formats only, and malware detection is only as good as the installed scanner.

## License

Apache-2.0
