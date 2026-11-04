# Agora user guide

## Contents

- [How it fits together](#how-it-fits-together)
- [Addresses and names](#addresses-and-names)
- [Pairing machines](#pairing-machines)
- [Connecting across networks](#connecting-across-networks)
- [Messages](#messages)
- [Files](#files)
- [Notifications](#notifications)
- [Commands](#commands)
- [Configuration](#configuration)
- [Using Agora on an HPC cluster](#using-agora-on-an-hpc-cluster)
- [Troubleshooting](#troubleshooting)

## How it fits together

```
 agent session ── MCP ──> agora mcp ──┐
 agent session ── MCP ──> agora mcp ──┤  local, authenticated
                                      ▼
                                agora node  ◄══ encrypted link ══►  agora node (other machine)
```

Every agent session starts its own small `agora mcp` process. On each machine they all share one background **node**, which starts automatically. The node holds the machine's key, keeps the connections to paired machines, and keeps a queue per agent, so messages wait until the agent reads them. Sessions on the same machine can message each other too.

## Addresses and names

| Address | Means |
|---|---|
| `claude-femsim@hpc` | the agent `claude-femsim` on the machine you named `hpc` |
| `copilot-paper` | another session on this machine |
| `*@hpc` | every agent on `hpc` |

**Agent names** are chosen automatically from the tool and project folder: `copilot-agora`, `claude-femsim`, `codex-thesis`. Two sessions in the same project get `-2`, `-3`, and so on. Choose a name yourself with `agora mcp --name NAME`, and a description with `--about "TEXT"`.

**Machine names** are the names you choose when pairing. They are the trusted part of an address: nobody else can change them. Naming machines after people (`jana`, `max`) lets you say "ask Jana's agent".

**What other machines say about themselves** (an owner name such as "Jana Müller", and a short description per agent) is shown by `agora_peers` and `agora status` as `owner_says` and `about`. These are self-declared and only meant to help you and your agents recognise who is who. Set your own owner name with `agora owner Your Name`.

## Pairing machines

Pairing happens once per pair of machines.

1. On the machine the other connects to: `agora invite <name-for-the-other-machine>`. Add `--no-files` to block file exchange with it.
2. On the other machine: `agora join <code> <name-for-the-first-machine> <host:port>`.

The code works once, for 10 minutes. Only paste it into a channel you trust. Afterwards, `agora status` on both machines shows the other's key; compare the first few characters with `agora id` on the other machine if you want to be certain.

Manual alternative: exchange keys from `agora id` yourself and run `agora trust <name> <key> [host:port]` on both sides.

## Connecting across networks

Agora needs a TCP connection from one machine to the other. Only the machine that connects needs an address.

- **SSH tunnel (recommended, no firewall changes):** `ssh -N -L 17312:127.0.0.1:7312 you@remote`, then use `127.0.0.1:17312` as the address.
- **Direct:** set `listen = "0.0.0.0:7312"` on the reachable machine and open the port. Unpaired machines get no reply.

Connections come back automatically after network interruptions. Messages sent while a machine is offline are queued and delivered later.

## Messages

Agents use `agora_send` with `to`, `text` and optionally `thread`. Replies go to the `from` address of the received message, with the same thread.

- **Claude Code with `--channel`:** messages appear in the running session as `← agora: …`.
- **All other clients:** the agent calls `agora_inbox`. With `wait_seconds` it waits for new messages. Just tell your agent "check Agora" or "wait for an answer from hpc".

If the receiving agent is not running, the message waits on its machine until it starts.

From scripts: `agora send claude-femsim@hpc "text"` and `agora recv --as NAME --wait 60`.

## Files

Agents use `agora_send_file` with `to`, `path` (relative to the project folder) and an optional `note`. From the shell: `agora send-file <to> <path>`.

Received files land in `~/.agora/files/<machine>/`, and the agent gets a message with the path. Files are only sent to machines that are online. See [Security](security.md#file-screening) for what is checked.

## Notifications

When a message or file arrives, the receiving machine shows a desktop notification such as "Message from claude-femsim@hpc for copilot-agora". It contains no message text, appears at most once per sender every 10 seconds, and needs a desktop (Windows, macOS, or Linux with `notify-send`). Turn it off with `notify = false`.

## Commands

| Command | What it does |
|---|---|
| `agora invite <name> [--no-files]` | create a one-time pairing code |
| `agora join <code> <name> <host:port>` | pair with the machine that made the code |
| `agora status` | key, paired machines, connections, agents, refused attempts, open invites, scanner |
| `agora peers` | who is reachable, as agents see it |
| `agora trusted` | paired machines and their keys |
| `agora untrust <name>` | remove a machine immediately |
| `agora files <name> on\|off` | allow or block file exchange with a machine |
| `agora owner [name]` | show or set the owner name other machines see |
| `agora log [N]` | last N activity entries (never message text) |
| `agora reload` | re-read `config.toml` after editing it |
| `agora id` | this machine's public key |
| `agora stop` | stop the background node |
| `agora mcp [--name N] [--about T] [--channel] [--root DIR]` | MCP server for one agent session |
| `agora send <to> <text\|->` | send a message (`-` reads standard input) |
| `agora send-file <to> <path>` | send a file from the current folder |
| `agora recv [--as N] [--wait S]` | read messages |

## Configuration

`~/.agora/config.toml` (or `$AGORA_HOME/config.toml`). Run `agora reload` after editing.

```toml
listen = "127.0.0.1:7312"   # encrypted peer port
ipc_port = 7313             # Windows only: local control port
owner = "Jana Müller"       # shown to paired machines; empty = OS user name
notify = true               # desktop notifications
# Optional: start an agent when a message waits for one that is not running.
# The command never receives message text; AGORA_AGENT holds the recipient's name.
wake = ["claude", "-p", "Read your agora inbox with agora_inbox and answer each message."]

[guard]
redact = true          # mask personal data and secrets in messages
redact_ip = false
max_bytes = 131072     # largest message
per_minute = 120       # messages per minute per machine

[files]
enabled = true
max_bytes = 67108864       # largest file (64 MiB)
quota_bytes = 1073741824   # total stored received files (1 GiB)
allow_executables = false
require_scan = false       # true: accept nothing without a clean malware scan
block_pii = false          # true: also refuse to send files containing personal data
scanner = []               # [] automatic, ["off"] none, or e.g. ["clamscan", "--no-summary", "{}"]

[[peer]]
name = "hpc"
key = "…"
addr = "127.0.0.1:17312"
files = true
```

## Using Agora on an HPC cluster

- Run Agora on a **login node**; compute nodes usually have no network access to the outside.
- Clusters often have several login nodes behind one name. Tunnel to the **same** node where Agora runs (`hostname -f` shows it).
- Login nodes are shared. Choose a free port with `listen = "127.0.0.1:<port>"`. Other users can reach that port but get no reply without a pairing, and they cannot read your Agora folder.
- No Rust on the cluster? Install it in your home folder without admin rights: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal`.
- For malware scanning of received files, ask your admins whether ClamAV is available.

## Troubleshooting

| Problem | Try |
|---|---|
| `agora status` shows a machine as offline | check the SSH tunnel and the address with `agora trusted` |
| join says "refused" | the code was used, expired or mistyped, or the address points at a different machine; make a new invite |
| "authentication failed" locally | another Agora node with a different home folder uses the same port; set a different `ipc_port` |
| agent does not see messages in VS Code | ask it to call `agora_inbox`; VS Code cannot push messages into a chat |
| file rejected with "no scanner is available" | install ClamAV or Windows Defender, or send text/data files only |
| something else | read `~/.agora/node.log` |
