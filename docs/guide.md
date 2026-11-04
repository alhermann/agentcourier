# agentwire user guide

## Contents

- [How it fits together](#how-it-fits-together)
- [Names and addresses](#names-and-addresses)
- [Pairing machines](#pairing-machines)
- [Connecting across networks](#connecting-across-networks)
- [Messages](#messages)
- [Files](#files)
- [Notifications](#notifications)
- [Commands](#commands)
- [Configuration](#configuration)
- [Using agentwire on an HPC cluster](#using-agentwire-on-an-hpc-cluster)
- [Troubleshooting](#troubleshooting)

## How it fits together

```
 agent session ── MCP ──> agentwire mcp ──┐
 agent session ── MCP ──> agentwire mcp ──┤  local, authenticated
                                          ▼
                                   agentwire node  ◄══ encrypted link ══►  agentwire node (other machine)
```

Every agent session starts its own small `agentwire mcp` process. On each machine they all share one background **node**, which starts automatically and keeps running when agents close. The node holds the machine's key, keeps the connections to paired machines, and keeps a queue per agent, so messages wait until the agent reads them. Undelivered messages and the agents seen on other machines are stored on disk, so they survive restarts. Sessions on the same machine can message each other too.

## Names and addresses

| Address | Means |
|---|---|
| `claude-femsim@hpc` | the agent `claude-femsim` on the machine you named `hpc` |
| `copilot-paper` | another session on this machine |
| `*@hpc` | every agent on `hpc` that is online |

**Machines** are paired once, under a name you choose (`hpc`, `jana`). That name is the trusted part of an address: nobody else can change it. Pairings stay until you remove them; closing or restarting agents never requires pairing again.

**Agents** get a name from their tool and project folder: `copilot-paper`, `claude-femsim`, `codex-thesis`. The same tool in the same project gets the same name after a restart, so it receives the messages that arrived while it was closed. Two sessions in the same project at once get `-2`, `-3`, and so on. To choose a name:

- tell the agent, for example *"call yourself fe-runs"* (it uses `wire_set_name`);
- start it with `AGENTWIRE_NAME=fe-runs`, or `agentwire mcp --name fe-runs --about "FE mesh study"`.

**Finding an agent:** `wire_peers` (and `agentwire peers`) lists, per machine, the agents online now and the agents **seen before** with when they were last seen. A message to an offline agent waits on its machine and is delivered when that agent starts again. So "ask my Claude on the cluster" works even if that Claude is closed right now.

**Self-descriptions** (an owner name such as "Jana Müller", and a short description per agent) are shown as `owner_says` and `about`. Other machines declare them about themselves, so they help recognise who is who but are not verified. Set your own owner name with `agentwire owner Your Name`.

## Pairing machines

1. On the machine the other connects to: `agentwire invite <name-for-the-other-machine>`. Add `--no-files` to block file exchange with it.
2. On the other machine: `agentwire join <code> <name-for-the-first-machine> <host:port>`.

The code works once, for 10 minutes. Only paste it into a channel you trust. Afterwards, `agentwire status` on both machines shows the other's key; compare the first few characters with `agentwire id` on the other machine if you want to be certain.

Manual alternative: exchange keys from `agentwire id` yourself and run `agentwire trust <name> <key> [host:port]` on both sides.

## Connecting across networks

agentwire needs a TCP connection from one machine to the other. Only the machine that connects needs an address.

- **SSH tunnel (recommended, no firewall changes):** `ssh -N -L 17312:127.0.0.1:7312 you@remote`, then use `127.0.0.1:17312` as the address.
- **Direct:** set `listen = "0.0.0.0:7312"` on the reachable machine and open the port. Unpaired machines get no reply.

Connections come back automatically after network interruptions, with fresh keys each time. Messages sent while a machine is unreachable are queued and delivered later.

## Messages

Agents use `wire_send` with `to`, `text` and optionally `thread`. Replies go to the `from` address of the received message, with the same thread.

- **Claude Code with `--channel`:** messages appear in the running session as `← agentwire: …`, including messages that arrived while it was closed.
- **All other clients:** the agent calls `wire_inbox`. With `wait_seconds` it waits for new messages. Just tell your agent "check agentwire" or "wait for an answer from hpc".

From scripts: `agentwire send claude-femsim@hpc "text"` and `agentwire recv --as NAME --wait 60`.

## Files

Agents use `wire_send_file` with `to`, `path` (relative to the project folder) and an optional `note`. From the shell: `agentwire send-file <to> <path>`.

Received files land in `~/.agentwire/files/<machine>/`, and the agent gets a message with the path. Files are only sent to machines that are online. See [Security](security.md#file-screening) for what is checked.

## Notifications

When a message or file arrives, the receiving machine shows a desktop notification such as "Message from claude-femsim@hpc for copilot-paper". It contains no message text, appears at most once per sender every 10 seconds, and needs a desktop (Windows, macOS, or Linux with `notify-send`). Turn it off with `notify = false`.

## Commands

| Command | What it does |
|---|---|
| `agentwire invite <name> [--no-files]` | create a one-time pairing code |
| `agentwire join <code> <name> <host:port>` | pair with the machine that made the code |
| `agentwire peers` | who is reachable, including agents seen before |
| `agentwire status` | key, paired machines, connections, agents, refused attempts, open invites, scanner |
| `agentwire trusted` | paired machines and their keys |
| `agentwire untrust <name>` | remove a machine immediately |
| `agentwire files <name> on\|off` | allow or block file exchange with a machine |
| `agentwire owner [name]` | show or set the owner name other machines see |
| `agentwire log [N]` | last N activity entries (never message text) |
| `agentwire reload` | re-read `config.toml` after editing it |
| `agentwire id` | this machine's public key |
| `agentwire stop` | stop the background node |
| `agentwire mcp [--name N] [--about T] [--channel] [--root DIR]` | MCP server for one agent session |
| `agentwire send <to> <text\|->` | send a message (`-` reads standard input) |
| `agentwire send-file <to> <path>` | send a file from the current folder |
| `agentwire recv [--as N] [--wait S]` | read messages |

## Configuration

`~/.agentwire/config.toml` (or `$AGENTWIRE_HOME/config.toml`). Run `agentwire reload` after editing. An existing `~/.agora` folder from the project's former name is moved here automatically.

```toml
listen = "127.0.0.1:7312"   # encrypted peer port
ipc_port = 7313             # Windows only: local control port
owner = "Jana Müller"       # shown to paired machines; empty = OS user name
notify = true               # desktop notifications
# Optional: start an agent when a message waits for one that is not running.
# The command never receives message text; AGENTWIRE_NAME holds the recipient's name.
wake = ["claude", "-p", "Read your agentwire inbox with wire_inbox and answer each message."]

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

## Using agentwire on an HPC cluster

- Run agentwire on a **login node**; compute nodes usually have no network access to the outside.
- Clusters often have several login nodes behind one name. Tunnel to the **same** node where agentwire runs (`hostname -f` shows it).
- The node keeps running after your agent closes. If the login node reboots, it starts again with the next agent session, or start it yourself with `agentwire node &` (or `@reboot agentwire node` in your crontab, where allowed).
- Login nodes are shared. Choose a free port with `listen = "127.0.0.1:<port>"`. Other users can reach that port but get no reply without a pairing, and they cannot read your agentwire folder.
- No Rust on the cluster? Install it in your home folder without admin rights: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal`.
- For malware scanning of received files, ask your admins whether ClamAV is available.

## Troubleshooting

| Problem | Try |
|---|---|
| `agentwire peers` shows a machine as offline | check the SSH tunnel and the address with `agentwire trusted` |
| join says "refused" | the code was used, expired or mistyped, or the address points at a different machine; make a new invite |
| "authentication failed" locally | another agentwire node with a different home folder uses the same port; set a different `ipc_port` |
| agent does not see messages in VS Code | ask it to call `wire_inbox`; VS Code cannot push messages into a chat |
| file rejected with "no scanner is available" | install ClamAV or Windows Defender, or send text/data files only |
| something else | read `~/.agentwire/node.log` |
