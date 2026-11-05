# agentcourier user guide

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
- [Using agentcourier on an HPC cluster](#using-agentcourier-on-an-hpc-cluster)
- [Troubleshooting](#troubleshooting)

## How it fits together

```
 agent session ── MCP ──> agentcourier mcp ──┐
 agent session ── MCP ──> agentcourier mcp ──┤  local, authenticated
                                             ▼
                                   agentcourier node  ◄══ encrypted link ══►  agentcourier node (other machine)
```

Every agent session starts its own small `agentcourier mcp` process. On each machine they all share one background **node**, which starts automatically and keeps running when agents close. The node holds the machine's key, keeps the connections to paired machines, and keeps a queue per agent, so messages wait until the agent reads them. Undelivered messages and the agents seen on other machines are stored on disk, so they survive restarts. Sessions on the same machine can message each other too.

## Names and addresses

| Address | Means |
|---|---|
| `claude-femsim@hpc` | the agent `claude-femsim` on the machine you named `hpc` |
| `copilot-paper` | another session on this machine |
| `*@hpc` | the agent on `hpc`, if exactly one is running; with several, the message is refused and the sender gets their names, so it never lands in an unrelated project |

**Machines** are paired once, under a name you choose (`hpc`, `jana`). That name is the trusted part of an address: nobody else can change it. Pairings stay until you remove them; closing or restarting agents never requires pairing again. Each machine names the other independently, and you can change your name for a machine any time with `agentcourier rename hpc strand`; the pairing, queued messages and the memory of its agents stay.

**Agents** get a name from their tool and project folder: `copilot-paper`, `claude-femsim`, `codex-thesis`. The same tool in the same project gets the same name after a restart, so it receives the messages that arrived while it was closed. Two sessions in the same project at once get `-2`, `-3`, and so on. To choose a name:

- tell the agent, for example *"call yourself fe-runs"* (it uses `courier_set_name`);
- start it with `AGENTCOURIER_NAME=fe-runs`, or `agentcourier mcp --name fe-runs --about "FE mesh study"`.

**Finding an agent:** `courier_peers` (and `agentcourier peers`) lists, per machine, the agents online now and the agents **seen before** with when they were last seen. A message to an offline agent waits on its machine and is delivered when that agent starts again. So "ask my Claude on the cluster" works even if that Claude is closed right now.

**Self-descriptions** (an owner name such as "Jana Müller", and a short description per agent) are shown as `owner_says` and `about`. Other machines declare them about themselves, so they help recognise who is who but are not verified. Set your own owner name with `agentcourier owner Your Name`.

## Pairing machines

1. On the machine the other connects to: `agentcourier invite <name-for-the-other-machine>`. Add `--no-files` to block file exchange with it.
2. On the other machine: `agentcourier join <code> <name-for-the-first-machine> <host:port>`.

The code works once, for 10 minutes. Only paste it into a channel you trust. Afterwards, `agentcourier status` on both machines shows the other's key; compare the first few characters with `agentcourier id` on the other machine if you want to be certain.

Manual alternative: exchange keys from `agentcourier id` yourself and run `agentcourier trust <name> <key> [host:port]` on both sides.

## Connecting across networks

agentcourier needs a TCP connection from one machine to the other. Only the machine that connects needs an address.

- **SSH tunnel (recommended, no firewall changes):** `ssh -N -L 17312:127.0.0.1:7312 you@remote`, then use `127.0.0.1:17312` as the address.
- **Through a shared server (no admin rights on either machine):** when neither machine accepts incoming connections, for example two office PCs behind a firewall, both use a server they can both reach by SSH, such as a cluster login node. The inviting machine keeps `ssh -N -R 27312:127.0.0.1:7312 you@server` running; the other keeps `ssh -N -L 17312:127.0.0.1:27312 them@server` running and joins with `127.0.0.1:17312`. Both must use the same server host. Other users of the server can reach that port but get no reply without a pairing.
- **Direct:** set `listen = "0.0.0.0:7312"` on the reachable machine and open the port. Unpaired machines get no reply.

Connections come back automatically after network interruptions, with fresh keys each time. Messages sent while a machine is unreachable are queued and delivered later.

## Messages

Agents use `courier_send` with `to`, `text` and optionally `thread`. Replies go to the `from` address of the received message, with the same thread.

- **Claude Code with `--channel`:** messages appear in the running session as `← agentcourier: …`, including messages that arrived while it was closed. This only works if Claude Code is started with `claude --dangerously-load-development-channels server:agentcourier`; otherwise the session sees messages only when it calls `courier_inbox`.
- **All other clients:** the agent calls `courier_inbox`. With `wait_seconds` it waits for new messages. Just tell your agent "check agentcourier" or "wait for an answer from hpc".
- **VS Code:** run `agentcourier vscode` once and reload the window. The extension shows "agentcourier: new message from …" and an unread counter in the status bar for messages to that window; clicking asks Copilot to read them. It only sees sender and recipient names, never message text.

From scripts: `agentcourier send claude-femsim@hpc "text"` and `agentcourier recv --as NAME --wait 60`.

## Files

Agents use `courier_send_file` with `to`, `path` (relative to the project folder) and an optional `note`. From the shell: `agentcourier send-file <to> <path>`.

Received files land in `~/.agentcourier/files/<machine>/`, and the agent gets a message with the path. Files are only sent to machines that are online. See [Security](security.md#file-screening) for what is checked.

## Notifications

When a message or file arrives, the receiving machine shows a desktop notification such as "Message from claude-femsim@hpc for copilot-paper". It contains no message text, appears at most once per sender every 10 seconds, and needs a desktop (Windows, macOS, or Linux with `notify-send`). Turn it off with `notify = false`.

## Commands

| Command | What it does |
|---|---|
| `agentcourier invite <name> [--no-files]` | create a one-time pairing code |
| `agentcourier join <code> <name> <host:port>` | pair with the machine that made the code |
| `agentcourier peers` | who is reachable, including agents seen before |
| `agentcourier status` | key, paired machines, connections, agents, refused attempts, open invites, scanner |
| `agentcourier trusted` | paired machines and their keys |
| `agentcourier untrust <name>` | remove a machine immediately |
| `agentcourier rename <name> <new-name>` | change what this machine calls a paired machine; the pairing stays |
| `agentcourier files <name> on\|off` | allow or block file exchange with a machine |
| `agentcourier owner [name]` | show or set the owner name other machines see |
| `agentcourier log [N]` | last N activity entries (never message text) |
| `agentcourier reload` | re-read `config.toml` after editing it |
| `agentcourier id` | this machine's public key |
| `agentcourier stop` | stop the background node |
| `agentcourier mcp [--name N] [--about T] [--channel] [--root DIR]` | MCP server for one agent session; the project folder comes from the editor (or the start folder), `--root` overrides it |
| `agentcourier send <to> <text\|->` | send a message (`-` reads standard input) |
| `agentcourier send-file <to> <path>` | send a file from the current folder |
| `agentcourier recv [--as N] [--wait S]` | read messages |
| `agentcourier watch` | stream arrival notices (sender and recipient only, never text) |
| `agentcourier vscode` | install the VS Code extension that shows new messages |

## Configuration

`~/.agentcourier/config.toml` (or `$AGENTCOURIER_HOME/config.toml`). Run `agentcourier reload` after editing. A `~/.agentwire` or `~/.agora` folder from the project's former names is moved here automatically on first start, with keys and pairings; a still running old node is stopped first.

```toml
listen = "127.0.0.1:7312"   # encrypted peer port
ipc_port = 7313             # Windows only: local control port
owner = "Jana Müller"       # shown to paired machines; empty = OS user name
notify = true               # desktop notifications
# Optional: start an agent when a message waits for one that is not running.
# The command never receives message text; AGENTCOURIER_NAME holds the recipient's name.
wake = ["claude", "-p", "Read your agentcourier inbox with courier_inbox and answer each message."]

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

## Using agentcourier on an HPC cluster

- Run agentcourier on a **login node**; compute nodes usually have no network access to the outside.
- Clusters often have several login nodes behind one name. Tunnel to the **same** node where agentcourier runs (`hostname -f` shows it).
- The node keeps running after your agent closes. If the login node reboots, it starts again with the next agent session, or start it yourself with `agentcourier node &` (or `@reboot agentcourier node` in your crontab, where allowed).
- Login nodes are shared. Choose a free port with `listen = "127.0.0.1:<port>"`. Other users can reach that port but get no reply without a pairing, and they cannot read your agentcourier folder.
- Install without admin rights: `pip install --user agentcourier`. Or with Rust in your home folder: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal`.
- For malware scanning of received files, ask your admins whether ClamAV is available.

## Troubleshooting

| Problem | Try |
|---|---|
| `agentcourier peers` shows a machine as offline | check the SSH tunnel and the address with `agentcourier trusted` |
| join says "refused" | the code was used, expired or mistyped, or the address points at a different machine; make a new invite |
| "authentication failed" locally | another agentcourier node with a different home folder uses the same port; set a different `ipc_port` |
| agent does not see messages in VS Code | ask it to call `courier_inbox`; VS Code cannot push messages into a chat |
| file rejected with "no scanner is available" | install ClamAV or Windows Defender, or send text/data files only |
| something else | read `~/.agentcourier/node.log` |
