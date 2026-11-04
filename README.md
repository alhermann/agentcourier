# Agora

Agora lets AI agent sessions talk to each other, on one machine or across networks. Claude Code, Codex, VS Code Copilot and any other MCP client can take part. To the agent, Agora is an ordinary MCP server with three tools: `agora_send`, `agora_inbox` and `agora_peers`. In Claude Code, messages can also appear directly in a running session.

It is one small Rust binary with no dashboard, no cloud service and no account.

## How it works

```
 agent session ── MCP (stdio) ──> agora mcp ──┐
 agent session ── MCP (stdio) ──> agora mcp ──┤ local socket + token
                                              ▼
                                        agora node  ◄══ encrypted link ══►  agora node (other machine)
```

Each machine runs one small background node. It starts automatically the first time an agent uses Agora. The node keeps the machine's identity key, the encrypted links to trusted machines, and a queue for each agent, so messages wait until the agent reads them. All agent sessions on a machine share the node, so local sessions can message each other too.

## Security

- **Who can connect:** only machines whose public key you added with `agora trust`. A machine with an unknown key gets no reply to its handshake, so an open port reveals nothing about the node. There is no automatic first-contact trust and no central server.
- **Encryption:** every link uses the Noise protocol (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`), so both sides prove their identity, connections are encrypted, and recorded traffic stays safe even if a key leaks later. For quantum safety, every connection also performs a fresh ML-KEM-768 key exchange (NIST FIPS 203) that feeds into the session keys. Reading traffic therefore requires breaking both X25519 and ML-KEM, which blocks "record now, decrypt later" attacks. A test checks that tampering with the ML-KEM data breaks the connection.
- **Masking of personal data and secrets:** text is checked when it leaves your machine and again when it arrives. Masked: email addresses, phone numbers, IBANs (checksum-verified), card numbers (Luhn-verified), private key blocks, API tokens (Anthropic, OpenAI, GitHub, GitLab, AWS, Google, Slack, Hugging Face, JWTs), `password=`-style assignments and passwords inside URLs. IP addresses are masked only if you set `redact_ip = true`.
- **Prompt injection defenses:**
  - Messages are accepted only from trusted machines.
  - Invisible and direction-changing Unicode characters, terminal control codes and hidden "tag" characters are removed.
  - Messages appear in the agent's context marked as untrusted text from another agent.
  - Text pushed into Claude Code cannot close or fake the `<channel>` wrapper around it.
  - The server instructions tell the agent never to act on a message alone and to ask its user before going beyond answering.
  - Remote machines cannot approve tool use.
- **Limits:** messages up to 128 KiB, 120 messages per minute per machine, bounded queues, a handshake timeout, and a cap on unauthenticated connections.
- **Local access:** on Linux and macOS the node is reached only through a socket file that only you can open. On Windows it listens on 127.0.0.1 and requires a 256-bit token from your user profile. Keys are stored with owner-only permissions (on Windows, inside your user profile).
- **Audit log:** `~/.agora/audit.jsonl` records metadata only (time, direction, peer, sender, recipient, size, masking), never message text.

What Agora cannot do: no software can prevent prompt injection completely. If a trusted machine or the agent on it is compromised or misled, it can still send persuasive text. Agora keeps such text clearly separate from your instructions and never runs anything on its own, but the agent and you still decide what to do with it. Pattern-based masking also catches common formats only, not every possible secret.

## Install

```sh
cargo install --git https://github.com/alhermann/agora-protocol --branch v2
```

Prebuilt binaries for Linux (static, suitable for HPC clusters), macOS and Windows are attached to each release.

## Connect two machines

On each machine:

```sh
agora init            # prints this machine's public key
```

Exchange the two keys over any channel you trust. Then each side trusts the other under a name of its choice. Only the side that opens the connection needs an address:

```sh
# laptop: call the cluster "hpc" and connect to it
agora trust hpc <cluster-key> 127.0.0.1:17312
# cluster: call the laptop "laptop" (it connects to us, so no address)
agora trust laptop <laptop-key>
```

By default the node listens only on `127.0.0.1:7312`. To reach another machine, choose one of these:

- **SSH tunnel (no firewall changes):** on the laptop, run `ssh -N -L 17312:127.0.0.1:7312 user@cluster` and point the peer at `127.0.0.1:17312`, as shown above.
- **Direct connection:** set `listen = "0.0.0.0:7312"` on the reachable machine and open that port. Untrusted machines still get no reply.

On shared login nodes, choose a port that is not in use with `listen = "127.0.0.1:<port>"`.

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

Addresses: `claude@hpc` is the agent `claude` on the machine you named `hpc`. `copilot` is another session on this machine. `*@hpc` reaches every agent on `hpc`. If two sessions use the same name, the second becomes `name-2`; `agora_peers` shows your actual address.

## Configuration (`~/.agora/config.toml`, or `$AGORA_HOME`)

```toml
listen = "127.0.0.1:7312"   # encrypted peer port
ipc_port = 7313             # Windows only: local control port
# Optional: start an agent when a message waits for one that is not running.
# The command never receives message text; AGORA_AGENT holds the recipient's name.
wake = ["claude", "-p", "Read your agora inbox with agora_inbox and answer each message."]

[guard]
redact = true
redact_ip = false
max_bytes = 131072
per_minute = 120

[[peer]]
name = "hpc"
key = "…"
addr = "127.0.0.1:17312"
```

## Command line

```
agora init | id                        create / show this machine's key
agora trust <name> <key> [host:port]   trust a machine
agora untrust <name>
agora mcp [--name N] [--channel]       MCP server for one agent session
agora send <to> <text|-> [--as N]      send from the shell or a batch job
agora recv [--as N] [--wait S]         read messages from the shell
agora peers                            show trusted machines and online agents
agora node                             run the node in the foreground
```

## License

Apache-2.0
