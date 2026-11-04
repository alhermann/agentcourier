<p align="center">
  <img src="assets/icon.png" alt="agentwire" width="140">
</p>

<h1 align="center">agentwire</h1>

<p align="center">
  <b>Let your AI agents talk to each other, securely, across machines.</b><br>
  Claude Code, Codex, VS Code Copilot and any MCP client, on your laptop, your cluster or a colleague's machine.
</p>

<p align="center">
  <a href="https://github.com/alhermann/agentwire/actions/workflows/ci.yml"><img src="https://github.com/alhermann/agentwire/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/encryption-post--quantum%20hybrid-blue" alt="Post-quantum hybrid encryption">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License"></a>
</p>

---

## What it does

- **Messages and files between agents.** An agent on your laptop asks the agent on the cluster to check a simulation; the answer comes back into the same conversation. Files can be sent too.
- **Pair once, then it just works.** Machines are paired once. Agents can close and restart; they keep their names, and messages for an agent that is offline wait until it is back.
- **Works with running sessions.** In Claude Code, messages appear directly in the session. Other clients read them with one tool call, and you get a desktop notification.
- **Only machines you paired.** No accounts, no server, no cloud. Every connection is encrypted end to end, including protection against future quantum computers.
- **Guardrails built in.** Personal data and secrets are masked, files are screened for malware, and agents are told to treat incoming messages as untrusted.

To an agent, agentwire is a normal MCP server with the tools `wire_send`, `wire_send_file`, `wire_inbox`, `wire_peers` and `wire_set_name`.

## Get started

**1. Install** on each machine (one small binary, no admin rights needed):

```sh
cargo install --git https://github.com/alhermann/agentwire
```

**2. Pair two machines** once. On the machine the other one connects to (for example your cluster):

```sh
agentwire invite laptop
```

It prints a one-time code. On the other machine, paste it and say how to reach the first one (here through an SSH tunnel):

```sh
ssh -N -L 17312:127.0.0.1:7312 you@cluster-login-node
agentwire join agentwire-… hpc 127.0.0.1:17312
```

Tip: name machines after their owners (`agentwire invite jana`), so you can say "ask Jana's agent".

**3. Add agentwire to your agents:**

<details open>
<summary><b>Claude Code</b></summary>

```sh
claude mcp add --scope user agentwire -- agentwire mcp --channel
claude --dangerously-load-development-channels server:agentwire
```

`--channel` makes messages appear directly in the running session (Claude Code channels, research preview).
</details>

<details>
<summary><b>VS Code (Copilot)</b></summary>

Add to your user `mcp.json` (Command Palette: <i>MCP: Open User Configuration</i>):

```json
{
  "servers": {
    "agentwire": { "type": "stdio", "command": "agentwire", "args": ["mcp", "--root", "${workspaceFolder}"] }
  }
}
```
</details>

<details>
<summary><b>Codex</b></summary>

In `~/.codex/config.toml`:

```toml
[mcp_servers.agentwire]
command = "agentwire"
args = ["mcp"]
```
</details>

**4. Talk.** Tell your agent, for example: *"Ask my Claude on hpc whether the mesh study has finished, and send it `results/summary.csv`."*

Each session gets a clear name from its tool and project, such as `copilot-paper` or `claude-femsim`; its full address is `claude-femsim@hpc`. You can also tell an agent *"call yourself fe-runs"*. Agents look up who is online, and who was seen before, with `wire_peers`.

## Check what is going on

```sh
agentwire peers    # who is reachable, and agents seen before
agentwire status   # connections, paired machines, refused attempts
agentwire log      # recent activity (no message text)
agentwire untrust X  # cut off a machine immediately
```

## Learn more

- [User guide](docs/guide.md): names and addresses, files, notifications, commands, configuration, clusters
- [Security](docs/security.md): how pairing, encryption, masking and file screening work, and their limits

## License

Apache-2.0
