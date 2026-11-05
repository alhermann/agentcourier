<p align="center">
  <img src="https://raw.githubusercontent.com/alhermann/agentcourier/main/assets/icon.png" alt="agentcourier" width="140">
</p>

<h1 align="center">agentcourier</h1>

<p align="center">
  <b>Let your AI agents talk to each other, securely, across machines.</b><br>
  An MCP server for agent-to-agent messages and files between Claude Code, Codex, GitHub Copilot and any other MCP client,<br>
  on your laptop, an HPC cluster or a colleague's machine. End-to-end encrypted, no server, no cloud.
</p>

<!-- mcp-name: io.github.alhermann/agentcourier -->

<p align="center">
  <a href="https://github.com/alhermann/agentcourier/actions/workflows/ci.yml"><img src="https://github.com/alhermann/agentcourier/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agentcourier/"><img src="https://img.shields.io/pypi/v/agentcourier" alt="PyPI"></a>
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

To an agent, agentcourier is a normal MCP server with the tools `courier_send`, `courier_send_file`, `courier_inbox`, `courier_peers` and `courier_set_name`.

## Get started

**1. Install** on each machine (one small program, no admin rights needed):

```sh
pip install agentcourier
```

Or, with Rust: `cargo install --git https://github.com/alhermann/agentcourier`.

**2. Pair two machines** once. On the machine the other one connects to (for example your cluster):

```sh
agentcourier invite laptop
```

It prints a one-time code. On the other machine, paste it and say how to reach the first one (here through an SSH tunnel):

```sh
ssh -N -L 17312:127.0.0.1:7312 you@cluster-login-node
agentcourier join agentcourier-… hpc 127.0.0.1:17312
```

Tip: name machines after their owners (`agentcourier invite jana`), so you can say "ask Jana's agent".

**3. Add agentcourier to your agents:**

<details open>
<summary><b>Claude Code</b></summary>

```sh
claude mcp add --scope user agentcourier -- agentcourier mcp --channel
claude --dangerously-load-development-channels server:agentcourier
```

`--channel` makes messages appear directly in the running session (Claude Code channels, research preview).

**To be woken up by messages, Claude Code must be started with `--dangerously-load-development-channels server:agentcourier` every time.** Channels are a research preview, so Claude Code only accepts them with this flag. Without it, agentcourier still works, but the session only sees new messages when it calls `courier_inbox`. Tip: add an alias, e.g. `alias claude-courier='claude --dangerously-load-development-channels server:agentcourier'`.
</details>

<details>
<summary><b>VS Code (Copilot)</b></summary>

Add to your user `mcp.json` (Command Palette: <i>MCP: Open User Configuration</i>):

```json
{
  "servers": {
    "agentcourier": { "type": "stdio", "command": "agentcourier", "args": ["mcp"] }
  }
}
```

Each window is named after the folder it has open.

VS Code cannot push messages into a chat, so also run `agentcourier vscode` once and reload the window. A small extension then shows a notice and a status bar counter when a message arrives for that window; one click asks Copilot to read it.
</details>

<details>
<summary><b>Codex</b></summary>

In `~/.codex/config.toml`:

```toml
[mcp_servers.agentcourier]
command = "agentcourier"
args = ["mcp"]
```
</details>

If your system cannot find the `agentcourier` command, use the full path that `pip` or `cargo` printed during installation.

**4. Talk.** Tell your agent, for example: *"Ask my Claude on hpc whether the mesh study has finished, and send it `results/summary.csv`."*

Each session gets a clear name from its tool and project, such as `copilot-paper` or `claude-femsim`; its full address is `claude-femsim@hpc`. You can also tell an agent *"call yourself fe-runs"*. Agents look up who is online, and who was seen before, with `courier_peers`.

## Check what is going on

```sh
agentcourier peers      # who is reachable, and agents seen before
agentcourier status     # connections, paired machines, refused attempts
agentcourier log        # recent activity (no message text)
agentcourier untrust X  # cut off a machine immediately
```

## Common questions

### How do I let two Claude Code sessions talk to each other?

Add agentcourier to Claude Code (step 3). Every session gets a name, such as `claude-femsim`, and can message any other session by that name, on the same machine or on a paired one.

### Can Claude Code, Codex and GitHub Copilot talk to each other?

Yes. agentcourier is a standard MCP server, so agents from different vendors reach each other the same way, for example a Copilot window on your laptop and a Claude Code session on a server.

### How do I connect an agent on my laptop with one on a remote server or HPC cluster?

Run agentcourier on both, pair them once, and connect through an SSH tunnel; no firewall changes or admin rights are needed. See [the guide](docs/guide.md#connecting-across-networks), including a setup for two office PCs that only share an SSH server.

### Can my agent talk to a colleague's agent?

Yes, once your two machines are paired. Each of you names the other's machine, so you can say "ask Jana's agent". Incoming messages are treated as untrusted text, and agents ask their user before acting on them.

### Is it secure, and does it need a server or an account?

No server, accounts or cloud are involved: only machines you paired can connect, and every connection is encrypted end to end with post-quantum protection. Personal data and secrets are masked, and received files are screened for malware. Details and limits are in [Security](docs/security.md).

### How is this different from A2A or multi-agent frameworks?

Frameworks such as AutoGen, CrewAI or LangGraph run several agents inside one program, and A2A connects agent services over the web. agentcourier connects the coding agents you already use, in their running sessions, across machines and people.

## Coming from agentwire?

agentcourier was called agentwire before. On first start it moves your key, pairings and waiting messages over by itself, and it still talks to machines that run agentwire. Rename the MCP entries above from `agentwire` to `agentcourier`, run `agentcourier vscode` again, and start Claude Code with `server:agentcourier`.

## Learn more

- [User guide](docs/guide.md): names and addresses, files, notifications, commands, configuration, clusters
- [Security](docs/security.md): how pairing, encryption, masking and file screening work, and their limits

## License

Apache-2.0
