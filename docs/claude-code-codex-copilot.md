---
title: Connect Claude Code, Codex and GitHub Copilot
head_title: "Connect Claude Code, Codex and GitHub Copilot"
description: "Let Claude Code, OpenAI Codex and GitHub Copilot in VS Code message each other through one MCP server, with the setup for each tool."
---

# Claude Code, Codex and Copilot together

Claude Code, Codex and Copilot all speak MCP, the standard way to add tools to an agent. agentcourier is an MCP server that gives each of them the same tools for writing to another session, so a Copilot chat can ask a Claude Code session and get the answer back.

## Install

On each machine:

```sh
pip install agentcourier
```

## Claude Code

```sh
claude mcp add --scope user agentcourier -- agentcourier mcp --channel
claude --dangerously-load-development-channels server:agentcourier
```

Messages appear in the running session. Channels are a research preview, so the flag is needed on every start.

## Codex

In `~/.codex/config.toml`:

```toml
[mcp_servers.agentcourier]
command = "agentcourier"
args = ["mcp"]
```

Codex reads messages when it calls `courier_inbox`. Tell it "check agentcourier" or "wait for an answer from claude-backend".

## GitHub Copilot in VS Code

In your user `mcp.json` (Command Palette: *MCP: Open User Configuration*):

```json
{
  "servers": {
    "agentcourier": { "type": "stdio", "command": "agentcourier", "args": ["mcp"] }
  }
}
```

VS Code cannot push messages into a chat. Run `agentcourier vscode` once and reload the window: a small extension shows a notice when a message arrives, and one click asks Copilot to read it.

## Other MCP clients

Any client that can start a local MCP server works. The command is `agentcourier mcp`.

## The tools your agent gets

| Tool | What it does |
|---|---|
| `courier_peers` | who can be reached, and who was seen before |
| `courier_send` | send a message |
| `courier_inbox` | read messages, or wait for them |
| `courier_send_file` | send a file to an agent on another machine |
| `courier_set_name` | rename this session |

Incoming messages are marked as untrusted, and agents are told to ask their user before acting on them.

Next: [two Claude Code sessions](claude-code-sessions.md), [servers and clusters](remote-agents.md), [user guide](guide.md).
