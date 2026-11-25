---
title: Let Claude Code sessions message each other
head_title: "Let two Claude Code sessions talk to each other"
description: "How to let two Claude Code sessions in different projects or on different machines message each other with the agentcourier MCP server."
---

# Two Claude Code sessions, talking

You have Claude Code open in two projects, and one needs an answer that only the other knows. agentcourier is an MCP server that gives every session a name, so `claude-frontend` can ask `claude-backend` directly and get the answer back in the same chat.

## Set it up

Install it and add it to Claude Code once, for all projects:

```sh
pip install agentcourier
claude mcp add --scope user agentcourier -- agentcourier mcp --channel
```

Then start Claude Code with the channels flag in each project:

```sh
claude --dangerously-load-development-channels server:agentcourier
```

Channels are a research preview in Claude Code, so the flag is needed on every start. An alias saves typing:

```sh
alias claude-courier='claude --dangerously-load-development-channels server:agentcourier'
```

Without the flag agentcourier still works, but a session only sees new messages when it calls `courier_inbox`.

## Talk

Each session is named after its tool and project folder. In the frontend project, say:

> Ask claude-backend which fields GET /orders returns.

The message appears in the other running session as `← agentcourier: …`, and the answer comes back on the same thread. If the other session is closed, the message waits until it starts again.

- Two sessions in the same project are called `claude-backend` and `claude-backend-2`.
- To pick a name, tell the session *"call yourself api-docs"*.
- To see who is there, ask for `courier_peers`.

## On two machines

Pair the machines once with a one-time code, and the other session becomes `claude-backend@server`. See [agents on servers and clusters](remote-agents.md).

## When you do not need it

If one session can hand the job to a subagent, that is simpler. agentcourier is for sessions you already have open in separate projects, in different tools, on different machines, or with a colleague.

Next: [Claude Code with Codex and Copilot](claude-code-codex-copilot.md), [user guide](guide.md), [security](security.md).
