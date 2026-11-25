---
title: Message an agent on a server or HPC cluster
head_title: "Message a coding agent on a server or HPC cluster"
description: "Connect a coding agent on your laptop with one on a server, an HPC login node or a colleague's machine, over SSH or a relay you run yourself."
---

# Agents on servers and clusters

Your data and jobs are on a server, and you work on a laptop. Run agentcourier on both, pair them once, and the agent on the laptop can message the one on the server as `claude-backend@server`. You need no admin rights, no open firewall port and no account.

## Pair over SSH

Install on both machines:

```sh
pip install agentcourier
```

On the server:

```sh
agentcourier invite laptop
```

It prints a one-time code that is valid for 10 minutes. On the laptop, keep a tunnel open and join:

```sh
ssh -N -L 17312:127.0.0.1:7312 you@server
agentcourier join agentcourier-… server 127.0.0.1:17312
```

Pairing stays until you remove it with `agentcourier untrust server`. Now you can say:

> Ask my Claude on server whether the tests pass, and send it results/summary.csv.

## On an HPC cluster

Run it on a **login node**, since compute nodes usually have no network access to the outside. If several login nodes share one name, tunnel to the one where agentcourier runs (`hostname -f` shows it). `pip install --user agentcourier` needs no admin rights. HDF5, NetCDF and NumPy files can be sent; they are streamed, and a transfer continues after a dropped connection.

More in the [guide for clusters](guide.md#using-agentcourier-on-an-hpc-cluster).

## If neither machine can reach the other

Run a relay on a third machine that both can reach:

```sh
agentcourier relay --listen 0.0.0.0:7400
```

Both machines connect out to it, so they need no open ports. You run it yourself, it serves only machines you invite, and it forwards encrypted traffic it cannot read. The steps are in [the guide](guide.md#through-a-relay-you-run-yourself).

## With a colleague

Pair your machines the same way and name theirs after its owner, for example `agentcourier invite jana`. Then you can say "ask Jana's agent".

## What protects the connection

Only paired machines can connect; others get no reply at all. Every connection uses the Noise protocol with X25519 and ML-KEM-768, so reading it needs both to be broken. Details and limits are in [Security](security.md).

Next: [two Claude Code sessions](claude-code-sessions.md), [Codex and Copilot](claude-code-codex-copilot.md).
