# Testing Against Real Products (Sandbox)

The fastest way to verify an `aipostex` module is **honest** is to point it at the **real product**,
not a mock — tool-shaped mocks hide tool bugs. The companion lab repo provides a **single-service
sandbox** for exactly this: spin up one real AI-infra product under Docker on your workstation, run
the matching module against it, confirm the output is honest, tear it down.

```
up <svc>  →  aipostex <module> --target <real product>  →  confirm honest  →  down
```

## Use it

In the [aipostex-lab](https://github.com/professor-moody/aipostex-lab) repo:

```bash
( cd /path/to/aipostex && make build )
export AIPOSTEX=/path/to/aipostex/bin/aipostex

cd /path/to/aipostex-lab/sandbox
./sandbox up wandb        # start real wandb/local
./sandbox prove wandb     # run `aipostex wandb` against it
./sandbox down wandb
```

Services today: `chromadb`, `wandb`, `qdrant`, `mlflow`, `ollama`, and `a2a` (a real a2a-sdk agent in
a deliberately-weak `vuln` variant + a hardened `secure` peer, so the A2A probe verbs can be checked
in **both** directions). Full guide: the lab's
[Single-Service Sandbox](https://professor-moody.github.io/aipostex-lab/sandbox/).

## Why it matters

This loop is the **realism principle** in practice, and it has caught real tool bugs that the lab's
tool-shaped mocks masked — e.g. the `wandb` module scraping a version out of a `/healthz` liveness
token, and the five A2A probe verbs crashing against an auth-enforcing agent instead of honestly
reporting "not weak." When you add or change a module, prove it against the real product in the
sandbox before relying on a mock.
