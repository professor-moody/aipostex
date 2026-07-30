# sessions

Group an engagement's findings across many commands into one **engagement dossier** — without
per-command output flags.

## Synopsis

```bash
aipostex sessions start [name] [flags]
aipostex sessions stop [--id <id>]
aipostex sessions list [--all]
aipostex sessions show [--id <id>]
aipostex sessions prune
aipostex sessions notes --text "…" [--append]
aipostex sessions export --id <id> --findings-file <file> [--format …]
```

## Why

Running an assessment is many commands — `discover`, `scan`, and the exploit modules — and their loot
only chains if it lands in one place. Without a session you'd repeat `--output`/`--format` on every
command and stitch the results together afterward. A **session** does that for you: start one, run
your commands bare, and every finding auto-accumulates into a single dossier you read back with
[`report view`](report-view.md).

## The workflow

```bash
aipostex sessions start acme-mlops          # opens ~/engagements/acme-mlops and marks it active

aipostex ray --target http://10.0.0.20:8265 jobs           # bare — findings land in the engagement
aipostex mlflow --target http://10.0.0.30:5000 \
    --header "Authorization: Basic <looted>" runs
aipostex huggingface --target http://10.0.0.40:8180 \
    --header "Authorization: Bearer <looted>" generate --force-exploit

aipostex report view ~/engagements/acme-mlops --chains --commands   # find → loot → chain → reached
cat ~/engagements/acme-mlops/credentials.txt                        # the looted credentials

aipostex sessions stop
```

While a session is active, every **finding-emitting** command (discover, scan, and the exploit
modules) writes into the engagement dossier automatically. `report view`, `version`, and `sessions`
itself are unaffected. Your terminal still shows each command's summary and the ready-to-paste next
command — the accumulation happens in the background.

!!! note "Explicit flags always win"
    If you pass `-o`/`--format` on a command, that overrides the session for that command — it goes
    where you point it. The session default only applies when you *don't* specify an output.

## Commands

| Command | What it does |
|---|---|
| `start [name]` | Create an engagement dossier at `~/engagements/<name>` (or `--dir`) and mark it active. Name is a positional arg or `--name`. |
| `stop` | End the active session (or `--id`). Prints the finding count and the review command. |
| `list` | Show sessions with live findings/target counts derived from each dossier. Hides empty stopped ones (`--all` to show them). |
| `prune` | Delete stopped sessions that captured no findings (e.g. from automated runs). |
| `show` | Print a session's record as JSON (`--id`, else the active one). |
| `notes` | Set or append notes on a session (`--text`, `--append`). |
| `export` | Export findings from an engagement file filtered to one session id. |

## Flags

| Flag | Command | Description |
|---|---|---|
| `--name` | `start` | Session name (or pass it positionally). |
| `--dir` | `start` | Engagement dossier directory (default `~/engagements/<name>`). |
| `--force` | `start` | Stop any active session and start a new one. |
| `--id` | `stop`/`show`/`export`/`notes` | Target a specific session (default: the active one). |
| `--all` | `list` | Include stopped, empty sessions. |

## The engagement dossier

`~/engagements/<name>` is a normal [dossier directory](report-view.md) — greppable,
copy-ready files (`credentials.{txt,json,csv}`, `commands.sh`, `evidence/`, `findings.jsonl`,
`README.md`, and `manual/` when a k8s token is looted). Read it with `report view <dir> …`, or `cat` /
`jq` the files directly.

To score a session against a manifest (which wants one JSON engagement), merge its findings first:

```bash
aipostex engagement merge ~/engagements/<name>/findings.jsonl -o engagement.json
```

## See also

- [report view](report-view.md) — read chains/credentials/evidence out of the dossier
- [engagement merge](merge.md) — combine engagement files for scoring
- [output formats](../output/formats.md) — the `dossier` format the session accumulates into
