# Security Policy

## Scope

This policy covers vulnerabilities in **aipostex itself** — the CLI, the template engine, or the
build/release pipeline. aipostex is an offensive security tool; findings it *reports* about target
systems are its intended function, not vulnerabilities in aipostex.

## Reporting a vulnerability

Please report security issues in the tool privately rather than opening a public issue:

- Use [GitHub private vulnerability reporting](https://github.com/professor-moody/aipostex/security/advisories/new), or
- Open a minimal public issue asking for a private contact if advisories are unavailable.

Include the version (`aipostex --version`), affected component, and a reproduction. We aim to
acknowledge reports within a few days.

## Supported versions

Fixes land on the latest release. Please reproduce against the most recent tag before reporting.

## Responsible use

aipostex is for authorized testing only. Running it against systems you do not own or have explicit
permission to test may be illegal. The maintainers are not responsible for misuse.
