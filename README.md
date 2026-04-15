# public-file-exposure-guard

A lightweight TypeScript workflow tool that scans app and storage surfaces for unintentionally public files and URLs before they get indexed or shared.

## Install

```bash
bun install
```

Create a config file or pass targets programmatically once implementation begins.

## Usage

Run in development:

```bash
bun run dev
```

Run once:

```bash
bun run start
```

Type-check the project:

```bash
bun run typecheck
```

### Intended scope

This scaffold is aimed at building a small-team external exposure monitor that can:

- inspect uploaded file URLs and document endpoints
- probe bucket/object URLs for anonymous access
- detect indexability signals such as robots and cache headers
- flag metadata leakage in common delivery workflows
- emit findings for CI, cron jobs, or internal workflows

## Contributing

Contributions are welcome.

Suggested flow:

1. Fork the repository
2. Create a feature branch
3. Add or update tests
4. Open a pull request with a clear description of the workflow or exposure case addressed

This repository is intentionally scaffolded, not production-complete. Prioritize small, reviewable changes around scanners, probes, policies, and reporting.