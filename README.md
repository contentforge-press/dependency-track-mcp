# Dependency-Track MCP Server

A Model Context Protocol server for [OWASP Dependency-Track](https://dependencytrack.org/),
designed to answer the questions security teams actually ask — without forcing an
LLM to walk thousands of REST pages.

## Why not a 1:1 REST wrapper?

A thin proxy of the Dependency-Track REST API yields poor results: questions like
*"show me all critical vulnerabilities across the portfolio"* require iterating
over many projects and, for large portfolios, thousands of paginated calls.

This server takes the approach suggested in the upstream discussion
(DependencyTrack/dependency-track#5791):

- **Efficient aggregation in the server**, not the LLM. Project findings use
  Dependency-Track's already-aggregated per-project findings endpoint, with a
  bounded page cap for project listing to prevent runaway scans.
- **A small set of high-level tools** that map directly to real questions.
- **Open-finding semantics**: suppressed findings and findings already analyzed
  as `RESOLVED`, `FALSE_POSITIVE`, or `NOT_AFFECTED` are excluded from risk totals.

## Tools

### `portfolio_risk_overview`

Portfolio-wide rollup of open vulnerabilities across projects, sorted by
critical/high exposure.

Arguments:

| Name | Default | Description |
|---|---|---|
| `minSeverity` | `HIGH` | Only count open findings at/above `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`. |
| `activeOnly` | `true` | Skip inactive projects. |
| `limit` | _none_ | Optional cap on projects scanned. |

Returns the number of projects scanned, portfolio-level severity buckets, and the
highest-risk projects.

## Configuration

The server reads a Dependency-Track **team API key** and base URL from the
environment. Scope the key in Dependency-Track to only the permissions the agent
needs.

```json
{
  "mcpServers": {
    "dependency-track": {
      "command": "npx",
      "args": ["-y", "dependency-track-mcp-server"],
      "env": {
        "DEPENDENCY_TRACK_URL": "https://dependencytrack.example.com",
        "DEPENDENCY_TRACK_API_KEY": "your-scoped-team-api-key"
      }
    }
  }
}
```

## Status

Early v0.1 focused on the portfolio risk rollup. Planned: project/component drill
down, remediation status by vulnerability, and license-risk aggregation.

## License

Apache-2.0.
