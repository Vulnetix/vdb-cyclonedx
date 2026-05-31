# vdb-cyclonedx

Pure-stdlib CycloneDX SBOM parser for Go, supporting spec versions **1.2 through 1.7**.

Extracted (behavior-preserving) from `vdb-api-cyclonedx-uploads`'s internal parser so it can be
shared across Vulnetix services — currently `vdb-api-cyclonedx-uploads` (SBOM upload pipeline) and
`vdb-sca-monitor` (scheduled SCA re-evaluation). No external dependencies (`encoding/json` only).

```go
import "github.com/Vulnetix/vdb-cyclonedx"

bom, err := cyclonedx.ParseCDX(data)         // parses 1.2–1.7
g := cyclonedx.BuildGraph(bom)               // dependency graph
path := g.PathTo(rootRef, vulnerableRef)     // introduced-via chain
```

Consumed as a sibling module via `replace github.com/Vulnetix/vdb-cyclonedx => ../vdb-cyclonedx`
(the same pattern `vdb-api` uses for `ietf-crit-spec`), cloned at container-build time.

See [PLAN.md](./PLAN.md) for the full design and extraction plan.

## Status

Scaffold + plan. Implementation extracts `internal/processor/{cyclonedx,parity,purl}.go` from
`vdb-api-cyclonedx-uploads`.
