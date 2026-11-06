<p align="center">
  <img src="pix.svg" alt="Pix, the Vulnetix mascot" width="110">
</p>

# vdb-cyclonedx

CycloneDX SBOM parser and schema validator for Go, supporting spec versions **1.2 through 1.7** plus
the official **2.0 development schema**.

Extracted (behavior-preserving) from `vdb-api-cyclonedx-uploads`'s internal parser so it can be
shared across Vulnetix services — currently `vdb-api-cyclonedx-uploads` (SBOM upload pipeline) and
`vdb-sca-monitor` (scheduled SCA re-evaluation).

```go
import "github.com/Vulnetix/vdb-cyclonedx"

bom, err := cyclonedx.ParseCDX(data)         // validates and parses 1.2–1.7 and 2.0-dev
g := cyclonedx.BuildGraph(bom)               // dependency graph
path := g.PathTo(rootRef, vulnerableRef)     // introduced-via chain
```

Consumed as a sibling module via `replace github.com/Vulnetix/vdb-cyclonedx => ../vdb-cyclonedx`
(the same pattern `vdb-api` uses for `ietf-crit-spec`), cloned at container-build time.

See [PLAN.md](./PLAN.md) for the full design and extraction plan.

## Generating an SBOM (`BuildSBOM`)

Other Go projects can generate the same Vulnetix CycloneDX document shape by
importing `github.com/Vulnetix/vdb-cyclonedx` directly:

```go
package main

import (
	"os"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
)

func main() {
	bom, err := cyclonedx.BuildSBOM(cyclonedx.SBOMInventory{
		Packages: []cyclonedx.SBOMPackage{{
			Name:       "example",
			Version:    "1.2.3",
			Ecosystem:  "golang",
			Scope:      "production",
			SourceFile: "go.mod",
			SourceType: "manifest",
			IsDirect:   true,
		}},
	}, cyclonedx.SBOMOptions{
		SpecVersion: "1.7",
		ToolName:    "my-builder",
		ToolVersion: "1.0.0",
	})
	if err != nil {
		panic(err)
	}
	_ = os.WriteFile("sbom.cdx.json", bom, 0o644)
}
```

`BuildSBOM` can also merge `AIDetections` and `CryptoDetections` so a single
CycloneDX file carries package SBOM, AIBOM and CBOM components, accepts a resolved
dependency graph via `SBOMInventory.Dependencies`, and takes an optional
`SBOMOptions.CanonicalSPDXID` hook so recognised licenses are emitted as
`license.id` instead of free text. The builder validates the output against the
bundled CycloneDX schema before returning JSON.

[`vulnetix cdx`](https://github.com/Vulnetix/cli) (alias `vulnetix sbom`) is the CLI front end for this: it discovers packages from
manifests, installed package trees, container package databases, Dockerfiles,
CI/CD pipeline files, shell scripts and the metadata compiled into Go, Rust and
JVM artefacts, then writes one validated CycloneDX file offline.

## Status

Scaffold + plan. Implementation extracts `internal/processor/{cyclonedx,parity,purl}.go` from
`vdb-api-cyclonedx-uploads`, with embedded official JSON schemas for validation.
<!-- ci-touch: 2026-08-24T13:13:32Z -->

## Conformance

The OWASP TEA conformance run captures CycloneDX responses to disk. Re-validate those captures
against the bundled schemas with `TestRealCapturedDocuments`, which skips unless
`VEX_CAPTURE_DIR` points at a run's recordings:

    VEX_CAPTURE_DIR=~/GitHub/owasp-tea-conformance/reports/vulnetix/responses/cyclonedx go test ./... -run TestRealCapturedDocuments -v

The conformance run itself is the `publish-tea` job in `.github/workflows/vulnetix.yml` (triggered
on push, release, or manually via `workflow_dispatch`); it delegates to
`Vulnetix/cli/.github/workflows/tea-release.yml`.

## VEX dispositions and suppression rules (`vexrules/`)

`vexrules` reads OpenVEX, CycloneDX VEX and CSAF VEX (`Detect`, `Parse`) and keeps each
statement's raw fields, so `Classify` can decide from state plus justification, responses,
action text, CSAF flags and remediations. Only two dispositions become suppression rules:

| Disposition | Examples | Rule |
|---|---|---|
| `false_positive` | CycloneDX `false_positive`; OpenVEX `not_affected` + `component_not_present`; CSAF `known_not_affected` + `component_not_present` | active |
| `wont_fix` | CycloneDX `exploitable` + `will_not_fix`, or `can_not_fix` alone; CSAF `known_affected` + `no_fix_planned` with no `vendor_fix` | active |
| `wont_fix` read from text | OpenVEX `affected` whose `action_statement` says it will not be fixed | inactive, pending review |
| `conflict` | a won't fix response together with `update`, `rollback` or a `vendor_fix` | none, flagged |
| `mitigated` | only a Vulnetix marker for a mitigated rule | links to that rule |
| `triage_only`, `undecided` | every other state | none |

A `vulnetix:suppression/{type,uuid,source}` marker (a CycloneDX property, an OpenVEX
`status_notes` line or a CSAF note) links a statement back to the rule that minted it, so
re-ingesting Vulnetix VEX does not create a second rule. The package also holds the rule
matcher (`RuleMatches`) and the identity ladder (`NewIdentity`) the services share.

The classifier's cases are in `vexrules/testdata/classify-golden.json`. The website keeps a
byte copy at `src/shared/vex-disposition-cases.json` for its TypeScript port; change both
together. Regenerate the golden with `VEXRULES_UPDATE=1 go test ./vexrules/`.

## Mutation testing

Mutation testing scores how well the test suite kills small semantic changes (mutants) of a source file. The tool is the [`avito-tech/go-mutesting`](https://github.com/avito-tech/go-mutesting) fork of `go-mutesting`, pinned to `v0.0.0-20261002081621-9ce5f731e321`. It is dev-only: this module does not depend on it, because its `go.mod` requires Go 1.27. Build it in `bin/` (gitignored) from a source copy whose `go` directive is lowered to the local toolchain:

```bash
mkdir -p bin/mutesting-src
cd bin/mutesting-src
GOTOOLCHAIN=auto go mod download github.com/avito-tech/go-mutesting@v0.0.0-20261002081621-9ce5f731e321
cp -r "$(go env GOMODCACHE)/github.com/avito-tech/go-mutesting@v0.0.0-20261002081621-9ce5f731e321/." .
chmod -R u+w . # the module cache extracts read-only files
go mod edit -go=1.26
GOTOOLCHAIN=local go mod tidy
GOTOOLCHAIN=local go build -o ../go-mutesting ./cmd/go-mutesting
```

Score a root-package file with (run from the repository root):

```bash
./bin/go-mutesting purl.go
```

The tool applies each mutant in turn and runs the package tests against it, then prints a summary line of the form `The mutation score is 0.571429 (16 passed, 12 failed, 2 duplicated, 0 skipped, total is 28)`. A `passed` mutant is one the tests killed; a `failed` mutant survives the tests and marks behaviour the suite does not cover. The score tracks the test suite, so expect it to move as tests change.
