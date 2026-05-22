# policy

[![ci](https://github.com/pilot-protocol/policy/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/policy/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/policy/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/policy)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Policy plugin and expression language for the Pilot Protocol daemon.
The repo ships two packages:

- `policy/` — a `coreapi.Service` adapter that loads per-network policy
  files and emits decisions on the event bus.
- `policy/policylang/` — the expr-lang/expr–backed evaluator. Used by
  the plugin and by `cmd/pilotctl` for policy linting.

## Install

```go
import (
    "github.com/pilot-protocol/policy"
    "github.com/pilot-protocol/policy/policylang"
)
```

## Usage

```go
p, err := policylang.Parse(jsonBytes)
if err != nil {
    return err
}
_ = p

rt.Register(policy.NewService(policy.Config{
    PolicyDir: "~/.pilot/policy",
}))
```

## Layout

### Root package (`github.com/pilot-protocol/policy`)

| File | What it does |
|---|---|
| `runtime.go` | Loads/reloads policy files and watches the policy dir. |
| `runner.go` | Per-network expression runner; binds events to the evaluator. |
| `peer.go` | Per-peer rate/scope state used by directives. |
| `aliases.go` | Re-exports `policylang` types for source compatibility. |
| `service.go` | `*Service` — `coreapi.Service` adapter. Build tag `!no_policy`. |
| `service_disabled.go` | Stub when build tag `no_policy` is set. |

### Subpackage `policylang/`

| File | What it does |
|---|---|
| `policy.go` | `Policy` struct and JSON unmarshal. |
| `engine.go` | Compile and cache compiled programs; evaluate against env. |
| `env.go` | Event/peer-context binding for the expr-lang VM. |

## Build tags

| Tag | Effect |
|---|---|
| `no_policy` | Compiles a stub whose `Start` is a no-op. |

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
