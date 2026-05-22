# policy

Pilot Protocol policy plugin + the policy expression language. Two
packages in one repo:

- `policy/` — `coreapi.Service` adapter that loads per-network policy
  config and emits decisions on the event bus.
- `policy/policylang/` — the expr-lang/expr–backed evaluator. Used by
  the plugin and by `cmd/pilotctl` for policy linting.

## Layout

### Root package (`github.com/pilot-protocol/policy`)

| File | What it does |
|---|---|
| `runtime.go` | Loads/reloads policy files; watches the policy dir. |
| `runner.go` | Per-network expression runner; binds events to evaluator. |
| `peer.go` | Per-peer rate/scope state used by directives. |
| `aliases.go` | Re-exports policylang types for source compatibility. |
| `service.go` | `*Service` — `coreapi.Service` adapter. Build tag `!no_policy`. |
| `service_disabled.go` | Stub when build tag `no_policy` is set. |

### Subpackage `policylang/`

| File | What it does |
|---|---|
| `policy.go` | `Policy` struct + JSON unmarshal. |
| `engine.go` | Compile + cache compiled programs; evaluate against env. |
| `env.go` | Event/peer-context binding for the expr-lang VM. |

## Import paths

```go
import (
    "github.com/pilot-protocol/policy"
    "github.com/pilot-protocol/policy/policylang"
)

p, err := policylang.Parse(jsonBytes)

rt.Register(policy.NewService(policy.Config{
    PolicyDir: "~/.pilot/policy",
}))
```

## Disabling

Pass `-tags no_policy` to compile a stub whose `Start` is a no-op.

## Releasing

Tag a SemVer version (e.g. `v0.1.0`); web4 pulls it in via
`require github.com/pilot-protocol/policy v0.1.0`. During
co-development consumers use `replace ../policy`.
