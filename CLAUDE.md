# Security Operator PoC — Agent Guide

## Project Purpose

CTEM(Continuous Threat Exposure Management) 프레임워크에 매핑되는 Kubernetes Security Operator PoC.
단일 CRD(`SecurityAgent`)로 4개 보안 도구(Falco, Tetragon, OSquery, Trivy) + OTel 로그 파이프라인을 통합 관리.

## Architecture: Feature-as-Plugin

Datadog Operator의 Feature 시스템을 참고하되 PoC에 맞게 단순화.

**참조 코드**: `/Users/kikim/github/ctem/datadog-operator/`
- Feature interface: `internal/controller/datadogagent/feature/types.go`
- Feature registration: `internal/controller/datadogagent/feature/factory.go`
- Store pattern: `internal/controller/datadogagent/store/store.go`
- Reconcile loop: `internal/controller/datadogagent/controller_reconcile_v2.go`
- Override system: `internal/controller/datadogagent/override/`

## Directory Structure

```
security-operator/
├── cmd/main.go                                    # Entry point + Feature blank imports
├── api/v1alpha1/
│   └── securityagent_types.go                     # CRD types (array-based FeatureSpec)
├── internal/controller/
│   ├── reconciler.go                              # 7-Step Reconcile Loop
│   ├── feature/
│   │   ├── feature.go                             # Feature interface (4 methods)
│   │   ├── types.go                               # OTelReceiverConfig, FeatureCondition, FeatureID constants
│   │   ├── registry.go                            # Priority-based self-registration
│   │   ├── store.go                               # DesiredStateStore + SSA Apply
│   │   ├── otel_pipeline/feature.go               # Priority 10 — OTel Gateway + Node DS
│   │   ├── falco/feature.go                       # Priority 100 — Falco DS + CM + RBAC
│   │   ├── tetragon/feature.go                    # Priority 100 — Tetragon DS + TracingPolicy
│   │   ├── osquery/feature.go                     # Priority 100 — OSquery DS + Query Pack CM
│   │   └── trivy/feature.go                       # Priority 200 — CronJob (no OTel)
│   ├── override/override.go                       # 2-Level Override (common + per-tool)
│   └── otel/config_builder.go                     # OTel YAML synthesis
├── config/
│   ├── elasticsearch/                             # ES templates, ES/Kibana deployment
│   ├── falco/falco_rules.local.yaml               # Noise override
│   └── samples/                                   # Sample SecurityAgent CRDs
├── test/
│   ├── pods.yaml                                  # MITRE test pods
│   └── run-ctem-scenarios.sh                      # Test automation
└── Dockerfile, Makefile, go.mod
```

## Feature Interface (4 Methods)

```go
type Feature interface {
    ID() FeatureID
    Configure(raw []byte) error                                       // Parse RawExtension config
    Contribute(ctx context.Context, store *DesiredStateStore) error    // Add K8s resources to store
    OTelConfig() *OTelReceiverConfig                                  // filelog receiver config (nil for Trivy)
    Assess(ctx context.Context, c client.Client, ns string) FeatureCondition  // Health check
}
```

## Feature Priority

| Priority | Feature        | Role                    |
|----------|---------------|-------------------------|
| 10       | otel_pipeline | Collection infra (first) |
| 100      | falco         | eBPF syscall sensor     |
| 100      | tetragon      | eBPF kprobe sensor      |
| 100      | osquery       | SQL inventory collector |
| 200      | trivy         | CVE scanner (last)      |

## Self-Registration Pattern

```go
// In each feature's feature.go:
func init() {
    feature.Register(feature.FalcoFeatureID, 100, func() feature.Feature {
        return &falcoFeature{}
    })
}

// In cmd/main.go:
import _ "github.com/ctem/security-operator/internal/controller/feature/falco"
```

## CRD Design — Array-Based Features

```yaml
spec:
  features:
    - name: falco
      enabled: true
      config: { driver: "modern_ebpf" }   # runtime.RawExtension
```

Adding a new tool: implement Feature interface + 1 import line. No CRD schema or Reconciler change.

## Reconciler 7-Step Loop

1. **Feature Build** — BuildActiveFeatures (enabled only, priority-sorted)
2. **DesiredState Collection** — Each Feature.Contribute() adds resources to store
3. **OTel ConfigMap Synthesis** — Merge OTelConfig() from all features
4. **Override Application** — Common (nodeAgent) + per-tool overrides
5. **SSA Apply** — Server-Side Apply all resources with FieldOwner
6. **GC** — Delete resources from disabled features
7. **Status Update** — Assess() each feature + set ObservedGeneration

## Infinite Loop Prevention

- `GenerationChangedPredicate{}` on CRD watch (spec changes only)
- `ObservedGeneration` pattern in Status (skip reconcile if already processed)

## Data Flow

- Falco → file_output → OTel Node (filelog) → OTel Gateway → ES `security-events`
- Tetragon → stdout → OTel Node (filelog from /var/log/pods/) → Gateway → ES `security-events`
- OSquery → file → OTel Node (filelog) → Gateway → ES `security-inventory`
- Trivy → VulnerabilityReport CRD → CronJob → ES `security-vuln` (direct, no OTel)

## ES Indices (CTEM Mapping)

| Index               | CTEM Stage          | Source           |
|---------------------|---------------------|------------------|
| security-inventory  | Scope               | OSquery          |
| security-events     | Validation          | Falco + Tetragon |
| security-vuln       | Discovery/Priority  | Trivy            |

## Go Conventions

- Go 1.26, controller-runtime v0.20.x
- Error wrapping: `fmt.Errorf("action %s: %w", name, err)`
- Context propagation: always pass ctx from Reconcile
- SSA: `client.Patch(ctx, obj, client.Apply, client.FieldOwner("security-operator"), client.ForceOwnership)`
- OwnerReference for namespaced resources, labels for cluster-scoped
- Finalizer: `security.ctem.io/cleanup`

## Teammate Assignments

Each teammate should ONLY modify files in their assigned area:
- **scaffold**: `cmd/`, `api/`, `Makefile`, `Dockerfile`, `go.mod`, `config/crd/`, `config/rbac/`, `config/manager/`
- **core**: `internal/controller/reconciler.go`, `internal/controller/feature/feature.go`, `types.go`, `registry.go`, `store.go`, `internal/controller/override/`, `internal/controller/otel/`
- **features**: `internal/controller/feature/{otel_pipeline,falco,tetragon,osquery,trivy}/`, `cmd/main.go` (blank imports only)
- **infra**: `config/elasticsearch/`, `config/falco/`, `config/samples/`, `test/`
