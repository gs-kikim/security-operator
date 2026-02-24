# Security Operator PoC 통합 실행 계획서 v4.0

> **도구**: Falco · Tetragon · OSquery · Trivy (4개, Tracee 제외)  
> **아키텍처**: Feature-as-Plugin (Datadog Operator 패턴 — 배열 기반 CRD + 자기등록)  
> **적재**: Elasticsearch 3개 인덱스 (CTEM 용도별) + Kibana  
> **프레임워크**: CTEM Scope / Discovery / Priority / Validation 매핑 검증  
> **비목표**: Tracee · 멀티클러스터 · 인라인 차단 · Kafka · 완벽한 OCSF 정규화

---

# 1. PoC 목표 & 성공 기준

## 1.1 기능 목표

| # | 성공 기준 | 검증 방법 |
|---|----------|----------|
| G1 | `SecurityAgent` CRD 1개 적용으로 4개 센서 + OTel 파이프라인 자동 배치 | `kubectl apply` 후 DS/Deploy 자동 생성 확인 |
| G2 | Feature 토글(`enabled: false`)로 개별 도구 DaemonSet 생성/삭제 | CRD 수정 → DS 사라짐/생성 확인 |
| G3 | Override 적용으로 특정 도구의 리소스/tolerations 변경 | CRD override 수정 → DS spec 변경 확인 |
| G4 | 4개 도구의 이벤트가 ES에 CTEM 용도별 인덱스로 적재 | Kibana에서 3개 인덱스 조회 |
| G5 | Kibana 대시보드 3개 동작 | 스크린샷 |
| G6 | MITRE ATT&CK 테스트 시나리오 5개 실행 시 탐지 | ES 쿼리로 이벤트 존재 확인 |
| G7 | CTEM Scope/Discovery/Priority/Validation 매핑 검증 체크리스트 통과 | 검증 항목 Pass/Fail |

## 1.2 비목표 (명시적 제외)

- Tracee (Falco와 탐지 영역 겹침 → PoC 복잡도 감소)
- 인라인 차단/Enforcement (Tetragon enforcement, Kyverno)
- Kafka 버퍼링, OCSF Normalizer, Correlation Engine → Phase B
- 멀티클러스터, HA, 성능 튜닝

---

# 2. CRD 설계 — 배열 기반 Feature 선언

새 보안 도구 추가 시 CRD 스키마 변경 없이 `config` 필드만 확장하면 되는 구조.

```yaml
apiVersion: security.example.io/v1alpha1
kind: SecurityAgent
metadata:
  name: poc-security
  namespace: security-system
spec:
  global:
    clusterName: poc-cluster

  features:
    - name: otel_pipeline
      enabled: true
      config:
        mode: "node-to-gateway-to-es"
        nodeLogBasePath: "/var/log/security"
        gatewayReplicas: 1

    - name: falco
      enabled: true
      config:
        driver: "modern_ebpf"
        jsonOutput: true

    - name: tetragon
      enabled: true
      config:
        exportMode: "stdout"
        policies: ["process-exec", "container-escape-monitor"]

    - name: osquery
      enabled: true
      config:
        intervalSeconds: 60
        packs: ["scope-minimal"]

    - name: trivy
      enabled: true
      config:
        scanSchedule: "@every 6h"
        severityThreshold: "HIGH"

  output:
    elasticsearch:
      endpoints: ["https://security-es-es-http.elastic-system:9200"]
      authSecretRef: { name: "es-credentials" }
      caSecretRef: { name: "es-ca" }
      indices:
        inventory: "security-inventory"       # CTEM Scope
        events: "security-events"             # CTEM Validation
        vulnerabilities: "security-vuln"      # CTEM Discovery/Priority

  override:
    nodeAgent:
      tolerations:
        - operator: Exists
    falco:
      resources:
        limits:
          memory: "2Gi"

  tests:
    enabled: true
    scenarios:
      - "scope-inventory"
      - "validate-shell"
      - "validate-k8s-api"
      - "validate-container-escape"
      - "validate-cron-persistence"
```

## Go 타입 정의 (배열 + RawExtension)

```go
// api/v1alpha1/securityagent_types.go

type SecurityAgentSpec struct {
    Global   GlobalSpec     `json:"global,omitempty"`
    Features []FeatureSpec  `json:"features"`
    Output   OutputSpec     `json:"output"`
    Override *OverrideSpec  `json:"override,omitempty"`
    Tests    *TestSpec      `json:"tests,omitempty"`
}

// FeatureSpec — 배열 기반으로 CRD 스키마 변경 없이 새 도구 추가 가능
type FeatureSpec struct {
    Name    string                `json:"name"`
    Enabled bool                  `json:"enabled"`
    Config  runtime.RawExtension  `json:"config,omitempty"`
}

type OutputSpec struct {
    Elasticsearch *ElasticsearchSpec `json:"elasticsearch,omitempty"`
}

type ElasticsearchSpec struct {
    Endpoints     []string  `json:"endpoints"`
    AuthSecretRef SecretRef `json:"authSecretRef,omitempty"`
    CASecretRef   SecretRef `json:"caSecretRef,omitempty"`
    Indices       IndexSpec `json:"indices"`
}

// CTEM 용도별 3개 인덱스
type IndexSpec struct {
    Inventory       string `json:"inventory"`
    Events          string `json:"events"`
    Vulnerabilities string `json:"vulnerabilities"`
}

type OverrideSpec struct {
    NodeAgent   *ComponentOverride `json:"nodeAgent,omitempty"`
    Falco       *ComponentOverride `json:"falco,omitempty"`
    Tetragon    *ComponentOverride `json:"tetragon,omitempty"`
    OSQuery     *ComponentOverride `json:"osquery,omitempty"`
    OTelGateway *ComponentOverride `json:"otelGateway,omitempty"`
}

type ComponentOverride struct {
    Resources         *corev1.ResourceRequirements `json:"resources,omitempty"`
    Tolerations       []corev1.Toleration          `json:"tolerations,omitempty"`
    NodeSelector      map[string]string            `json:"nodeSelector,omitempty"`
    Replicas          *int32                       `json:"replicas,omitempty"`
    PriorityClassName string                       `json:"priorityClassName,omitempty"`
    Image             string                       `json:"image,omitempty"`
}

type SecurityAgentStatus struct {
    ObservedGeneration int64              `json:"observedGeneration,omitempty"`
    Conditions         []metav1.Condition `json:"conditions,omitempty"`
    Features           map[string]string  `json:"features,omitempty"`
}
```

---

# 3. Feature-as-Plugin 아키텍처

## 3.1 Feature 인터페이스 — 4개 메서드

```go
// internal/controller/feature/feature.go

type Feature interface {
    // ID — Feature 고유 식별자
    ID() FeatureID

    // Configure — CRD spec.features[].config(RawExtension)를 타입 안전 디코딩하고
    //             활성화 여부를 결정한다.
    Configure(raw []byte) error

    // Contribute — 이 Feature가 필요한 모든 리소스를 DesiredState에 기여한다.
    //              DaemonSet/Deployment/ConfigMap/RBAC/OTel 수집 설정을 한 번에 Store에 추가.
    Contribute(ctx context.Context, store *DesiredStateStore) error

    // OTelConfig — OTel Node Collector에 추가할 filelog 리시버 정보 반환.
    //              nil이면 OTel filelog 수집이 필요 없다는 뜻 (예: Trivy).
    OTelConfig() *OTelReceiverConfig

    // Assess — 이 Feature의 정상 동작 여부를 판단하여 Status 조건을 반환한다.
    Assess(ctx context.Context, client client.Client, ns string) FeatureCondition
}
```

## 3.2 보조 타입

```go
type OTelReceiverConfig struct {
    ReceiverName string   // "filelog/falco"
    IncludePaths []string // 수집할 로그 파일 경로
    ParseFormat  string   // "json" | "regex" | "none"
    ToolLabel    string   // labels.security_tool 값
    TargetIndex  string   // "events" | "inventory" | "vulnerabilities"
}

type FeatureCondition struct {
    Type    string // "FalcoReady", "TetragonReady", ...
    Status  bool
    Reason  string
    Message string
}
```

## 3.3 Feature 자기등록 — 우선순위 기반 Registry

OTel Pipeline이 센서보다 먼저 Ready되도록 우선순위를 부여한다.

```go
// internal/controller/feature/registry.go

type FeatureRegistration struct {
    ID       FeatureID
    Priority int             // 낮을수록 먼저 실행
    Factory  func() Feature
}

var (
    mu       sync.RWMutex
    registry []FeatureRegistration
)

func Register(id FeatureID, priority int, factory func() Feature) {
    mu.Lock()
    defer mu.Unlock()
    registry = append(registry, FeatureRegistration{ID: id, Priority: priority, Factory: factory})
    sort.Slice(registry, func(i, j int) bool {
        return registry[i].Priority < registry[j].Priority
    })
}

// BuildActiveFeatures — CRD spec.features[]를 순회하며
//   등록된 Feature를 찾아 Configure()하고 활성화된 것만 반환
func BuildActiveFeatures(specs []FeatureSpec) ([]Feature, error) {
    mu.RLock()
    defer mu.RUnlock()

    specMap := make(map[FeatureID]*FeatureSpec)
    for i := range specs {
        if specs[i].Enabled {
            specMap[FeatureID(specs[i].Name)] = &specs[i]
        }
    }

    var active []Feature
    for _, reg := range registry {  // 우선순위 순서대로 순회
        fs, ok := specMap[reg.ID]
        if !ok { continue }
        feat := reg.Factory()
        if err := feat.Configure(fs.Config.Raw); err != nil {
            return nil, fmt.Errorf("configure %s: %w", reg.ID, err)
        }
        active = append(active, feat)
    }
    return active, nil
}
```

**우선순위 레이어**:

```
Priority 10   otel_pipeline   ← 가장 먼저 (수집 인프라)
Priority 100  falco, tetragon, osquery ← 센서
Priority 200  trivy           ← 스캔 (센서보다 나중이어도 무방)
```

## 3.4 DesiredStateStore — Feature가 리소스를 기여하는 중앙 저장소

```go
// internal/controller/feature/store.go

type DesiredStateStore struct {
    Namespace           string
    DaemonSets          map[string]*appsv1.DaemonSet
    Deployments         map[string]*appsv1.Deployment
    CronJobs            map[string]*batchv1.CronJob
    ConfigMaps          map[string]*corev1.ConfigMap
    Services            map[string]*corev1.Service
    ServiceAccounts     map[string]*corev1.ServiceAccount
    ClusterRoles        map[string]*rbacv1.ClusterRole
    ClusterRoleBindings map[string]*rbacv1.ClusterRoleBinding
    Unstructured        map[string]*unstructured.Unstructured  // TracingPolicy 등 CRD
}

func (s *DesiredStateStore) ApplyAll(ctx context.Context, c client.Client,
    owner *securityv1alpha1.SecurityAgent, scheme *runtime.Scheme) error {
    // 네임스페이스 스코프 리소스 → OwnerReference 설정 + SSA Apply
    for _, obj := range s.getAllNamespacedObjects() {
        ctrl.SetControllerReference(owner, obj, scheme)
        c.Patch(ctx, obj, client.Apply,
            client.FieldOwner("security-operator"), client.ForceOwnership)
    }
    // 클러스터 스코프 리소스(ClusterRole 등) → OwnerReference 불가, 라벨로 추적
    for _, obj := range s.getAllClusterScopedObjects() {
        obj.SetLabels(map[string]string{
            "app.kubernetes.io/managed-by": "security-operator",
            "security.example.io/owner":    owner.Name,
        })
        c.Patch(ctx, obj, client.Apply,
            client.FieldOwner("security-operator"), client.ForceOwnership)
    }
    // Unstructured (TracingPolicy 등)
    for _, obj := range s.Unstructured {
        if obj == nil { continue }
        ctrl.SetControllerReference(owner, obj, scheme)
        c.Patch(ctx, obj, client.Apply,
            client.FieldOwner("security-operator"), client.ForceOwnership)
    }
    return nil
}
```

## 3.5 Falco Feature 구현

```go
// internal/controller/feature/falco/feature.go

func init() {
    feature.Register(feature.FalcoFeatureID, 100, func() feature.Feature {
        return &falcoFeature{}
    })
}

type FalcoConfig struct {
    Driver     string `json:"driver"`
    JSONOutput bool   `json:"jsonOutput"`
    Image      string `json:"image,omitempty"`
}

func (f *falcoFeature) Contribute(ctx context.Context, store *feature.DesiredStateStore) error {
    image := "falcosecurity/falco-no-driver:0.39.2"
    if f.config.Image != "" { image = f.config.Image }

    priv := true
    pathType := corev1.HostPathDirectoryOrCreate

    ds := &appsv1.DaemonSet{
        // ... ObjectMeta, Selector ...
        Spec: appsv1.DaemonSetSpec{
            Template: corev1.PodTemplateSpec{
                Spec: corev1.PodSpec{
                    ServiceAccountName: "falco",
                    Containers: []corev1.Container{{
                        Name:  "falco",
                        Image: image,
                        Args: []string{
                            "--cri", "/run/containerd/containerd.sock",
                            "-o", "json_output=true",
                            "-o", "file_output.enabled=true",
                            "-o", "file_output.filename=/var/log/security/falco/events.log",
                            // ★ k8s meta enrichment 활성화
                            "-o", "metadata_download.enabled=true",
                        },
                        SecurityContext: &corev1.SecurityContext{Privileged: &priv},
                        Resources: corev1.ResourceRequirements{
                            Requests: corev1.ResourceList{
                                corev1.ResourceCPU: resource.MustParse("100m"),
                                corev1.ResourceMemory: resource.MustParse("512Mi"),
                            },
                            Limits: corev1.ResourceList{
                                corev1.ResourceCPU: resource.MustParse("500m"),
                                corev1.ResourceMemory: resource.MustParse("1Gi"),
                            },
                        },
                        VolumeMounts: []corev1.VolumeMount{
                            {Name: "dev", MountPath: "/host/dev", ReadOnly: true},
                            {Name: "proc", MountPath: "/host/proc", ReadOnly: true},
                            {Name: "boot", MountPath: "/host/boot", ReadOnly: true},
                            {Name: "modules", MountPath: "/host/lib/modules", ReadOnly: true},
                            {Name: "containerd", MountPath: "/run/containerd", ReadOnly: true},
                            {Name: "security-log", MountPath: "/var/log/security/falco"},
                            {Name: "falco-config", MountPath: "/etc/falco/falco_rules.local.yaml",
                                SubPath: "falco_rules.local.yaml"},
                        },
                    }},
                    Volumes: []corev1.Volume{
                        {Name: "dev", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/dev"}}},
                        {Name: "proc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
                        {Name: "boot", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/boot"}}},
                        {Name: "modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
                        {Name: "containerd", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/containerd"}}},
                        {Name: "security-log", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
                            Path: "/var/log/security/falco", Type: &pathType}}},
                        {Name: "falco-config", VolumeSource: corev1.VolumeSource{
                            ConfigMap: &corev1.ConfigMapVolumeSource{
                                LocalObjectReference: corev1.LocalObjectReference{Name: "falco-config"}}}},
                    },
                },
            },
        },
    }

    store.AddDaemonSet("falco", ds)
    store.AddServiceAccount("falco")

    // ★ Falco 설정: 로테이션 + 노이즈 제어
    store.AddConfigMap("falco-config", &corev1.ConfigMap{
        ObjectMeta: metav1.ObjectMeta{Name: "falco-config", Namespace: store.Namespace},
        Data: map[string]string{
            "falco.yaml": `
file_output:
  enabled: true
  filename: /var/log/security/falco/events.log
  keep_alive: true
  rotate:
    max_size: 100
    max_files: 3
json_output: true
metadata_download:
  enabled: true
`,
            // ★ PoC 전용 룰 오버라이드 — 노이즈 제거
            "falco_rules.local.yaml": `
- rule: "Read sensitive file trusted after startup"
  enabled: false
- rule: "Contact cloud metadata service from container"
  enabled: false
- rule: "Unexpected outbound connection destination"
  enabled: false
- rule: "Redirect STDOUT/STDIN to Network Connection in Container"
  enabled: false
- rule: "Drop and execute new binary in container"
  enabled: false
`,
        },
    })

    return nil
}

func (f *falcoFeature) OTelConfig() *feature.OTelReceiverConfig {
    return &feature.OTelReceiverConfig{
        ReceiverName: "filelog/falco",
        IncludePaths: []string{
            "/var/log/security/falco/events.log",
            "/var/log/security/falco/events.log.*",  // ★ 로테이션 파일
        },
        ParseFormat: "json",
        ToolLabel:   "falco",
        TargetIndex: "events",
    }
}

func (f *falcoFeature) Assess(ctx context.Context, c client.Client, ns string) feature.FeatureCondition {
    var ds appsv1.DaemonSet
    if err := c.Get(ctx, client.ObjectKey{Name: "falco", Namespace: ns}, &ds); err != nil {
        return feature.FeatureCondition{Type: "FalcoReady", Status: false, Reason: "NotFound"}
    }
    ready := ds.Status.DesiredNumberScheduled == ds.Status.NumberReady
    return feature.FeatureCondition{
        Type:    "FalcoReady",
        Status:  ready,
        Reason:  fmt.Sprintf("%d/%d", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled),
    }
}
```

## 3.6 Tetragon Feature — stdout 모드

```go
// internal/controller/feature/tetragon/feature.go

func init() {
    feature.Register(feature.TetragonFeatureID, 100, func() feature.Feature {
        return &tetragonFeature{}
    })
}

type TetragonConfig struct {
    ExportMode string   `json:"exportMode"`  // "stdout" (기본)
    Policies   []string `json:"policies"`
    Image      string   `json:"image,omitempty"`
}

func (f *tetragonFeature) Contribute(ctx context.Context, store *feature.DesiredStateStore) error {
    image := "quay.io/cilium/tetragon:v1.3.0"
    if f.config.Image != "" { image = f.config.Image }

    // ★ stdout 모드 — /var/log/security/tetragon 마운트 불필요
    //   kubelet이 /var/log/pods/ 하위에 자동으로 로그 파일 생성
    ds := /* ... Tetragon DaemonSet: eBPF 볼륨만 마운트 ... */
    store.AddDaemonSet("tetragon", ds)
    store.AddServiceAccount("tetragon")

    // ★ TracingPolicy CRD를 Unstructured로 등록
    for _, policyName := range f.config.Policies {
        tp := buildTracingPolicy(policyName)
        if tp != nil {
            store.AddUnstructured("tracingpolicy-"+policyName, tp)
        }
    }

    return nil
}

func (f *tetragonFeature) OTelConfig() *feature.OTelReceiverConfig {
    return &feature.OTelReceiverConfig{
        ReceiverName: "filelog/tetragon",
        // ★ stdout 모드 — k8sattributes가 자동으로 Pod 메타를 붙임
        IncludePaths: []string{
            "/var/log/pods/security-system_tetragon-*/tetragon/*.log",
        },
        ParseFormat: "json",
        ToolLabel:   "tetragon",
        TargetIndex: "events",
    }
}

func buildTracingPolicy(name string) *unstructured.Unstructured {
    switch name {
    case "container-escape-monitor":
        return &unstructured.Unstructured{
            Object: map[string]interface{}{
                "apiVersion": "cilium.io/v1alpha1",
                "kind":       "TracingPolicy",
                "metadata":   map[string]interface{}{"name": name},
                "spec": map[string]interface{}{
                    "kprobes": []interface{}{
                        map[string]interface{}{
                            "call": "__x64_sys_setns", "syscall": true,
                            "args": []interface{}{
                                map[string]interface{}{"index": 0, "type": "int"},
                                map[string]interface{}{"index": 1, "type": "int"},
                            },
                        },
                        map[string]interface{}{
                            "call": "__x64_sys_mount", "syscall": true,
                            "args": []interface{}{
                                map[string]interface{}{"index": 0, "type": "string"},
                                map[string]interface{}{"index": 1, "type": "string"},
                                map[string]interface{}{"index": 2, "type": "string"},
                            },
                        },
                    },
                },
            },
        }
    default:
        return nil
    }
}
```

## 3.7 OSquery Feature — CTEM Scope 전용

```go
// internal/controller/feature/osquery/feature.go

func init() {
    feature.Register(feature.OSQueryFeatureID, 100, func() feature.Feature {
        return &osqueryFeature{}
    })
}

func (f *osqueryFeature) OTelConfig() *feature.OTelReceiverConfig {
    return &feature.OTelReceiverConfig{
        ReceiverName: "filelog/osquery",
        IncludePaths: []string{"/var/log/security/osquery/results.log"},
        ParseFormat:  "json",
        ToolLabel:    "osquery",
        TargetIndex:  "inventory",  // ★ Scope → security-inventory
    }
}
```

## 3.8 Trivy Feature — OTel 비사용, CronJob 경로

```go
// internal/controller/feature/trivy/feature.go

func init() {
    feature.Register(feature.TrivyFeatureID, 200, func() feature.Feature {
        return &trivyFeature{}
    })
}

func (f *trivyFeature) OTelConfig() *feature.OTelReceiverConfig {
    return nil  // ★ Trivy는 CronJob → ES 직접 적재
}
```

## 3.9 cmd/main.go

```go
package main

import (
    _ "github.com/example/security-operator/internal/controller/feature/otel_pipeline"
    _ "github.com/example/security-operator/internal/controller/feature/falco"
    _ "github.com/example/security-operator/internal/controller/feature/tetragon"
    _ "github.com/example/security-operator/internal/controller/feature/osquery"
    _ "github.com/example/security-operator/internal/controller/feature/trivy"
)
```

## 3.10 새 도구 추가 = 3단계

```
1. internal/controller/feature/newtool/feature.go 생성
   → Feature 인터페이스 4개 메서드 구현
   → init()에서 feature.Register(id, priority, factory) 호출

2. cmd/main.go에 import 1줄 추가

3. 끝. Reconciler 코드 변경 없음. CRD 스키마 변경 없음.
```

---

# 4. Reconciler — Feature를 오케스트레이션하는 엔진

```go
func (r *SecurityAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    var agent securityv1alpha1.SecurityAgent
    if err := r.Get(ctx, req.NamespacedName, &agent); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // ★ 삭제 중이면 Finalizer 처리
    if !agent.DeletionTimestamp.IsZero() {
        return r.handleDeletion(ctx, &agent)
    }

    // ★ Finalizer 등록
    if !controllerutil.ContainsFinalizer(&agent, "security.example.io/cleanup") {
        controllerutil.AddFinalizer(&agent, "security.example.io/cleanup")
        r.Update(ctx, &agent)
    }

    // ★ Spec 미변경이면 상태 점검만 (무한 루프 방지)
    if agent.Status.ObservedGeneration == agent.Generation {
        r.updateStatus(ctx, &agent)
        return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
    }

    // ═══ Step 1: Feature 빌드 (우선순위 순서) ═══
    activeFeatures, err := feature.BuildActiveFeatures(agent.Spec.Features)
    if err != nil {
        return ctrl.Result{}, err
    }

    // ═══ Step 2: DesiredState 수집 ═══
    store := feature.NewDesiredStateStore(agent.Namespace)
    var otelConfigs []*feature.OTelReceiverConfig
    for _, feat := range activeFeatures {
        if err := feat.Contribute(ctx, store); err != nil {
            return ctrl.Result{}, err
        }
        if oc := feat.OTelConfig(); oc != nil {
            otelConfigs = append(otelConfigs, oc)
        }
    }

    // ═══ Step 3: OTel ConfigMap 합성 ═══
    if len(otelConfigs) > 0 {
        otelCM := buildOTelNodeConfigMap(otelConfigs, agent.Spec.Output)
        store.AddConfigMap("otel-node-config", otelCM)
    }

    // ═══ Step 4: Override 적용 ═══
    override.ApplyOverrides(agent.Spec.Override, store)

    // ═══ Step 5: SSA Apply ═══
    if err := store.ApplyAll(ctx, r.Client, &agent, r.Scheme); err != nil {
        return ctrl.Result{}, err
    }

    // ═══ Step 6: 비활성 Feature GC ═══
    if err := r.cleanupStale(ctx, &agent, store); err != nil {
        return ctrl.Result{}, err
    }

    // ═══ Step 7: Status 갱신 + ObservedGeneration ═══
    agent.Status.ObservedGeneration = agent.Generation
    r.updateStatus(ctx, &agent)

    return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// ★ Controller 설정 — Status 변경은 Reconcile 트리거하지 않음
func (r *SecurityAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return ctrl.NewControllerManagedBy(mgr).
        For(&securityv1alpha1.SecurityAgent{},
            builder.WithPredicates(predicate.GenerationChangedPredicate{})).
        Owns(&appsv1.DaemonSet{}).
        Owns(&appsv1.Deployment{}).
        Complete(r)
}

// ★ Finalizer — ClusterRole/ClusterRoleBinding 수동 삭제
func (r *SecurityAgentReconciler) handleDeletion(ctx context.Context,
    agent *securityv1alpha1.SecurityAgent) (ctrl.Result, error) {
    for _, name := range []string{"falco", "tetragon", "osquery"} {
        r.Delete(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}})
        r.Delete(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}})
    }
    controllerutil.RemoveFinalizer(agent, "security.example.io/cleanup")
    r.Update(ctx, agent)
    return ctrl.Result{}, nil
}
```

---

# 5. 데이터 플로우 아키텍처

## 5.1 전체 흐름

```
┌────────────────────────────────────────────────────────────────────┐
│                   SecurityAgent CRD (단일 진입점)                   │
│   features: [otel_pipeline, falco, tetragon, osquery, trivy]       │
└──────────────────────────────┬─────────────────────────────────────┘
                               │ Reconcile
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│                Security Operator Controller                        │
│   BuildActiveFeatures(priority순) → Contribute → Override → Apply  │
│   Assess() → Status 갱신                                           │
└──────────────────────────────┬─────────────────────────────────────┘
                               │
         ┌─────────────────────┼────────────────────────┐
         ▼                     ▼                        ▼
  ┌──────────────┐  ┌────────────────────┐  ┌────────────────────┐
  │  DaemonSets  │  │   Deployments      │  │  CRD / RBAC / CM   │
  │  falco       │  │   trivy-operator   │  │  TracingPolicy     │
  │  tetragon    │  │   otel-gateway     │  │  ServiceAccounts   │
  │  osquery     │  └────────────────────┘  │  CronJob           │
  │  otel-node   │                          └────────────────────┘
  └──────┬───────┘
         │
═════════╪══════════════════════ Worker Node ════════════════════════
         │
  ┌──────┴──────────────────────────────────────────────────────────┐
  │  ┌────────┐  ┌──────────┐  ┌─────────┐                         │
  │  │ Falco  │  │ Tetragon │  │ OSquery │                         │
  │  │  eBPF  │  │  eBPF    │  │  SQL    │                         │
  │  │syscall │  │  kprobe  │  │  poll   │                         │
  │  └───┬────┘  └────┬─────┘  └────┬────┘                         │
  │      │ JSON file   │ stdout      │ JSON file                    │
  │      ▼             ▼             ▼                              │
  │  /var/log/      /var/log/     /var/log/                         │
  │  security/      pods/...      security/                         │
  │  falco/         tetragon/     osquery/                          │
  │  events.log     *.log         results.log                       │
  │      │             │             │                              │
  │      ▼             ▼             ▼                              │
  │  ┌──────────────────────────────────────────────────────────┐   │
  │  │       OTel Node Collector DaemonSet                      │   │
  │  │                                                          │   │
  │  │  filelog/falco    ──┐                                    │   │
  │  │  filelog/tetragon ──┼→ k8sattributes → transform(meta)  │   │
  │  │  filelog/osquery  ──┘   → batch → otlp exporter          │   │
  │  └──────────────────────────────┬───────────────────────────┘   │
  └─────────────────────────────────┼───────────────────────────────┘
                                    │ OTLP/gRPC
                                    ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │          OTel Gateway Deployment                                 │
  │                                                                 │
  │  otlp receiver                                                  │
  │      │                                                          │
  │  transform/severity (통합 정수 1~5 매핑)                          │
  │      │                                                          │
  │  routing processor                                              │
  │    → tool=osquery  → security-inventory     (CTEM Scope)        │
  │    → tool=falco    → security-events        (CTEM Validation)   │
  │    → tool=tetragon → security-events        (CTEM Validation)   │
  │      │                                                          │
  │  elasticsearch exporter(s)                                      │
  └──────────────────────┬──────────────────────────────────────────┘
                         │ Bulk API
                         ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │                 Elasticsearch + Kibana                           │
  │                                                                 │
  │  security-inventory   OSquery 인벤토리          ← CTEM Scope    │
  │  security-events      Falco/Tetragon 경보       ← CTEM Valid.   │
  │  security-vuln        Trivy CVE                 ← CTEM Disc.    │
  │                                                                 │
  │  Data View: security-*  (통합 조회)                              │
  └─────────────────────────────────────────────────────────────────┘

  ※ Trivy 별도 경로:
  Trivy Operator → VulnerabilityReport CRD → CronJob (5분, _id 고정 upsert) → security-vuln
```

## 5.2 k8s 메타데이터 부착 — 도구별 하이브리드 방식

도구마다 출력 특성이 다르므로 **도구별 최적 경로를 선택**한다.

```
도구        출력 방식         k8s 메타 소스              이유
────────────────────────────────────────────────────────────────────────
Falco       파일 출력         도구 자체 JSON 필드         Falco JSON에 k8s.ns.name,
            (file_output)     → OTel transform 리매핑     k8s.pod.name이 이미 포함.

Tetragon    stdout            /var/log/pods/ 경로         k8sattributes가 자동으로
                              → k8sattributes 자동        Pod 메타를 붙임.

OSquery     파일 출력         hostIdentifier 필드         노드 인벤토리 = Node 메타 중심.
            (results.log)     + k8sattributes node        Pod 메타 불필요.
```

## 5.3 OTel Node Collector 설정 (자동 합성)

```yaml
receivers:
  filelog/falco:
    include:
      - /var/log/security/falco/events.log
      - /var/log/security/falco/events.log.*
    start_at: beginning
    operators:
      - type: json_parser
        timestamp:
          parse_from: attributes.time
          layout_type: epoch
          layout: s

  filelog/tetragon:
    include:
      - /var/log/pods/security-system_tetragon-*/tetragon/*.log
    start_at: beginning
    operators:
      - type: json_parser

  filelog/osquery:
    include:
      - /var/log/security/osquery/results.log
    start_at: beginning
    operators:
      - type: json_parser

processors:
  k8sattributes:
    auth_type: "serviceAccount"
    extract:
      metadata: [k8s.pod.name, k8s.namespace.name, k8s.node.name, k8s.pod.uid]
    pod_association:
      - sources:
          - from: resource_attribute
            name: k8s.pod.uid

  # Falco 전용: 도구 JSON → 표준 필드 리매핑
  transform/falco_meta:
    log_statements:
      - context: log
        conditions:
          - attributes["security_tool"] == "falco"
        statements:
          - set(resource.attributes["k8s.namespace.name"],
                attributes["output_fields.k8s.ns.name"])
              where attributes["output_fields.k8s.ns.name"] != nil
          - set(resource.attributes["k8s.pod.name"],
                attributes["output_fields.k8s.pod.name"])
              where attributes["output_fields.k8s.pod.name"] != nil
          - set(resource.attributes["k8s.node.name"],
                attributes["output_fields.k8s.node.name"])
              where attributes["output_fields.k8s.node.name"] != nil

  # Tetragon fallback: k8sattributes 실패 시 도구 JSON에서 보강
  transform/tetragon_meta:
    log_statements:
      - context: log
        conditions:
          - attributes["security_tool"] == "tetragon"
        statements:
          - set(resource.attributes["k8s.namespace.name"],
                attributes["process.pod.namespace"])
              where resource.attributes["k8s.namespace.name"] == nil
                and attributes["process.pod.namespace"] != nil
          - set(resource.attributes["k8s.pod.name"],
                attributes["process.pod.name"])
              where resource.attributes["k8s.pod.name"] == nil
                and attributes["process.pod.name"] != nil

  # OSquery: 노드 메타 보강
  transform/osquery_meta:
    log_statements:
      - context: log
        conditions:
          - attributes["security_tool"] == "osquery"
        statements:
          - set(resource.attributes["k8s.node.name"],
                attributes["hostIdentifier"])
              where attributes["hostIdentifier"] != nil

  batch:
    send_batch_size: 512
    timeout: 500ms

service:
  pipelines:
    logs:
      receivers: [filelog/falco, filelog/tetragon, filelog/osquery]
      processors: [k8sattributes, transform/falco_meta, transform/tetragon_meta,
                    transform/osquery_meta, batch]
      exporters: [otlp]
```

## 5.4 OTel Gateway — Severity 통합 매핑 + 인덱스 라우팅

```yaml
processors:
  # ── 도구별 severity → 통합 정수(1~5) 매핑 ──
  transform/severity:
    log_statements:
      - context: log
        conditions:
          - attributes["security_tool"] == "falco"
        statements:
          - set(attributes["event.severity"], 5) where attributes["priority"] == "Emergency" or attributes["priority"] == "Alert"
          - set(attributes["event.severity"], 4) where attributes["priority"] == "Critical"
          - set(attributes["event.severity"], 3) where attributes["priority"] == "Error" or attributes["priority"] == "Warning"
          - set(attributes["event.severity"], 2) where attributes["priority"] == "Notice"
          - set(attributes["event.severity"], 1) where attributes["priority"] == "Informational" or attributes["priority"] == "Debug"
          - set(attributes["event.kind"], "alert")
      - context: log
        conditions:
          - attributes["security_tool"] == "tetragon"
        statements:
          - set(attributes["event.severity"], 4) where attributes["process_kprobe"] != nil
          - set(attributes["event.severity"], 2) where attributes["process_exec"] != nil and attributes["process_kprobe"] == nil
          - set(attributes["event.kind"], "event")
      - context: log
        conditions:
          - attributes["security_tool"] == "osquery"
        statements:
          - set(attributes["event.severity"], 1)
          - set(attributes["event.kind"], "metric")

  # ── CTEM 용도별 인덱스 라우팅 ──
  routing:
    from_attribute: security_tool
    table:
      - value: osquery
        exporters: [elasticsearch/inventory]
      - value: falco
        exporters: [elasticsearch/events]
      - value: tetragon
        exporters: [elasticsearch/events]
    default_exporters: [elasticsearch/events]

exporters:
  elasticsearch/inventory:
    endpoints: ["https://elasticsearch:9200"]
    logs_index: "security-inventory"
  elasticsearch/events:
    endpoints: ["https://elasticsearch:9200"]
    logs_index: "security-events"
```

**통합 severity 매핑 기준**:

```
통합 severity    Falco                   Trivy         Tetragon
──────────────────────────────────────────────────────────────────
5 (Critical)     Emergency, Alert        CRITICAL      -
4 (High)         Critical                HIGH          kprobe match
3 (Medium)       Error, Warning          MEDIUM        -
2 (Low)          Notice                  LOW           process_exec
1 (Info)         Info, Debug             UNKNOWN       -
```

---

# 6. Elasticsearch 설정

## 6.1 컴포넌트 템플릿 (공통 필드)

```bash
curl -XPUT "https://es:9200/_component_template/security-common" \
  -H 'Content-Type: application/json' -d '{
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "labels": {
          "properties": {
            "security_tool": { "type": "keyword" }
          }
        },
        "event": {
          "properties": {
            "kind":     { "type": "keyword" },
            "severity": { "type": "integer" },
            "category": { "type": "keyword" },
            "action":   { "type": "keyword" }
          }
        },
        "kubernetes": {
          "properties": {
            "namespace": { "type": "keyword" },
            "pod": { "properties": { "name": { "type": "keyword" }, "uid": { "type": "keyword" } } },
            "node": { "properties": { "name": { "type": "keyword" } } }
          }
        },
        "container": {
          "properties": {
            "id": { "type": "keyword" },
            "image": { "properties": { "name": { "type": "keyword" }, "tag": { "type": "keyword" } } }
          }
        }
      }
    }
  }
}'
```

## 6.2 security-events 템플릿 (Falco/Tetragon)

```bash
curl -XPUT "https://es:9200/_index_template/security-events" \
  -H 'Content-Type: application/json' -d '{
  "index_patterns": ["security-events*"],
  "composed_of": ["security-common"],
  "priority": 200,
  "template": {
    "mappings": {
      "properties": {
        "rule":     { "type": "keyword" },
        "priority": { "type": "keyword" },
        "process": {
          "properties": {
            "binary":    { "type": "keyword" },
            "arguments": { "type": "wildcard" },
            "pid":       { "type": "long" }
          }
        },
        "parent": { "properties": { "binary": { "type": "keyword" } } },
        "output_fields": { "type": "flattened" }
      }
    }
  }
}'
```

## 6.3 security-inventory 템플릿 (OSquery)

```bash
curl -XPUT "https://es:9200/_index_template/security-inventory" \
  -H 'Content-Type: application/json' -d '{
  "index_patterns": ["security-inventory*"],
  "composed_of": ["security-common"],
  "priority": 200,
  "template": {
    "mappings": {
      "properties": {
        "osquery": {
          "properties": {
            "query_name":     { "type": "keyword" },
            "action":         { "type": "keyword" },
            "hostIdentifier": { "type": "keyword" },
            "columns":        { "type": "flattened" }
          }
        },
        "host": {
          "properties": {
            "hostname": { "type": "keyword" },
            "os": { "properties": { "name": { "type": "keyword" }, "version": { "type": "keyword" }, "kernel": { "type": "keyword" } } }
          }
        },
        "network": {
          "properties": { "port": { "type": "integer" }, "protocol": { "type": "keyword" } }
        }
      }
    }
  }
}'
```

## 6.4 security-vuln 템플릿 (Trivy)

```bash
curl -XPUT "https://es:9200/_index_template/security-vuln" \
  -H 'Content-Type: application/json' -d '{
  "index_patterns": ["security-vuln*"],
  "composed_of": ["security-common"],
  "priority": 200,
  "template": {
    "mappings": {
      "properties": {
        "vulnerability": {
          "properties": {
            "id":               { "type": "keyword" },
            "severity":         { "type": "keyword" },
            "score":            { "type": "float" },
            "title":            { "type": "text" },
            "fixedVersion":     { "type": "keyword" },
            "installedVersion": { "type": "keyword" },
            "resource":         { "type": "keyword" }
          }
        },
        "workload": { "properties": { "name": { "type": "keyword" }, "kind": { "type": "keyword" } } }
      }
    }
  }
}'
```

**설계 포인트**:
- 모든 템플릿이 **객체 구조**(`properties` 중첩)로 정의 → dot notation 매핑 충돌 방지
- Falco `output_fields`, OSquery `columns` → `flattened` 타입으로 가변 필드 안전 처리
- `process.arguments` → `wildcard` 타입으로 부분 매칭 가능

---

# 7. CTEM 프레임워크 매핑 검증

## 7.1 5단계별 커버리지

```
 CTEM 단계        도구              PoC 검증 항목                  ES 인덱스
────────────────────────────────────────────────────────────────────────────

 ┌─────────┐
 │  Scope  │     OSquery          ✓ 노드 OS/커널 버전 인벤토리    inventory
 │  (영역)  │                      ✓ listening_ports 열린 포트     inventory
 │         │                      ✓ docker_containers 컨테이너    inventory
 │         │                      ✓ kernel_modules eBPF 확인      inventory
 │         │     Trivy            ✓ 컨테이너 이미지 목록          vuln
 └────┬────┘
      ▼
 ┌──────────┐
 │ Discovery│     Trivy            ✓ CVE 스캔 (ID, CVSS, fix)    vuln
 │  (발견)   │     Falco            ✓ 비정상 syscall 탐지          events
 │          │     Tetragon         ✓ process_exec 추적            events
 └────┬────┘
      ▼
 ┌──────────┐
 │ Priority │     Trivy            ✓ CVSS + fixedVersion 우선순위 vuln
 │(우선순위) │     Falco            ✓ priority 8단계 심각도        events
 │          │     Kibana           ✓ Severity 분포 대시보드        -
 └────┬────┘
      ▼
 ┌──────────┐
 │Validation│     Falco            ✓ MITRE 시나리오 → 룰 트리거   events
 │  (검증)   │     Tetragon         ✓ MITRE 시나리오 → kprobe      events
 │          │     교차검증          ✓ 동일 행위 양쪽 탐지          events
 └────┬────┘
      ▼
 ┌───────────┐
 │Mobilization│   Kibana Alert     △ 선택적
 │(실행 유도) │   Phase B           ✗ 비목표
 └───────────┘

 ✓ = PoC 필수    △ = 선택    ✗ = 비목표
```

## 7.2 CTEM 검증 체크리스트

### CTEM-SCOPE: OSquery가 Scope 단계 데이터를 제공한다

- [ ] **CTEM-SCOPE-01**: `security-inventory`에 `osquery.query_name: system_info` 문서가 주기적으로 유입되고, `host.hostname`, `host.os.kernel` 필드가 채워져 있다
- [ ] **CTEM-SCOPE-02**: `listening_ports` 쿼리 결과에 `network.port`, `network.protocol`, `process.name` 필드가 존재한다
- [ ] **CTEM-SCOPE-03**: Trivy 스캔 결과에 클러스터 내 모든 네임스페이스 워크로드 이미지가 `security-vuln`에 포함되어 있다
- [ ] **CTEM-SCOPE-04**: Kibana에서 `labels.security_tool: osquery`로 노드 인벤토리를 조회하고, 노드별 커널 버전을 비교할 수 있다
- [ ] **CTEM-SCOPE-05**: `kernel_modules` 쿼리로 eBPF 관련 모듈 로드 상태를 확인할 수 있다
- [ ] **CTEM-SCOPE-06**: `docker_containers` 쿼리로 노드별 실행 중 컨테이너 목록을 확인할 수 있다

**ES 검증 쿼리**:
```json
GET security-inventory/_search
{
  "size": 5, "sort": [{"@timestamp": "desc"}],
  "query": { "bool": { "filter": [
    {"term": {"labels.security_tool": "osquery"}},
    {"term": {"osquery.query_name": "system_info"}},
    {"range": {"@timestamp": {"gte": "now-15m"}}}
  ]}}
}
```
**Pass**: 15분 내 문서 유입 + host/커널 정보 존재 / **Fail**: osquery 로그 경로 → OTel filelog → PSA 순으로 점검

### CTEM-VALIDATION: Falco/Tetragon이 Validation 단계를 커버한다

- [ ] **CTEM-VAL-01**: 테스트 Pod에서 shell 실행 시 `security-events`에 Falco + Tetragon 이벤트가 **2분 이내에 양쪽 모두** 적재된다
- [ ] **CTEM-VAL-02**: K8s API 연결 시도 시 Falco/Tetragon 이벤트가 적재된다
- [ ] **CTEM-VAL-03**: Container Escape 시도(nsenter/mount) 시 Tetragon TracingPolicy kprobe 이벤트가 생성된다
- [ ] **CTEM-VAL-04**: MITRE 시나리오 5개 중 **4개 이상** 탐지
- [ ] **CTEM-VAL-05**: 탐지 이벤트에 `kubernetes.namespace`, `kubernetes.pod.name` 메타가 포함되어 Kibana에서 워크로드별 필터링 가능

**ES 검증 쿼리**:
```json
GET security-events/_search
{
  "size": 20, "sort": [{"@timestamp": "desc"}],
  "query": { "bool": { "filter": [
    {"range": {"@timestamp": {"gte": "now-10m"}}},
    {"term": {"kubernetes.namespace": "ctem-test"}},
    {"term": {"kubernetes.pod.name": "ctem-testbox"}},
    {"terms": {"labels.security_tool": ["falco", "tetragon"]}}
  ]}}
}
```
**Pass**: falco + tetragon 양쪽 이벤트 존재 / **Fail 분기**: falco만 → Tetragon 정책 확인, tetragon만 → Falco 룰 확인

### CTEM-DISCOVERY/PRIORITY: Trivy가 데이터를 제공한다

- [ ] **CTEM-DISC-01**: `security-vuln`에 `vulnerability.id`, `vulnerability.severity`, `container.image.name` 검색 가능
- [ ] **CTEM-PRI-01**: `vulnerability.severity: CRITICAL`로 필터링하면 CVSS ≥ 9.0만 조회
- [ ] **CTEM-PRI-02**: `vulnerability.fixedVersion` 유무로 "패치 가능한 Critical" 목록 생성 가능

---

# 8. MITRE ATT&CK 테스트 시나리오

## 8.1 테스트 환경 — Pod 역할 분리

각 Pod에 필요한 바이너리가 있는지 확인하여 **시나리오 실행 실패를 방지**한다.

```yaml
# test/pods.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ctem-test
  labels: { purpose: security-testing }
---
# ★ 기본 행위 시나리오 Pod (sh, cat, echo, ls, mount 내장)
apiVersion: v1
kind: Pod
metadata:
  name: ctem-testbox
  namespace: ctem-test
  labels: { app: ctem-testbox }
spec:
  containers:
  - name: box
    image: alpine:3
    command: ["sh", "-c", "sleep 36000"]
---
# ★ 네트워크/고급 도구 Pod (curl, nmap, nc, nsenter 포함)
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: ctem-test
  labels: { app: attacker }
spec:
  containers:
  - name: attacker
    image: nicolaka/netshoot:latest
    command: ["sleep", "infinity"]
---
# ★ Trivy CVE 스캔 대상 전용 (공격 행위 실행하지 않음)
apiVersion: v1
kind: Pod
metadata:
  name: target-nginx
  namespace: ctem-test
  labels: { app: target-nginx }
spec:
  containers:
  - name: nginx
    image: nginx:1.25
    ports: [{ containerPort: 80 }]
```

## 8.2 시나리오 상세

### A — CTEM Scope 검증 (OSquery 인벤토리)

**행위**: SecurityAgent CRD 적용 후 OSquery가 60초 주기 자동 쿼리  
**기대**: `security-inventory`에 `osquery.query_name: system_info/listening_ports` 문서 유입  
**Pass**: 15분 내 문서 유입 + host/커널/포트 정보 존재

---

### B — T1059.004 Unix Shell (Execution)

**실행 Pod**: `ctem-testbox` (alpine — /bin/sh 내장)

```bash
kubectl exec -n ctem-test -it ctem-testbox -- sh -c "whoami && id && uname -a"
```

| 도구 | 룰/이벤트 | ES 필드 |
|------|----------|---------|
| **Falco** | `Terminal shell in container` | `rule: "Terminal shell in container"` |
| **Tetragon** | `process_exec` — `/bin/sh` | `process.binary: "/bin/sh"` |

**Pass**: Falco + Tetragon **양쪽** 이벤트 존재

---

### C — T1552.001 + K8s API (Credential Access + Discovery)

**실행 Pod**: `ctem-testbox` (Part 1) + `attacker` (Part 2)

```bash
# Part 1: SA 토큰 읽기 (ctem-testbox — cat 있음)
kubectl exec -n ctem-test ctem-testbox -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Part 2: K8s API 연결 (attacker — curl 있음)
kubectl exec -n ctem-test attacker -- \
  curl -sk https://kubernetes.default.svc -m 2 || true
```

| 도구 | 룰/이벤트 |
|------|----------|
| **Falco** | `Read sensitive file untrusted`, `Contact K8S API Server From Container` |
| **Tetragon** | `process_exec` — `cat`, `curl` |

**Pass**: Falco/Tetragon 양쪽 이벤트 존재

---

### D — T1611 Container Escape (Privilege Escalation)

**실행 Pod**: `ctem-testbox` (Part 1,2) + `attacker` (Part 3)

```bash
# Part 1: /proc/1/ns 탐색 (ctem-testbox — ls 있음)
kubectl exec -n ctem-test ctem-testbox -- ls -la /proc/1/ns/

# Part 2: mount 시도 (ctem-testbox — busybox mount 있음)
kubectl exec -n ctem-test ctem-testbox -- \
  mount -t proc proc /mnt 2>/dev/null || echo "mount failed"

# Part 3: nsenter 시도 (attacker — nsenter 있음)
kubectl exec -n ctem-test attacker -- \
  nsenter --target 1 --mount -- /bin/sh -c "echo escaped" 2>/dev/null || echo "nsenter failed"
```

| 도구 | 룰/이벤트 | 비고 |
|------|----------|------|
| **Falco** | `Launch Privileged Container` (간접) | |
| **Tetragon** | kprobe `__x64_sys_mount`, `__x64_sys_setns` | TracingPolicy 필수 |

**Pass**: Tetragon kprobe 이벤트 존재 (TracingPolicy 동작 확인)

---

### E — T1053.003 Cron Persistence (Persistence)

**실행 Pod**: `ctem-testbox`

```bash
kubectl exec -n ctem-test ctem-testbox -- sh -c \
  "echo '* * * * * root /tmp/backdoor.sh' > /etc/cron.d/backdoor 2>/dev/null || echo 'blocked'"
```

| 도구 | 룰/이벤트 |
|------|----------|
| **Falco** | `Write below etc` |
| **Tetragon** | `process_exec` — sh, echo |

**Pass**: Falco + Tetragon 즉시 탐지  
**OSquery**: ★ 제외 (Scope 전용 — 컨테이너 내부 cron 감지 불가)

## 8.3 교차검증 매트릭스

```
시나리오              Pod            Falco    Tetragon   OSquery   CTEM
──────────────────────────────────────────────────────────────────────
A  Scope 검증         (자동)          -        -         ✅        Scope
B  Unix Shell        testbox        ✅       ✅          -        Validation
C  Credential+API    testbox+atk    ✅       ✅          -        Validation
D  Container Escape  testbox+atk    ✅       ✅*         -        Validation
E  Cron Persistence  testbox        ✅       ✅          -        Validation

Trivy: target-nginx(nginx:1.25) 이미지 CVE → security-vuln (Discovery/Priority)
  → "취약한 이미지 + 런타임 공격" 상관 가능 (image 기준 조인)

* TracingPolicy 필요
```

## 8.4 테스트 자동화 스크립트

```bash
#!/bin/bash
# test/run-ctem-scenarios.sh
set -euo pipefail
ES_URL="${ES_URL:-https://security-es-es-http.elastic-system:9200}"
NS="ctem-test"

echo "=== Setup ==="
kubectl apply -f test/pods.yaml
kubectl wait --for=condition=Ready pod/ctem-testbox -n $NS --timeout=60s
kubectl wait --for=condition=Ready pod/attacker -n $NS --timeout=60s
sleep 10

echo "=== A: Scope (90s wait) ===" && sleep 90

echo "=== B: T1059.004 Unix Shell ==="
kubectl exec -n $NS ctem-testbox -- sh -c "whoami && id && uname -a" && sleep 5

echo "=== C: T1552.001 + K8s API ==="
kubectl exec -n $NS ctem-testbox -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true
kubectl exec -n $NS attacker -- curl -sk https://kubernetes.default.svc -m 2 2>/dev/null || true
sleep 5

echo "=== D: T1611 Container Escape ==="
kubectl exec -n $NS ctem-testbox -- ls -la /proc/1/ns/ 2>/dev/null || true
kubectl exec -n $NS ctem-testbox -- mount -t proc proc /mnt 2>/dev/null || echo "mount failed"
kubectl exec -n $NS attacker -- nsenter --target 1 --mount -- /bin/sh -c "echo escaped" 2>/dev/null || echo "nsenter failed"
sleep 5

echo "=== E: T1053.003 Cron ==="
kubectl exec -n $NS ctem-testbox -- sh -c "echo '* * * * * root /tmp/evil.sh' > /etc/cron.d/backdoor 2>/dev/null || echo 'blocked'"
sleep 30

echo ""
echo "╔══════════════════════════════════════╗"
echo "║       Verification Results           ║"
echo "╚══════════════════════════════════════╝"

SCOPE=$(curl -sk "$ES_URL/security-inventory/_count?q=labels.security_tool:osquery" | jq -r .count)
echo "Scope (inventory): $SCOPE"
[ "$SCOPE" -gt 0 ] && echo "  ✅ CTEM-SCOPE: PASS" || echo "  ❌ CTEM-SCOPE: FAIL"

FALCO=$(curl -sk "$ES_URL/security-events/_count" -H 'Content-Type: application/json' -d '{"query":{"bool":{"filter":[{"term":{"labels.security_tool":"falco"}},{"range":{"@timestamp":{"gte":"now-10m"}}}]}}}' | jq -r .count)
TETRA=$(curl -sk "$ES_URL/security-events/_count" -H 'Content-Type: application/json' -d '{"query":{"bool":{"filter":[{"term":{"labels.security_tool":"tetragon"}},{"range":{"@timestamp":{"gte":"now-10m"}}}]}}}' | jq -r .count)
echo "Falco events: $FALCO / Tetragon events: $TETRA"
[ "$FALCO" -gt 0 ] && [ "$TETRA" -gt 0 ] && echo "  ✅ CTEM-VALIDATION: PASS" || echo "  ❌ CTEM-VALIDATION: FAIL"

VULN=$(curl -sk "$ES_URL/security-vuln/_count?q=labels.security_tool:trivy" | jq -r .count)
echo "Trivy CVEs: $VULN"
[ "$VULN" -gt 0 ] && echo "  ✅ CTEM-DISCOVERY: PASS" || echo "  △ CTEM-DISCOVERY: PENDING"

kubectl delete ns $NS --ignore-not-found
echo "Done."
```

---

# 9. OSquery 쿼리 팩 (CTEM Scope 전용)

호스트/노드 레벨 인벤토리만 수집. 컨테이너 내부 감지는 범위 밖.

```json
{
  "queries": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory, hardware_vendor FROM system_info;",
      "interval": 3600, "snapshot": true,
      "description": "CTEM Scope: 노드 하드웨어 인벤토리"
    },
    "os_version": {
      "query": "SELECT name, version, major, minor, patch, platform FROM os_version;",
      "interval": 3600, "snapshot": true,
      "description": "CTEM Scope: OS 버전"
    },
    "kernel_info": {
      "query": "SELECT version, arguments, device FROM kernel_info;",
      "interval": 3600, "snapshot": true,
      "description": "CTEM Scope: 커널 정보"
    },
    "listening_ports": {
      "query": "SELECT lp.pid, lp.port, lp.protocol, lp.address, p.name, p.path FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port != 0;",
      "interval": 300,
      "description": "CTEM Scope: 열린 포트 + 프로세스 매핑 (노드 레벨)"
    },
    "docker_containers": {
      "query": "SELECT id, name, image, state, status FROM docker_containers;",
      "interval": 300,
      "description": "CTEM Scope: 노드에서 실행 중인 컨테이너 목록"
    },
    "kernel_modules": {
      "query": "SELECT name, size, status FROM kernel_modules WHERE status = 'Live';",
      "interval": 600,
      "description": "CTEM Scope: 로드된 커널 모듈 (eBPF 확인)"
    }
  }
}
```

---

# 10. Trivy CronJob — 중복 방지 upsert

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: trivy-es-sync
  namespace: security-system
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: trivy-watcher
          containers:
          - name: sync
            image: bitnami/kubectl:1.29
            command:
            - /bin/sh
            - -c
            - |
              ES_URL="https://security-es-es-http.elastic-system:9200"
              ES_PASS=$(cat /etc/es-creds/password)

              kubectl get vulnerabilityreports -A -o json | \
              jq -c '
                .items[] |
                .metadata as $meta |
                .report.vulnerabilities[]? |
                select(.severity == "CRITICAL" or .severity == "HIGH") |
                {
                  id: (($meta.uid) + ":" + .vulnerabilityID + ":" + (.resource // "unknown")),
                  doc: {
                    "@timestamp": now | todate,
                    "labels": {"security_tool": "trivy"},
                    "event": {"kind": "alert", "severity": (
                      if .severity == "CRITICAL" then 5
                      elif .severity == "HIGH" then 4 else 3 end
                    )},
                    "vulnerability": {
                      "id": .vulnerabilityID,
                      "severity": .severity,
                      "score": (.score // 0),
                      "title": .title,
                      "fixedVersion": (.fixedVersion // "none"),
                      "installedVersion": .installedVersion,
                      "resource": .resource
                    },
                    "container": {"image": {"name": ($meta.labels["trivy-operator.resource.name"] // "unknown")}},
                    "kubernetes": {"namespace": $meta.namespace},
                    "workload": {
                      "name": ($meta.labels["trivy-operator.resource.name"] // "unknown"),
                      "kind": ($meta.labels["trivy-operator.resource.kind"] // "unknown")
                    }
                  }
                }
              ' | while IFS= read -r item; do
                _id=$(echo "$item" | jq -r .id)
                doc=$(echo "$item" | jq -c .doc)
                printf '{"index":{"_index":"security-vuln","_id":"%s"}}\n%s\n' "$_id" "$doc"
              done | curl -sk -u "elastic:$ES_PASS" \
                -XPOST "$ES_URL/_bulk" \
                -H 'Content-Type: application/x-ndjson' --data-binary @-
            volumeMounts:
            - { name: es-creds, mountPath: /etc/es-creds, readOnly: true }
          volumes:
          - { name: es-creds, secret: { secretName: es-credentials } }
          restartPolicy: OnFailure
```

`_id` = `<VulnerabilityReport UID>:<CVE ID>:<package>` → 동일 CVE는 덮어쓰기(중복 방지)

---

# 11. Kibana 대시보드

### 대시보드 1 — 도구별 이벤트 추이

```
Type: Area chart (stacked)  |  Index: security-*
X: @timestamp (5min)        |  Split: labels.security_tool
```

### 대시보드 2 — Severity 분포

```
Type: Donut chart            |  Index: security-events, security-vuln
Slice: event.severity        |  Filter: event.severity exists
```

### 대시보드 3 — Top Namespace/Pod

```
Type: Horizontal bar         |  Index: security-events
Y: Count                     |  X: kubernetes.namespace (top 10)
Split: kubernetes.pod.name   |
```

---

# 12. 리소스 사이징 가이드

## 노드당 리소스 (DaemonSet)

```
컴포넌트           CPU req/lim     Memory req/lim    비고
───────────────────────────────────────────────────────────
Falco DS           100m / 500m     512Mi / 1Gi       modern_ebpf, 룰 제한
Tetragon DS        100m / 500m     256Mi / 512Mi     TracingPolicy 2개
OSquery DS          50m / 200m     128Mi / 256Mi     쿼리 6개, 300s 간격
OTel Node DS       100m / 300m     128Mi / 256Mi     filelog 3개
───────────────────────────────────────────────────────────
노드당 합계        350m / 1500m    1Gi / 2Gi
```

## 클러스터 리소스 (Deployment)

```
컴포넌트           CPU req/lim     Memory req/lim    Replicas
───────────────────────────────────────────────────────────
OTel Gateway       100m / 500m     128Mi / 256Mi     1
ES (단일노드)      500m / 2000m    2Gi / 4Gi         1
Kibana             100m / 500m     512Mi / 1Gi       1
Trivy Operator     100m / 300m     128Mi / 256Mi     1
```

## 최소 클러스터 사양

```
Control Plane      2 vCPU / 4 GiB
Worker × 2         4 vCPU / 8 GiB each  (t3.xlarge)
커널               5.15+ (BTF), 6.1+ 권장
디스크 Worker      50 GiB gp3
디스크 ES          100 GiB gp3
```

---

# 13. 마일스톤 실행 계획

## M0. 인프라 준비 (1일)

**작업**: 네임스페이스 + PSA privileged, BTF/커널 확인, 로그 디렉터리 생성

**Exit Criteria**:
- [ ] privileged Pod 배포 가능
- [ ] 모든 노드 `/sys/kernel/btf/vmlinux` 존재
- [ ] `/var/log/security/{falco,osquery}` 디렉터리 존재

---

## M1. Elasticsearch + Kibana (1-2일)

**작업**: ECK 배포, 컴포넌트 템플릿(security-common) + 인덱스 템플릿 3개 생성

**Exit Criteria**:
- [ ] ES green, Kibana 접속 가능
- [ ] `security-events`, `security-inventory`, `security-vuln` 템플릿 생성 완료
- [ ] 테스트 문서 삽입 → Kibana `security-*` Data View에서 검색 성공

---

## M2. Operator Core + OTel Pipeline Feature (3-4일)

**작업**:
- Kubebuilder 스캐폴딩 → 배열 기반 CRD
- Feature Registry (우선순위 기반)
- DesiredStateStore (Unstructured 포함)
- Override 2단계 (공통 + 도구별)
- SSA Apply + OwnerReference + Finalizer
- GenerationChangedPredicate (무한 루프 방지)
- otel_pipeline Feature (Priority 10)
- Operator 헬스체크 + 메트릭

**Exit Criteria**:
- [ ] CRD 적용 시 OTel Gateway Deploy + OTel Node DS 자동 생성
- [ ] OTLP → Gateway → ES 적재 확인
- [ ] CRD 삭제 시 리소스 자동 GC (OwnerReference + Finalizer)
- [ ] Status에 `PipelineReady` 조건 반영

---

## M3. Falco Feature (2-3일)

**작업**:
- falco Feature (Priority 100) — 파일 출력 + k8s meta enrichment
- Falco 설정 ConfigMap (로테이션: max_size 100MB, max_files 3)
- PoC 전용 룰 오버라이드 (노이즈 Top5 비활성화)
- OTel Node에 filelog/falco + transform/falco_meta 리시버 자동 추가
- OTel Gateway에 transform/severity 매핑

**Exit Criteria**:
- [ ] `falco.enabled: true` → Falco DS 자동 생성
- [ ] OTel ConfigMap에 `filelog/falco` 리시버 자동 포함
- [ ] `kubectl exec -- sh` → `security-events`에 Falco 이벤트 적재
- [ ] Falco JSON의 k8s 메타 → transform 리매핑 후 `kubernetes.namespace` 매핑 확인
- [ ] 노이즈 측정: 테스트 행위 없이 5분간 50건 이하
- [ ] events.log가 100MB 초과 시 자동 로테이트
- [ ] Override 적용 시 DS spec 변경 확인

---

## M4. Tetragon Feature (2일)

**핵심**: Reconciler 코드 변경 **없이** Feature 추가

**작업**:
- tetragon Feature (Priority 100) — stdout 모드
- TracingPolicy CRD를 Unstructured로 등록/GC
- OTel Node에 filelog/tetragon (stdout 경로) + k8sattributes 자동 매핑

**Exit Criteria**:
- [ ] **Reconciler 변경 없이** Tetragon DS 생성
- [ ] OTel ConfigMap에 `filelog/tetragon` 자동 추가
- [ ] TracingPolicy `container-escape-monitor` CRD 자동 생성
- [ ] 시나리오 B: Falco + Tetragon 양쪽 이벤트 확인 (교차검증)
- [ ] Tetragon 이벤트에 k8sattributes가 붙인 `kubernetes.namespace` 존재
- [ ] Status에 `TetragonReady` 조건

---

## M5. OSquery Feature (2일)

**작업**: osquery Feature (Priority 100) + 쿼리 팩 ConfigMap

**Exit Criteria**:
- [ ] OSquery DS + 쿼리 팩 CM 자동 생성
- [ ] `security-inventory`에 `system_info` 문서 유입 (**CTEM-SCOPE-01**)
- [ ] `listening_ports` 결과에 port/protocol/process 존재 (**CTEM-SCOPE-02**)
- [ ] OSquery 로그 로테이션 동작 확인

---

## M6. Trivy + CronJob (2일)

**작업**: Trivy Operator (Helm) + CronJob Watcher (TrivyFeature, `_id` 고정 upsert)

**Exit Criteria**:
- [ ] VulnerabilityReport CRD 생성 확인
- [ ] CronJob이 5분마다 CVE → `security-vuln` 적재 (중복 없음)
- [ ] `vulnerability.severity: CRITICAL` 필터링 가능 (**CTEM-PRI-01**)

---

## M7. MITRE 전체 실행 + 대시보드 (2-3일)

**작업**: 5개 시나리오 실행 + 대시보드 3개 + CTEM 체크리스트 통과

**Exit Criteria**:
- [ ] 5개 시나리오 중 4개+ 탐지
- [ ] B, C에서 교차검증 (Falco + Tetragon 양쪽) 성공
- [ ] Kibana 대시보드 3개 동작 (스크린샷)
- [ ] CTEM 체크리스트 (7.2절) **전체 Pass**

---

## M8. Feature 토글 + Override 최종 검증 (1일)

```bash
# 비활성화 → DS 삭제
kubectl patch securityagent poc-security -n security-system \
  --type=json -p '[{"op":"replace","path":"/spec/features/2/enabled","value":false}]'

# 재활성화 → DS 재생성
kubectl patch securityagent poc-security -n security-system \
  --type=json -p '[{"op":"replace","path":"/spec/features/2/enabled","value":true}]'

# Override: 공통 + 개별
kubectl patch securityagent poc-security -n security-system \
  --type=merge -p '{"spec":{"override":{
    "nodeAgent":{"tolerations":[{"operator":"Exists"}]},
    "falco":{"resources":{"limits":{"memory":"2Gi"}}}
  }}}'
```

**Exit Criteria**:
- [ ] Feature 토글 시 DS 생성/삭제
- [ ] 공통 Override → 모든 DS 반영
- [ ] 도구별 Override → 해당 DS만 변경
- [ ] TracingPolicy도 Feature 비활성화 시 삭제

---

## 일정 총괄

```
Week 1                    Week 2                    Week 3
───────────────────────────────────────────────────────────────
M0 ■                      M3 ■■■                    M6 ■■
 인프라 준비               Falco Feature             Trivy + CronJob
                          + 로테이션/노이즈
M1 ■■
 ES + Kibana              M4 ■■                     M7 ■■■
 + 컴포넌트 템플릿         Tetragon Feature          MITRE 전체
                          + TracingPolicy CRD        + 대시보드
M2 ■■■■                                              + CTEM 검증
 Operator Core            M5 ■■
 + OTel Pipeline           OSquery Feature           M8 ■
 + 무한루프 방지           + CTEM-SCOPE 검증          토글/Override
 + Finalizer                                         최종 검증
```

**총 예상 기간: 3주 (15 working days)**

---

# 14. 프로젝트 디렉터리 구조

```
security-operator/
├── cmd/
│   └── main.go                              # Feature import + 헬스체크 + 메트릭
│
├── api/v1alpha1/
│   ├── securityagent_types.go               # 배열 기반 CRD + ObservedGeneration
│   └── zz_generated.deepcopy.go
│
├── internal/controller/
│   ├── reconciler.go                        # Feature-agnostic + Finalizer + Predicate
│   ├── feature/
│   │   ├── feature.go                       # Feature 인터페이스 (4메서드)
│   │   ├── types.go                         # OTelReceiverConfig, FeatureCondition
│   │   ├── registry.go                      # 우선순위 기반 Registry
│   │   ├── store.go                         # DesiredStateStore (Unstructured 포함)
│   │   ├── otel_pipeline/feature.go         # Priority 10
│   │   ├── falco/feature.go                 # Priority 100 + 로테이션/룰 오버라이드
│   │   ├── tetragon/feature.go              # Priority 100 + stdout + TracingPolicy
│   │   ├── osquery/feature.go               # Priority 100 + Scope 전용 팩
│   │   └── trivy/feature.go                 # Priority 200 + CronJob upsert
│   ├── override/override.go                 # 2단계 Override
│   └── otel/config_builder.go               # OTel 합성 (severity 매핑 포함)
│
├── config/
│   ├── crd/bases/
│   ├── elasticsearch/
│   │   ├── elasticsearch.yaml
│   │   ├── kibana.yaml
│   │   └── index-templates.sh               # 컴포넌트 + 인덱스 템플릿
│   ├── falco/
│   │   └── falco_rules.local.yaml           # PoC 노이즈 제거
│   └── samples/
│       ├── securityagent_full.yaml
│       └── securityagent_minimal.yaml
│
├── test/
│   ├── pods.yaml                            # testbox + attacker + target-nginx
│   ├── tracing-policies/
│   │   └── container-escape-monitor.yaml
│   └── run-ctem-scenarios.sh                # 자동화 + Pass/Fail 판정
│
├── demo/
│   └── live-demo.sh                         # 1분 데모 스크립트
│
└── docs/
    └── ctem-mapping-results.md
```

---

# 15. 리스크 & 회피 전략

| # | 리스크 | 확률 | 영향 | 회피 전략 |
|---|--------|:---:|:---:|----------|
| R1 | OTel filelog가 도구별 JSON 파싱 실패 | 높음 | M3 | JSON 샘플 사전 수집 후 파서 테스트. 파싱 실패 시 raw body 적재 + ES ingest pipeline 보완 |
| R2 | k8sattributes가 Falco 파일 로그에 Pod 메타 못 붙임 | 높음 | M3 | 하이브리드: Falco=transform 리매핑, Tetragon=stdout+k8sattributes 자동 |
| R3 | Falco+Tetragon eBPF 공존 시 커널 이슈 | 낮음 | 치명 | AL2023/Ubuntu 6.1 사전 검증. 문제 시 Tetragon 먼저 제거 후 단독 테스트 |
| R4 | Trivy CronJob bulk insert 타임아웃 | 중간 | M6 | severity ≥ HIGH만 필터 + `_id` 고정으로 중복 방지 |
| R5 | Reconcile 무한 루프 | 중간 | M2 | GenerationChangedPredicate + ObservedGeneration 패턴 |
| R6 | RawExtension 디코딩 실패 | 낮음 | M2 | Feature별 strict validation + unknown field 무시 정책 |
| R7 | Falco 노이즈로 ES 폭발 | 높음 | M3 | PoC 전용 falco_rules.local.yaml + 5분 이벤트 수 측정 |
| R8 | 로그 로테이션 미설정으로 디스크 풀 | 중간 | M3 | Falco rotate max_size:100MB + OSquery rotate + 48시간 모니터링 |
| R9 | 시나리오 Pod에 바이너리 없어 탐지 실패 | 높음 | M7 | testbox(alpine)+attacker(netshoot) 역할 분리, 사전 바이너리 확인 |
| R10 | ES 매핑 충돌 (dot vs 객체) | 중간 | M1 | 객체 구조 + 컴포넌트 템플릿 + flattened 타입 |

---

# 16. PoC 완료 최종 체크리스트

## 기능

- [ ] `SecurityAgent` CRD 1개로 4개 센서 + OTel 파이프라인 자동 배치
- [ ] Feature 토글로 DaemonSet 생성/삭제
- [ ] Override로 리소스/tolerations 변경
- [ ] 새 Feature 추가 시 Reconciler 코드 변경 없음 (import 1줄)
- [ ] Status: PipelineReady, FalcoReady, TetragonReady, OSQueryReady, TrivyReady

## CTEM 매핑

- [ ] **Scope**: OSquery → `security-inventory`에 노드/포트/프로세스/커널모듈 인벤토리
- [ ] **Discovery**: Trivy → `security-vuln`에 CVE (ID/severity/fixedVersion)
- [ ] **Priority**: Trivy CVSS + Falco priority로 심각도 필터링
- [ ] **Validation**: MITRE 5개 중 4개+ 탐지 + 교차검증 2개+

## MITRE ATT&CK

- [ ] A: OSquery 인벤토리 수집 (Scope)
- [ ] B: T1059.004 Unix Shell — Falco ✅ Tetragon ✅
- [ ] C: T1552.001 + K8s API — Falco ✅ Tetragon ✅
- [ ] D: T1611 Container Escape — Falco ✅ Tetragon ✅ (TracingPolicy)
- [ ] E: T1053.003 Cron Persistence — Falco ✅ Tetragon ✅

## 아키텍처

- [ ] Feature-as-Plugin: 우선순위 기반 init() 자기등록 + import 1줄 확장
- [ ] 배열 기반 CRD: 스키마 변경 없이 새 도구 추가
- [ ] Override 2단계: 공통(nodeAgent) + 도구별
- [ ] OTel Config 자동 합성: Feature 추가/제거 시 ConfigMap 자동 갱신
- [ ] CTEM 용도별 ES 인덱스 3개: inventory / events / vuln
- [ ] k8s 메타: 하이브리드 (Falco=transform, Tetragon=k8sattributes)
- [ ] 무한 루프 방지: GenerationChangedPredicate + ObservedGeneration
- [ ] GC: OwnerReference(네임스페이스) + Finalizer(ClusterRole)
- [ ] 로그 로테이션: Falco 100MB×3, OSquery 50MB×3

## 산출물

- [ ] CTEM 매핑 검증 결과표
- [ ] Kibana 대시보드 스크린샷 3장
- [ ] ES 검증 쿼리 모음
- [ ] 테스트 자동화 스크립트 (test/run-ctem-scenarios.sh)
- [ ] 1분 데모 스크립트 (demo/live-demo.sh)