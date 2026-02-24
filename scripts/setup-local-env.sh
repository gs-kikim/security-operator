#!/usr/bin/env bash
# =============================================================================
# CTEM Security Operator — 로컬 환경 전체 구성 스크립트
#
# 사전 요구사항:
#   - Docker Desktop (4GB+ 메모리 할당)
#   - kubectl
#   - kind (없으면 자동 설치)
#   - make, go 1.26+
#
# 사용법:
#   ./scripts/setup-local-env.sh          # 전체 구성
#   ./scripts/setup-local-env.sh --skip-build  # 이미지 빌드 생략 (재배포 시)
#   ./scripts/setup-local-env.sh --teardown    # 환경 삭제
#
# 예상 소요 시간: 약 10~15분 (이미지 풀 상태에 따라 다름)
# =============================================================================
set -euo pipefail

# ─── 설정 ────────────────────────────────────────────────────────────────────
CLUSTER_NAME="ctem-local"
NAMESPACE="security-system"
OPERATOR_IMG="ctem/security-operator:dev"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIND="${KIND:-$(command -v kind 2>/dev/null || echo "")}"
SKIP_BUILD="${SKIP_BUILD:-false}"

# ─── 색상 ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

step() { echo -e "\n${BLUE}${BOLD}▶ $1${NC}"; }
info() { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; exit 1; }

# ─── Teardown ────────────────────────────────────────────────────────────────
if [ "${1:-}" = "--teardown" ]; then
    step "환경 삭제"
    ${KIND} delete cluster --name "${CLUSTER_NAME}" 2>/dev/null && info "Kind 클러스터 삭제 완료" || warn "클러스터가 없습니다"
    exit 0
fi

if [ "${1:-}" = "--skip-build" ]; then
    SKIP_BUILD=true
fi

# ─── Step 0: 사전 요구사항 확인 ──────────────────────────────────────────────
step "Step 0/8: 사전 요구사항 확인"

command -v docker &>/dev/null || fail "Docker가 설치되어 있지 않습니다"
docker info &>/dev/null || fail "Docker가 실행 중이 아닙니다. Docker Desktop을 시작하세요"
info "Docker OK"

command -v kubectl &>/dev/null || fail "kubectl이 설치되어 있지 않습니다"
info "kubectl OK"

command -v go &>/dev/null || fail "Go가 설치되어 있지 않습니다"
info "Go $(go version | awk '{print $3}')"

if [ -z "${KIND}" ]; then
    warn "kind가 없습니다. 설치합니다..."
    go install sigs.k8s.io/kind@latest
    KIND="$(go env GOPATH)/bin/kind"
fi
info "kind $(${KIND} version)"

# Docker 메모리 확인 (macOS)
if [ "$(uname)" = "Darwin" ]; then
    DOCKER_MEM=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo "0")
    DOCKER_MEM_GB=$((DOCKER_MEM / 1073741824))
    if [ "${DOCKER_MEM_GB}" -lt 4 ]; then
        warn "Docker 메모리가 ${DOCKER_MEM_GB}GB입니다. 4GB 이상 권장합니다"
        warn "Docker Desktop → Settings → Resources → Memory에서 조정하세요"
    else
        info "Docker 메모리: ${DOCKER_MEM_GB}GB"
    fi
fi

# ─── Step 1: Kind 클러스터 생성 ──────────────────────────────────────────────
step "Step 1/8: Kind 클러스터 생성"

if ${KIND} get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    info "클러스터 '${CLUSTER_NAME}'이 이미 존재합니다. 재사용합니다"
    kubectl cluster-info --context "kind-${CLUSTER_NAME}" &>/dev/null || fail "클러스터에 접속할 수 없습니다"
else
    # Kind 설정: extraMounts로 /var/log/security 공유 (OTel filelog 수집용)
    # NOTE: ServerSideApply는 K8s 1.22+ GA이므로 feature-gate 불필요
    cat <<'KINDCONFIG' | ${KIND} create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      # 보안 도구 로그 경로 — 호스트 ↔ 노드 공유
      - hostPath: /tmp/ctem-security-logs
        containerPath: /var/log/security
KINDCONFIG
    info "클러스터 '${CLUSTER_NAME}' 생성 완료"
fi

kubectl config use-context "kind-${CLUSTER_NAME}"

# ─── Step 2: Namespace 생성 ──────────────────────────────────────────────────
step "Step 2/8: Namespace 생성"

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
info "namespace/${NAMESPACE}"

# ─── Step 3: ECK (Elastic Cloud on Kubernetes) 설치 ──────────────────────────
step "Step 3/8: ECK Operator 설치 (Elasticsearch + Kibana)"

# ECK CRD + Operator 설치
if kubectl get crd elasticsearches.elasticsearch.k8s.elastic.co &>/dev/null; then
    info "ECK CRD가 이미 설치되어 있습니다"
else
    kubectl create -f https://download.elastic.co/downloads/eck/2.11.1/crds.yaml
    kubectl apply -f https://download.elastic.co/downloads/eck/2.11.1/operator.yaml
    info "ECK Operator 설치 완료"

    echo -n "  ECK Operator 준비 대기"
    kubectl wait --for=condition=Ready pod/elastic-operator-0 \
        -n elastic-system --timeout=180s &>/dev/null
    echo ""
    info "ECK Operator Ready"
fi

# Elasticsearch 배포
kubectl apply -f "${PROJECT_ROOT}/config/elasticsearch/elasticsearch.yaml"
info "Elasticsearch CR 적용"

# Kibana 배포
kubectl apply -f "${PROJECT_ROOT}/config/elasticsearch/kibana.yaml"
info "Kibana CR 적용"

# ES가 Ready 될 때까지 대기
echo -n "  Elasticsearch 준비 대기 (1~3분 소요)"
for i in $(seq 1 180); do
    PHASE=$(kubectl get elasticsearch ctem-es -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Pending")
    if [ "${PHASE}" = "Ready" ]; then
        echo ""
        break
    fi
    echo -n "."
    sleep 2
done
ES_PHASE=$(kubectl get elasticsearch ctem-es -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
if [ "${ES_PHASE}" = "Ready" ]; then
    info "Elasticsearch Ready"
else
    warn "Elasticsearch 상태: ${ES_PHASE} (아직 준비 중일 수 있습니다. 계속 진행합니다)"
fi

# ES 비밀번호 조회
ES_PASSWORD=$(kubectl get secret ctem-es-es-elastic-user -n "${NAMESPACE}" \
    -o jsonpath='{.data.elastic}' 2>/dev/null | base64 -d 2>/dev/null || echo "")
if [ -n "${ES_PASSWORD}" ]; then
    info "ES 비밀번호 확인 완료 (elastic user)"
else
    warn "ES 비밀번호를 아직 읽을 수 없습니다. ES 준비 후 재시도하세요"
fi

# ─── Step 4: ES 인덱스 템플릿 설정 ──────────────────────────────────────────
step "Step 4/8: ES 인덱스 템플릿 설정"

if [ -n "${ES_PASSWORD}" ]; then
    # ES 서비스로 port-forward (백그라운드)
    kubectl port-forward -n "${NAMESPACE}" svc/ctem-es-es-http 9200:9200 &>/dev/null &
    PF_PID=$!
    sleep 3

    chmod +x "${PROJECT_ROOT}/config/elasticsearch/index-templates.sh"
    "${PROJECT_ROOT}/config/elasticsearch/index-templates.sh" \
        "https://localhost:9200" "elastic" "${ES_PASSWORD}" && \
        info "인덱스 템플릿 생성 완료" || \
        warn "인덱스 템플릿 생성 실패 (ES가 아직 준비 중일 수 있습니다)"

    kill ${PF_PID} 2>/dev/null || true
else
    warn "ES 비밀번호가 없어 인덱스 템플릿 설정을 건너뜁니다"
    warn "ES 준비 후 수동 실행: ./config/elasticsearch/index-templates.sh"
fi

# ─── Step 5: Trivy Operator 설치 (VulnerabilityReport CRD) ──────────────────
step "Step 5/8: Trivy Operator 설치"

if kubectl get crd vulnerabilityreports.aquasecurity.github.io &>/dev/null; then
    info "Trivy Operator CRD가 이미 설치되어 있습니다"
else
    # Helm으로 Trivy Operator 설치
    if command -v helm &>/dev/null; then
        helm repo add aqua https://aquasecurity.github.io/helm-charts/ 2>/dev/null || true
        helm repo update aqua 2>/dev/null || true
        helm upgrade --install trivy-operator aqua/trivy-operator \
            --namespace trivy-system --create-namespace \
            --set trivy.ignoreUnfixed=true \
            --wait --timeout 3m 2>/dev/null && \
            info "Trivy Operator 설치 완료 (Helm)" || \
            warn "Trivy Operator Helm 설치 실패"
    else
        warn "Helm이 없습니다. Trivy Operator는 수동 설치가 필요합니다"
        warn "  brew install helm && helm install trivy-operator aqua/trivy-operator -n trivy-system --create-namespace"
    fi
fi

# ─── Step 6: Operator 이미지 빌드 및 배포 ────────────────────────────────────
step "Step 6/8: Security Operator 빌드 및 배포"

cd "${PROJECT_ROOT}"

if [ "${SKIP_BUILD}" = "true" ]; then
    info "이미지 빌드 건너뜀 (--skip-build)"
else
    make docker-build IMG="${OPERATOR_IMG}" 2>&1 | tail -3
    info "Docker 이미지 빌드 완료: ${OPERATOR_IMG}"
fi

# Kind에 이미지 로드
${KIND} load docker-image "${OPERATOR_IMG}" --name "${CLUSTER_NAME}"
info "Kind에 이미지 로드 완료"

# CRD 설치 + Operator 배포
make install 2>&1 | tail -2
info "CRD 설치 완료"

make deploy IMG="${OPERATOR_IMG}" 2>&1 | tail -3
info "Operator 배포 완료"

# Operator Pod 준비 대기
echo -n "  Operator Pod 준비 대기"
kubectl wait --for=condition=Available deployment/security-operator-controller-manager \
    -n security-operator-system --timeout=120s &>/dev/null && echo "" || echo ""
info "Operator Pod Ready"

# ─── Step 7: SecurityAgent CR 적용 ──────────────────────────────────────────
step "Step 7/8: SecurityAgent CR 적용"

kubectl apply -f "${PROJECT_ROOT}/config/samples/security_v1alpha1_securityagent.yaml"
info "SecurityAgent CR 적용 완료"

echo -n "  리소스 생성 대기"
sleep 10
echo ""

# 생성된 리소스 확인
echo ""
echo -e "  ${BOLD}생성된 리소스:${NC}"
echo "  ──────────────────────────────────"
for kind in daemonset deployment cronjob configmap serviceaccount; do
    COUNT=$(kubectl get ${kind} -n "${NAMESPACE}" -l app.kubernetes.io/managed-by=security-operator --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [ "${COUNT}" -gt "0" ]; then
        echo -e "  ${GREEN}${kind}:${NC} ${COUNT}개"
        kubectl get ${kind} -n "${NAMESPACE}" -l app.kubernetes.io/managed-by=security-operator --no-headers 2>/dev/null | while read line; do
            echo "    - $(echo $line | awk '{print $1}')"
        done
    fi
done

# ─── Step 8: 테스트 Pod 배포 ────────────────────────────────────────────────
step "Step 8/8: MITRE ATT&CK 테스트 Pod 배포"

kubectl apply -f "${PROJECT_ROOT}/test/pods.yaml"
info "테스트 Pod 배포 완료 (ctem-testbox, attacker, target-nginx)"

# ─── 완료 ────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e " ${GREEN}${BOLD} 환경 구성 완료!${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo -e " ${BOLD}클러스터 정보${NC}"
echo "   Kind cluster : ${CLUSTER_NAME}"
echo "   Context      : kind-${CLUSTER_NAME}"
echo "   Namespace    : ${NAMESPACE}"
echo ""
echo -e " ${BOLD}접속 정보${NC}"
if [ -n "${ES_PASSWORD}" ]; then
echo "   ES password  : ${ES_PASSWORD}"
fi
echo ""
echo -e " ${BOLD}확인 명령어${NC}"
echo "   # Operator 로그 확인"
echo "   kubectl logs -f deploy/security-operator-controller-manager \\"
echo "     -n security-operator-system"
echo ""
echo "   # SecurityAgent 상태 확인"
echo "   kubectl get securityagent -n ${NAMESPACE}"
echo "   kubectl describe securityagent ctem-security-agent -n ${NAMESPACE}"
echo ""
echo "   # 생성된 리소스 확인"
echo "   kubectl get ds,deploy,cronjob,cm -n ${NAMESPACE} \\"
echo "     -l app.kubernetes.io/managed-by=security-operator"
echo ""
echo "   # ES 포트포워딩"
echo "   kubectl port-forward -n ${NAMESPACE} svc/ctem-es-es-http 9200:9200"
echo ""
echo "   # Kibana 포트포워딩"
echo "   kubectl port-forward -n ${NAMESPACE} svc/ctem-kibana-kb-http 5601:5601"
echo ""
echo "   # CTEM 시나리오 테스트 실행"
echo "   kubectl port-forward -n ${NAMESPACE} svc/ctem-es-es-http 9200:9200 &"
echo "   ES_URL=https://localhost:9200 ES_PASS='${ES_PASSWORD}' \\"
echo "     ./test/run-ctem-scenarios.sh"
echo ""
echo "   # 환경 삭제"
echo "   ./scripts/setup-local-env.sh --teardown"
echo ""
echo "═══════════════════════════════════════════════════════════════"
