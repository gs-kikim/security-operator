#!/usr/bin/env bash
# CTEM Security Operator — MITRE ATT&CK Scenario Tests
# Tests 5 scenarios mapping to CTEM stages, querying ES for detections.
#
# Usage:
#   ES_URL=https://localhost:9200 NAMESPACE=security-system ./run-ctem-scenarios.sh
#
# Environment variables:
#   ES_URL      - Elasticsearch URL (default: https://localhost:9200)
#   NAMESPACE   - Kubernetes namespace (default: security-system)
#   ES_USER     - Elasticsearch username (default: elastic)
#   ES_PASS     - Elasticsearch password (default: read from secret)
#   WAIT_SECS   - Seconds to wait for detection after attack (default: 30)
#   SKIP_CLEANUP - Set to "true" to skip pod cleanup (default: false)
set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
ES_URL="${ES_URL:-https://localhost:9200}"
NAMESPACE="${NAMESPACE:-security-system}"
ES_USER="${ES_USER:-elastic}"
WAIT_SECS="${WAIT_SECS:-30}"
SKIP_CLEANUP="${SKIP_CLEANUP:-false}"

CURL_OPTS="-sk"
TESTBOX_POD="ctem-testbox"
ATTACKER_POD="attacker"
TIMESTAMP_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ─── Color output ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

# ─── Helper functions ─────────────────────────────────────────────────────────
log() {
  echo -e "${BLUE}[$(date -u +"%H:%M:%S")]${NC} $*"
}

pass() {
  local name="$1"
  local detail="${2:-}"
  echo -e "${GREEN}[PASS]${NC} ${name}"
  [ -n "${detail}" ] && echo "       ${detail}"
  PASS_COUNT=$((PASS_COUNT + 1))
  RESULTS+=("PASS: ${name}")
}

fail() {
  local name="$1"
  local detail="${2:-}"
  echo -e "${RED}[FAIL]${NC} ${name}"
  [ -n "${detail}" ] && echo "       ${detail}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  RESULTS+=("FAIL: ${name}")
}

wait_for_detection() {
  local secs="${1:-$WAIT_SECS}"
  log "Waiting ${secs}s for detection pipeline..."
  sleep "${secs}"
}

es_query() {
  local index="$1"
  local query="$2"
  curl ${CURL_OPTS} \
    -u "${ES_USER}:${ES_PASS}" \
    -X GET "${ES_URL}/${index}/_search" \
    -H "Content-Type: application/json" \
    -d "${query}"
}

es_count() {
  local index="$1"
  local query="$2"
  es_query "${index}" "${query}" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('hits',{}).get('total',{}).get('value',0))" 2>/dev/null || echo "0"
}

kubectl_exec() {
  local pod="$1"
  shift
  kubectl exec -n "${NAMESPACE}" "${pod}" -- "$@"
}

# ─── Prerequisite checks ──────────────────────────────────────────────────────
preflight_check() {
  log "Running preflight checks..."

  # Check kubectl
  if ! command -v kubectl &>/dev/null; then
    echo "ERROR: kubectl not found" >&2
    exit 1
  fi

  # Check ES_PASS
  if [ -z "${ES_PASS:-}" ]; then
    log "ES_PASS not set, reading from secret ctem-es-es-elastic-user..."
    ES_PASS=$(kubectl get secret -n "${NAMESPACE}" ctem-es-es-elastic-user \
      -o jsonpath='{.data.elastic}' 2>/dev/null | base64 -d 2>/dev/null || true)
    if [ -z "${ES_PASS}" ]; then
      echo "ERROR: Cannot read ES password. Set ES_PASS env var or ensure secret exists." >&2
      exit 1
    fi
  fi

  # Check test pods are running
  for pod in "${TESTBOX_POD}" "${ATTACKER_POD}"; do
    local status
    status=$(kubectl get pod -n "${NAMESPACE}" "${pod}" \
      -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    if [ "${status}" != "Running" ]; then
      echo "ERROR: Pod ${pod} is not Running (status: ${status}). Apply test/pods.yaml first." >&2
      exit 1
    fi
  done

  # Check ES connectivity
  local es_health
  es_health=$(curl ${CURL_OPTS} -u "${ES_USER}:${ES_PASS}" \
    "${ES_URL}/_cluster/health" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unreachable")
  if [ "${es_health}" = "unreachable" ]; then
    echo "ERROR: Cannot connect to Elasticsearch at ${ES_URL}" >&2
    exit 1
  fi
  log "ES cluster health: ${es_health}"

  log "Preflight OK"
}

# ─── Scenario A: Scope Verification (OSquery) ─────────────────────────────────
# CTEM Stage: Scope
# Check that OSquery inventory data is flowing to ES
scenario_a() {
  echo ""
  echo -e "${YELLOW}=== Scenario A: Scope Verification (OSquery → security-inventory) ===${NC}"
  echo "CTEM Stage: Scope | CTEM-SCOPE-01"

  log "Querying security-inventory for OSquery data..."
  local count
  count=$(es_count "security-inventory" '{
    "query": {
      "bool": {
        "must": [
          { "term": { "labels.security_tool": "osquery" } },
          { "range": { "@timestamp": { "gte": "now-1h" } } }
        ]
      }
    },
    "size": 0
  }')

  log "Found ${count} OSquery events in security-inventory"

  if [ "${count}" -gt "0" ]; then
    # Check for specific query types
    local proc_count
    proc_count=$(es_count "security-inventory" '{
      "query": {
        "bool": {
          "must": [
            { "term": { "labels.security_tool": "osquery" } },
            { "term": { "osquery.name": "running_processes" } },
            { "range": { "@timestamp": { "gte": "now-1h" } } }
          ]
        }
      },
      "size": 0
    }')
    pass "CTEM-SCOPE-01: OSquery inventory flowing to ES" \
      "${count} events total, ${proc_count} process inventory events"
  else
    fail "CTEM-SCOPE-01: No OSquery data in security-inventory (last 1h)" \
      "Check OSquery DaemonSet and OTel pipeline status"
  fi
}

# ─── Scenario B: T1059.004 — Command Shell Execution ──────────────────────────
# CTEM Stage: Validation
# Technique: T1059.004 Unix Shell
scenario_b() {
  echo ""
  echo -e "${YELLOW}=== Scenario B: T1059.004 — Command Shell Execution in Container ===${NC}"
  echo "CTEM Stage: Validation | CTEM-VAL-01"

  log "Executing shell commands in container (T1059.004)..."
  # Trigger Falco rule: "Terminal shell in container"
  kubectl_exec "${TESTBOX_POD}" sh -c \
    'id; uname -a; cat /etc/os-release; ls /bin; echo "T1059.004-test"' \
    >/dev/null 2>&1 || true

  # Trigger bash from sh (spawning new process)
  kubectl_exec "${TESTBOX_POD}" sh -c \
    'sh -c "sh -c \"echo nested-shell-test\""' \
    >/dev/null 2>&1 || true

  wait_for_detection

  local count
  count=$(es_count "security-events" "{
    \"query\": {
      \"bool\": {
        \"must\": [
          { \"range\": { \"@timestamp\": { \"gte\": \"${TIMESTAMP_START}\" } } }
        ],
        \"should\": [
          { \"match_phrase\": { \"rule.name\": \"Terminal shell in container\" } },
          { \"match_phrase\": { \"rule.name\": \"Spawning a shell\" } },
          { \"term\": { \"process.name\": \"sh\" } }
        ],
        \"minimum_should_match\": 1
      }
    },
    \"size\": 0
  }")

  log "Found ${count} shell-related detection events"
  if [ "${count}" -gt "0" ]; then
    pass "CTEM-VAL-01: T1059.004 detected (shell execution in container)" \
      "${count} detection events"
  else
    fail "CTEM-VAL-01: T1059.004 NOT detected" \
      "Check Falco rules for 'Terminal shell in container' and OTel pipeline"
  fi
}

# ─── Scenario C: T1552.001 — Credential Access ────────────────────────────────
# CTEM Stage: Validation
# Technique: T1552.001 Credentials in Files + K8s API token
scenario_c() {
  echo ""
  echo -e "${YELLOW}=== Scenario C: T1552.001 — Credential Access ===${NC}"
  echo "CTEM Stage: Validation | CTEM-VAL-02"

  # C-1: Read sensitive file (/etc/shadow)
  log "C-1: Attempting to read /etc/shadow (T1552.001)..."
  kubectl_exec "${TESTBOX_POD}" sh -c \
    'cat /etc/shadow 2>/dev/null || echo "shadow-read-attempted"' \
    >/dev/null 2>&1 || true

  # C-2: Access K8s API token from attacker pod
  log "C-2: Accessing K8s service account token..."
  kubectl_exec "${ATTACKER_POD}" sh -c \
    'cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 50 || echo "token-read-attempted"' \
    >/dev/null 2>&1 || true

  # Try to call K8s API with the token
  kubectl_exec "${ATTACKER_POD}" sh -c \
    'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces 2>/dev/null | head -c 100 || true' \
    >/dev/null 2>&1 || true

  wait_for_detection

  local count
  count=$(es_count "security-events" "{
    \"query\": {
      \"bool\": {
        \"must\": [
          { \"range\": { \"@timestamp\": { \"gte\": \"${TIMESTAMP_START}\" } } }
        ],
        \"should\": [
          { \"match_phrase\": { \"rule.name\": \"Read sensitive file untouched\" } },
          { \"match_phrase\": { \"rule.name\": \"Read sensitive file trusted after startup\" } },
          { \"match_phrase\": { \"rule.name\": \"Contact K8S API Server From Container\" } },
          { \"match_phrase\": { \"output\": \"shadow\" } },
          { \"match_phrase\": { \"output\": \"serviceaccount\" } }
        ],
        \"minimum_should_match\": 1
      }
    },
    \"size\": 0
  }")

  log "Found ${count} credential-access detection events"
  if [ "${count}" -gt "0" ]; then
    pass "CTEM-VAL-02: T1552.001 detected (credential access)" \
      "${count} detection events"
  else
    fail "CTEM-VAL-02: T1552.001 NOT detected" \
      "Check Falco rules for sensitive file reads and K8s API contact"
  fi
}

# ─── Scenario D: T1611 — Container Escape ─────────────────────────────────────
# CTEM Stage: Validation
# Technique: T1611 Escape to Host
scenario_d() {
  echo ""
  echo -e "${YELLOW}=== Scenario D: T1611 — Container Escape ===${NC}"
  echo "CTEM Stage: Validation | CTEM-VAL-03"

  # D-1: Mount proc filesystem
  log "D-1: Attempting proc mount (T1611)..."
  kubectl_exec "${TESTBOX_POD}" sh -c \
    'mkdir -p /tmp/hostproc && mount -t proc proc /tmp/hostproc 2>/dev/null || echo "mount-attempted"' \
    >/dev/null 2>&1 || true

  # D-2: Read host process info through /host/proc
  log "D-2: Accessing host /proc through volume mount..."
  kubectl_exec "${TESTBOX_POD}" sh -c \
    'ls /host/proc/ 2>/dev/null | head -20 || echo "hostproc-read-attempted"' \
    >/dev/null 2>&1 || true

  # D-3: nsenter attempt from attacker pod
  log "D-3: Attempting nsenter from attacker pod..."
  kubectl_exec "${ATTACKER_POD}" sh -c \
    'nsenter --mount=/host/proc/1/ns/mnt -- ls /etc/ 2>/dev/null | head -5 || echo "nsenter-attempted"' \
    >/dev/null 2>&1 || true

  wait_for_detection

  local count
  count=$(es_count "security-events" "{
    \"query\": {
      \"bool\": {
        \"must\": [
          { \"range\": { \"@timestamp\": { \"gte\": \"${TIMESTAMP_START}\" } } }
        ],
        \"should\": [
          { \"match_phrase\": { \"rule.name\": \"Launch Privileged Container\" } },
          { \"match_phrase\": { \"rule.name\": \"Container Escape via Privileged Pod\" } },
          { \"match_phrase\": { \"rule.name\": \"Detect Mount\" } },
          { \"term\": { \"process.name\": \"nsenter\" } },
          { \"match_phrase\": { \"output\": \"nsenter\" } },
          { \"match_phrase\": { \"output\": \"mount\" } }
        ],
        \"minimum_should_match\": 1
      }
    },
    \"size\": 0
  }")

  # Also check Tetragon detections (setns syscall tracking)
  local tet_count
  tet_count=$(es_count "security-events" "{
    \"query\": {
      \"bool\": {
        \"must\": [
          { \"term\": { \"labels.security_tool\": \"tetragon\" } },
          { \"range\": { \"@timestamp\": { \"gte\": \"${TIMESTAMP_START}\" } } }
        ],
        \"should\": [
          { \"match_phrase\": { \"output\": \"setns\" } },
          { \"match_phrase\": { \"output\": \"sys_mount\" } }
        ],
        \"minimum_should_match\": 1
      }
    },
    \"size\": 0
  }")

  local total=$((count + tet_count))
  log "Found ${count} Falco + ${tet_count} Tetragon container-escape detection events"
  if [ "${total}" -gt "0" ]; then
    pass "CTEM-VAL-03: T1611 detected (container escape attempt)" \
      "Falco: ${count}, Tetragon: ${tet_count} events"
  else
    fail "CTEM-VAL-03: T1611 NOT detected" \
      "Check Falco + Tetragon detections for mount/nsenter syscalls"
  fi
}

# ─── Scenario E: T1053.003 — Cron Job Scheduling ─────────────────────────────
# CTEM Stage: Validation
# Technique: T1053.003 Cron
scenario_e() {
  echo ""
  echo -e "${YELLOW}=== Scenario E: T1053.003 — Cron Job Scheduling ===${NC}"
  echo "CTEM Stage: Validation | CTEM-VAL-04"

  log "E: Attempting to schedule cron job in container (T1053.003)..."
  # Write to crontab
  kubectl_exec "${TESTBOX_POD}" sh -c \
    '(crontab -l 2>/dev/null; echo "* * * * * echo ctem-test") | crontab - 2>/dev/null || echo "crontab-attempted"' \
    >/dev/null 2>&1 || true

  # Write to cron directory
  kubectl_exec "${TESTBOX_POD}" sh -c \
    'echo "#!/bin/sh" > /tmp/ctem-cron.sh && chmod +x /tmp/ctem-cron.sh' \
    >/dev/null 2>&1 || true

  kubectl_exec "${TESTBOX_POD}" sh -c \
    'cp /tmp/ctem-cron.sh /etc/cron.d/ctem-test 2>/dev/null || echo "cron.d-write-attempted"' \
    >/dev/null 2>&1 || true

  # Try to spawn crond
  kubectl_exec "${TESTBOX_POD}" sh -c \
    'crond 2>/dev/null || cron 2>/dev/null || echo "crond-spawn-attempted"' \
    >/dev/null 2>&1 || true

  wait_for_detection

  local count
  count=$(es_count "security-events" "{
    \"query\": {
      \"bool\": {
        \"must\": [
          { \"range\": { \"@timestamp\": { \"gte\": \"${TIMESTAMP_START}\" } } }
        ],
        \"should\": [
          { \"match_phrase\": { \"rule.name\": \"Modify Shell Configuration File\" } },
          { \"match_phrase\": { \"rule.name\": \"Schedule Cron Jobs\" } },
          { \"match_phrase\": { \"rule.name\": \"Write below etc\" } },
          { \"term\": { \"process.name\": \"crontab\" } },
          { \"term\": { \"process.name\": \"crond\" } },
          { \"match_phrase\": { \"output\": \"crontab\" } },
          { \"match_phrase\": { \"output\": \"cron\" } }
        ],
        \"minimum_should_match\": 1
      }
    },
    \"size\": 0
  }")

  log "Found ${count} cron-related detection events"
  if [ "${count}" -gt "0" ]; then
    pass "CTEM-VAL-04: T1053.003 detected (cron scheduling)" \
      "${count} detection events"
  else
    fail "CTEM-VAL-04: T1053.003 NOT detected" \
      "Check Falco rules for crontab/cron.d modifications"
  fi
}

# ─── Scenario: Trivy CVE Discovery ────────────────────────────────────────────
# CTEM Stage: Discovery + Prioritization
scenario_trivy() {
  echo ""
  echo -e "${YELLOW}=== Scenario: CVE Discovery + Prioritization (Trivy → security-vuln) ===${NC}"
  echo "CTEM Stage: Discovery | CTEM-DISC-01, CTEM-PRI-01"

  log "Querying security-vuln for Trivy scan results..."
  local count
  count=$(es_count "security-vuln" '{
    "query": {
      "bool": {
        "must": [
          { "range": { "@timestamp": { "gte": "now-24h" } } }
        ]
      }
    },
    "size": 0
  }')

  log "Found ${count} vulnerability records in security-vuln"
  if [ "${count}" -gt "0" ]; then
    # Check for nginx CVEs (expected target-nginx pod)
    local nginx_count
    nginx_count=$(es_count "security-vuln" '{
      "query": {
        "bool": {
          "must": [
            { "term": { "workload.name": "target-nginx" } },
            { "range": { "@timestamp": { "gte": "now-24h" } } }
          ]
        }
      },
      "size": 0
    }')

    # Check for CRITICAL severity
    local crit_count
    crit_count=$(es_count "security-vuln" '{
      "query": {
        "bool": {
          "must": [
            { "term": { "vulnerability.severity": "CRITICAL" } },
            { "range": { "@timestamp": { "gte": "now-24h" } } }
          ]
        }
      },
      "size": 0
    }')

    pass "CTEM-DISC-01: CVE data flowing to security-vuln" \
      "Total: ${count}, nginx CVEs: ${nginx_count}, CRITICAL: ${crit_count}"
  else
    fail "CTEM-DISC-01: No CVE data in security-vuln (last 24h)" \
      "Check Trivy CronJob execution status and VulnerabilityReport CRDs"
  fi
}

# ─── Cross-tool validation ─────────────────────────────────────────────────────
scenario_cross_validate() {
  echo ""
  echo -e "${YELLOW}=== Cross-tool Validation: Falco + Tetragon Coverage ===${NC}"
  echo "CTEM Stage: Validation | CTEM-VAL-05"

  local falco_count tetragon_count
  falco_count=$(es_count "security-events" "{
    \"query\": {
      \"bool\": {
        \"must\": [
          { \"term\": { \"labels.security_tool\": \"falco\" } },
          { \"range\": { \"@timestamp\": { \"gte\": \"${TIMESTAMP_START}\" } } }
        ]
      }
    },
    \"size\": 0
  }")

  tetragon_count=$(es_count "security-events" "{
    \"query\": {
      \"bool\": {
        \"must\": [
          { \"term\": { \"labels.security_tool\": \"tetragon\" } },
          { \"range\": { \"@timestamp\": { \"gte\": \"${TIMESTAMP_START}\" } } }
        ]
      }
    },
    \"size\": 0
  }")

  log "Falco events: ${falco_count}, Tetragon events: ${tetragon_count}"
  if [ "${falco_count}" -gt "0" ] && [ "${tetragon_count}" -gt "0" ]; then
    pass "CTEM-VAL-05: Both Falco and Tetragon producing events" \
      "Falco: ${falco_count}, Tetragon: ${tetragon_count}"
  elif [ "${falco_count}" -gt "0" ]; then
    fail "CTEM-VAL-05: Tetragon not producing events (Falco OK)" \
      "Check Tetragon DaemonSet and OTel pipeline"
  elif [ "${tetragon_count}" -gt "0" ]; then
    fail "CTEM-VAL-05: Falco not producing events (Tetragon OK)" \
      "Check Falco DaemonSet and file output configuration"
  else
    fail "CTEM-VAL-05: Neither Falco nor Tetragon producing events" \
      "Check both DaemonSets and OTel pipeline status"
  fi
}

# ─── Cleanup ──────────────────────────────────────────────────────────────────
cleanup() {
  if [ "${SKIP_CLEANUP}" = "true" ]; then
    log "Skipping cleanup (SKIP_CLEANUP=true)"
    return
  fi
  log "Cleaning up test artifacts..."
  kubectl_exec "${TESTBOX_POD}" sh -c \
    'crontab -r 2>/dev/null; rm -f /etc/cron.d/ctem-test /tmp/ctem-cron.sh /tmp/hostproc 2>/dev/null; true' \
    >/dev/null 2>&1 || true
}

# ─── Summary report ───────────────────────────────────────────────────────────
print_summary() {
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  CTEM Security Operator — Test Results Summary"
  echo "═══════════════════════════════════════════════════════════"
  for result in "${RESULTS[@]}"; do
    if [[ "${result}" == PASS* ]]; then
      echo -e "  ${GREEN}${result}${NC}"
    else
      echo -e "  ${RED}${result}${NC}"
    fi
  done
  echo "───────────────────────────────────────────────────────────"
  echo -e "  Total: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
  echo "═══════════════════════════════════════════════════════════"
  echo ""

  if [ "${FAIL_COUNT}" -gt "0" ]; then
    exit 1
  fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  CTEM Security Operator — MITRE ATT&CK Scenario Tests"
  echo "  ES: ${ES_URL}"
  echo "  Namespace: ${NAMESPACE}"
  echo "  Start time: ${TIMESTAMP_START}"
  echo "═══════════════════════════════════════════════════════════"

  preflight_check

  # Run all scenarios
  scenario_a          # Scope: OSquery inventory check
  scenario_b          # T1059.004: Shell execution
  scenario_c          # T1552.001: Credential access
  scenario_d          # T1611: Container escape
  scenario_e          # T1053.003: Cron scheduling
  scenario_trivy      # Discovery: CVE data
  scenario_cross_validate  # Cross-tool coverage

  cleanup
  print_summary
}

main "$@"
