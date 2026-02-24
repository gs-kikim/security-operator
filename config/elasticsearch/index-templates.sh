#!/usr/bin/env bash
# ES Index Templates setup for CTEM Security Operator
# Usage: ./index-templates.sh [ES_URL] [ES_USER] [ES_PASS]
# Default ES_URL: https://localhost:9200
set -euo pipefail

ES_URL="${1:-https://localhost:9200}"
ES_USER="${2:-}"
ES_PASS="${3:-}"

CURL_OPTS="-sk --fail"
if [ -n "$ES_USER" ] && [ -n "$ES_PASS" ]; then
  CURL_OPTS="$CURL_OPTS -u ${ES_USER}:${ES_PASS}"
fi

echo "Setting up ES index templates at ${ES_URL}..."

# ─── Component Template: security-common (shared fields) ─────────────────────
echo "Creating component template: security-common"
curl ${CURL_OPTS} -X PUT "${ES_URL}/_component_template/security-common" \
  -H "Content-Type: application/json" \
  -d '{
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "labels": {
          "properties": {
            "security_tool": { "type": "keyword" },
            "ctem_stage":     { "type": "keyword" },
            "cluster":        { "type": "keyword" },
            "environment":    { "type": "keyword" }
          }
        },
        "event": {
          "properties": {
            "kind":     { "type": "keyword" },
            "category": { "type": "keyword" },
            "type":     { "type": "keyword" },
            "severity": { "type": "keyword" },
            "outcome":  { "type": "keyword" },
            "action":   { "type": "keyword" },
            "dataset":  { "type": "keyword" },
            "module":   { "type": "keyword" }
          }
        },
        "kubernetes": {
          "properties": {
            "namespace":    { "type": "keyword" },
            "pod": {
              "properties": {
                "name": { "type": "keyword" },
                "uid":  { "type": "keyword" }
              }
            },
            "container": {
              "properties": {
                "name":  { "type": "keyword" },
                "image": { "type": "keyword" }
              }
            },
            "node": {
              "properties": {
                "name": { "type": "keyword" }
              }
            },
            "labels": { "type": "flattened" }
          }
        },
        "container": {
          "properties": {
            "id":      { "type": "keyword" },
            "name":    { "type": "keyword" },
            "image": {
              "properties": {
                "name": { "type": "keyword" },
                "tag":  { "type": "keyword" }
              }
            },
            "runtime": { "type": "keyword" }
          }
        }
      }
    },
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    }
  }
}'
echo ""

# ─── Index Template: security-events (Falco + Tetragon) ──────────────────────
echo "Creating index template: security-events"
curl ${CURL_OPTS} -X PUT "${ES_URL}/_index_template/security-events" \
  -H "Content-Type: application/json" \
  -d '{
  "index_patterns": ["security-events*"],
  "composed_of": ["security-common"],
  "priority": 200,
  "template": {
    "mappings": {
      "properties": {
        "rule": {
          "properties": {
            "name":     { "type": "keyword" },
            "priority": { "type": "keyword" },
            "tags":     { "type": "keyword" },
            "source":   { "type": "keyword" }
          }
        },
        "output": {
          "type": "text",
          "fields": {
            "keyword": { "type": "keyword", "ignore_above": 1024 }
          }
        },
        "output_fields": {
          "type": "flattened"
        },
        "process": {
          "properties": {
            "pid":        { "type": "long" },
            "ppid":       { "type": "long" },
            "name":       { "type": "keyword" },
            "executable": { "type": "keyword" },
            "args":       { "type": "keyword" },
            "command_line": {
              "type": "text",
              "fields": {
                "keyword": { "type": "keyword", "ignore_above": 512 }
              }
            },
            "user": {
              "properties": {
                "name": { "type": "keyword" },
                "id":   { "type": "keyword" }
              }
            },
            "working_directory": { "type": "keyword" }
          }
        },
        "parent": {
          "properties": {
            "pid":        { "type": "long" },
            "name":       { "type": "keyword" },
            "executable": { "type": "keyword" },
            "args":       { "type": "keyword" }
          }
        },
        "file": {
          "properties": {
            "path":      { "type": "keyword" },
            "directory": { "type": "keyword" },
            "name":      { "type": "keyword" },
            "extension": { "type": "keyword" }
          }
        },
        "network": {
          "properties": {
            "direction": { "type": "keyword" },
            "protocol":  { "type": "keyword" }
          }
        },
        "source": {
          "properties": {
            "ip":   { "type": "ip" },
            "port": { "type": "integer" }
          }
        },
        "destination": {
          "properties": {
            "ip":   { "type": "ip" },
            "port": { "type": "integer" }
          }
        },
        "mitre": {
          "properties": {
            "technique": { "type": "keyword" },
            "tactic":    { "type": "keyword" }
          }
        },
        "syscall": {
          "properties": {
            "name": { "type": "keyword" },
            "args": { "type": "flattened" }
          }
        }
      }
    }
  }
}'
echo ""

# ─── Index Template: security-inventory (OSquery) ────────────────────────────
echo "Creating index template: security-inventory"
curl ${CURL_OPTS} -X PUT "${ES_URL}/_index_template/security-inventory" \
  -H "Content-Type: application/json" \
  -d '{
  "index_patterns": ["security-inventory*"],
  "composed_of": ["security-common"],
  "priority": 200,
  "template": {
    "mappings": {
      "properties": {
        "query": {
          "properties": {
            "name":   { "type": "keyword" },
            "action": { "type": "keyword" }
          }
        },
        "osquery": {
          "properties": {
            "name":          { "type": "keyword" },
            "epoch":         { "type": "long" },
            "action":        { "type": "keyword" },
            "counter":       { "type": "long" },
            "decorations": { "type": "flattened" },
            "columns":     { "type": "flattened" }
          }
        },
        "host": {
          "properties": {
            "hostname":       { "type": "keyword" },
            "architecture":   { "type": "keyword" },
            "os": {
              "properties": {
                "name":    { "type": "keyword" },
                "version": { "type": "keyword" },
                "family":  { "type": "keyword" },
                "kernel":  { "type": "keyword" }
              }
            },
            "ip":  { "type": "ip" },
            "mac": { "type": "keyword" }
          }
        },
        "network": {
          "properties": {
            "interface": {
              "properties": {
                "name":    { "type": "keyword" },
                "address": { "type": "ip" },
                "mask":    { "type": "keyword" }
              }
            },
            "listening_port": {
              "properties": {
                "port":     { "type": "integer" },
                "protocol": { "type": "keyword" },
                "state":    { "type": "keyword" },
                "pid":      { "type": "long" }
              }
            }
          }
        },
        "package": {
          "properties": {
            "name":    { "type": "keyword" },
            "version": { "type": "keyword" },
            "source":  { "type": "keyword" }
          }
        },
        "user": {
          "properties": {
            "name":       { "type": "keyword" },
            "uid":        { "type": "keyword" },
            "gid":        { "type": "keyword" },
            "shell":      { "type": "keyword" },
            "directory":  { "type": "keyword" }
          }
        }
      }
    }
  }
}'
echo ""

# ─── Index Template: security-vuln (Trivy) ───────────────────────────────────
echo "Creating index template: security-vuln"
curl ${CURL_OPTS} -X PUT "${ES_URL}/_index_template/security-vuln" \
  -H "Content-Type: application/json" \
  -d '{
  "index_patterns": ["security-vuln*"],
  "composed_of": ["security-common"],
  "priority": 200,
  "template": {
    "mappings": {
      "properties": {
        "vulnerability": {
          "properties": {
            "id":          { "type": "keyword" },
            "title":       { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 512 } } },
            "description": { "type": "text" },
            "severity":    { "type": "keyword" },
            "score": {
              "properties": {
                "base":    { "type": "float" },
                "version": { "type": "keyword" }
              }
            },
            "cvss": { "type": "flattened" },
            "references": { "type": "keyword" },
            "published_date":  { "type": "date" },
            "last_modified":   { "type": "date" },
            "fixed_version":   { "type": "keyword" },
            "primary_link":    { "type": "keyword" }
          }
        },
        "package": {
          "properties": {
            "name":             { "type": "keyword" },
            "version":          { "type": "keyword" },
            "installed_version":{ "type": "keyword" },
            "fixed_version":    { "type": "keyword" },
            "ecosystem":        { "type": "keyword" },
            "layer": {
              "properties": {
                "digest": { "type": "keyword" },
                "diff_id": { "type": "keyword" }
              }
            }
          }
        },
        "workload": {
          "properties": {
            "kind":       { "type": "keyword" },
            "name":       { "type": "keyword" },
            "namespace":  { "type": "keyword" },
            "uid":        { "type": "keyword" },
            "image": {
              "properties": {
                "name":    { "type": "keyword" },
                "tag":     { "type": "keyword" },
                "digest":  { "type": "keyword" }
              }
            }
          }
        },
        "report": {
          "properties": {
            "name":      { "type": "keyword" },
            "namespace": { "type": "keyword" },
            "uid":       { "type": "keyword" },
            "scanner": {
              "properties": {
                "name":    { "type": "keyword" },
                "version": { "type": "keyword" }
              }
            }
          }
        }
      }
    }
  }
}'
echo ""

echo "Done. All index templates created successfully."
