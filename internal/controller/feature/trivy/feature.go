/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package trivy implements the Trivy feature (Priority 200).
// It deploys a CronJob that reads VulnerabilityReport CRDs and posts them
// directly to Elasticsearch (no OTel pipeline needed).
package trivy

import (
	"context"
	"encoding/json"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ctem/security-operator/internal/controller/feature"
)

func init() {
	feature.Register(feature.TrivyFeatureID, 200, func() feature.Feature {
		return &trivyFeature{}
	})
}

const (
	trivyCronJobImage   = "alpine/k8s:1.30.2"
	trivyCronJobName    = "trivy-es-sync"
	trivySAName         = "trivy-es-sync"
	trivyCRName         = "trivy-es-sync"
	trivyCRBName        = "trivy-es-sync"
	defaultCronSchedule = "0 */6 * * *"
)

// trivyConfig holds optional config parsed from the FeatureSpec.Config.
type trivyConfig struct {
	Schedule string `json:"schedule,omitempty"`
	Image    string `json:"image,omitempty"`
	// ESEndpoint allows overriding the ES endpoint for the CronJob.
	// If empty, uses the SecurityAgent's output.elasticsearch.url.
	ESEndpoint string `json:"esEndpoint,omitempty"`
}

type trivyFeature struct {
	cfg trivyConfig
}

func (f *trivyFeature) ID() feature.FeatureID {
	return feature.TrivyFeatureID
}

func (f *trivyFeature) Configure(raw []byte) error {
	// Set defaults
	f.cfg.Schedule = defaultCronSchedule
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &f.cfg); err != nil {
		return fmt.Errorf("configure trivy: %w", err)
	}
	if f.cfg.Schedule == "" {
		f.cfg.Schedule = defaultCronSchedule
	}
	return nil
}

func (f *trivyFeature) Contribute(ctx context.Context, store *feature.DesiredStateStore) error {
	image := trivyCronJobImage
	if f.cfg.Image != "" {
		image = f.cfg.Image
	}

	store.AddServiceAccount(trivySAName, f.buildServiceAccount())
	store.AddClusterRole(trivyCRName, f.buildClusterRole())
	store.AddClusterRoleBinding(trivyCRBName, f.buildClusterRoleBinding(store))
	store.AddCronJob(trivyCronJobName, f.buildCronJob(image))

	return nil
}

// OTelConfig returns nil — Trivy CronJob posts directly to Elasticsearch.
func (f *trivyFeature) OTelConfig() *feature.OTelReceiverConfig {
	return nil
}

func (f *trivyFeature) Assess(ctx context.Context, c client.Client, ns string) feature.FeatureCondition {
	cj := &batchv1.CronJob{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: trivyCronJobName}, cj); err != nil {
		return feature.FeatureCondition{
			Type:    "TrivyReady",
			Status:  "False",
			Reason:  "CronJobNotFound",
			Message: fmt.Sprintf("Trivy CronJob not found: %v", err),
		}
	}
	if cj.Status.LastSuccessfulTime == nil {
		return feature.FeatureCondition{
			Type:    "TrivyReady",
			Status:  "False",
			Reason:  "NeverRun",
			Message: "Trivy CronJob has not completed successfully yet",
		}
	}
	return feature.FeatureCondition{
		Type:    "TrivyReady",
		Status:  "True",
		Reason:  "Ready",
		Message: fmt.Sprintf("Trivy last synced at %s", cj.Status.LastSuccessfulTime.String()),
	}
}

func (f *trivyFeature) buildServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": trivySAName},
		},
	}
}

func (f *trivyFeature) buildClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRole",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": trivyCRName},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"aquasecurity.github.io"},
				Resources: []string{"vulnerabilityreports"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
}

func (f *trivyFeature) buildClusterRoleBinding(store *feature.DesiredStateStore) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": trivyCRBName},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     trivyCRName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      trivySAName,
				Namespace: store.GetNamespace(),
			},
		},
	}
}

func (f *trivyFeature) buildCronJob(image string) *batchv1.CronJob {
	// ES endpoint: use configured value or default to in-cluster ES.
	esEndpoint := f.cfg.ESEndpoint
	if esEndpoint == "" {
		esEndpoint = "http://elasticsearch-es-http:9200"
	}

	// The script:
	// 1. Fetches all VulnerabilityReports across all namespaces via kubectl
	// 2. Transforms to ES bulk format with _id = "<UID>:<CVE>:<package>" for dedup
	// 3. Posts to ES /_bulk endpoint
	script := fmt.Sprintf(`#!/bin/sh
set -e

# Ensure jq and curl are available
command -v jq  >/dev/null 2>&1 || apk add --no-cache jq  curl >/dev/null 2>&1 || true
command -v curl >/dev/null 2>&1 || true

ES_ENDPOINT="%s"
INDEX="security-vuln"

echo "Fetching VulnerabilityReports..."
REPORTS=$(kubectl get vulnerabilityreports -A -o json 2>/dev/null || echo '{"items":[]}')
COUNT=$(echo "$REPORTS" | jq '.items | length')
echo "Found $COUNT VulnerabilityReport(s)"

if [ "$COUNT" = "0" ]; then
  echo "No VulnerabilityReports found, exiting"
  exit 0
fi

# Build ES bulk payload
# Each VulnerabilityReport may contain multiple vulnerabilities
# _id = "<reportUID>:<cveID>:<pkgName>" for deduplication
BULK_BODY=$(echo "$REPORTS" | jq -r '
  .items[] |
  . as $report |
  ($report.metadata.uid) as $uid |
  ($report.metadata.namespace) as $ns |
  ($report.metadata.name) as $name |
  ($report.spec.artifact.repository + ":" + ($report.spec.artifact.tag // "latest")) as $image |
  $report.report.vulnerabilities[]? |
  . as $vuln |
  (($uid + ":" + $vuln.vulnerabilityID + ":" + $vuln.resource) | gsub(" "; "_")) as $id |
  {
    index: {
      _index: "%s",
      _id: $id
    }
  } | tojson,
  {
    "@timestamp": (now | todate),
    "vulnerability": {
      "id": $vuln.vulnerabilityID,
      "severity": $vuln.severity,
      "score": {
        "base": ($vuln.score // 0),
        "version": "3.1"
      },
      "title": $vuln.title,
      "fixed_version": $vuln.fixedVersion,
      "primary_link": $vuln.primaryLink
    },
    "package": {
      "name": $vuln.resource,
      "installed_version": $vuln.installedVersion,
      "fixed_version": $vuln.fixedVersion
    },
    "workload": {
      "namespace": $ns,
      "name": $name,
      "image": {
        "name": $report.spec.artifact.repository,
        "tag": ($report.spec.artifact.tag // "latest")
      }
    }
  } | tojson
')

if [ -z "$BULK_BODY" ]; then
  echo "No vulnerabilities to index"
  exit 0
fi

# Add trailing newline required by ES bulk API
BULK_PAYLOAD=$(printf "%%s\n" "$BULK_BODY")

echo "Posting to Elasticsearch..."
HTTP_STATUS=$(curl -s -o /tmp/es-response.json -w "%%{http_code}" \
  -X POST "${ES_ENDPOINT}/_bulk" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary "$BULK_PAYLOAD")

if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
  echo "Successfully indexed vulnerabilities (HTTP $HTTP_STATUS)"
  ERRORS=$(jq '.errors' /tmp/es-response.json 2>/dev/null || echo "unknown")
  echo "ES bulk errors: $ERRORS"
else
  echo "Failed to index vulnerabilities (HTTP $HTTP_STATUS)"
  cat /tmp/es-response.json
  exit 1
fi
`, esEndpoint, "security-vuln")

	backoffLimit := int32(3)
	successfulJobsHistory := int32(3)
	failedJobsHistory := int32(3)

	return &batchv1.CronJob{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "batch/v1",
			Kind:       "CronJob",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app":  trivyCronJobName,
				"role": "vuln-exporter",
			},
		},
		Spec: batchv1.CronJobSpec{
			Schedule:                   f.cfg.Schedule,
			SuccessfulJobsHistoryLimit: &successfulJobsHistory,
			FailedJobsHistoryLimit:     &failedJobsHistory,
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					BackoffLimit: &backoffLimit,
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"app":  trivyCronJobName,
								"role": "vuln-exporter",
							},
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: trivySAName,
							RestartPolicy:      corev1.RestartPolicyOnFailure,
							Containers: []corev1.Container{
								{
									Name:  "trivy-es-sync",
									Image: image,
									Command: []string{
										"/bin/sh",
										"-c",
										script,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
