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

// Package falco implements the Falco feature (Priority 100).
// It deploys Falco as a DaemonSet using the modern_ebpf driver for eBPF-based syscall monitoring.
package falco

import (
	"context"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ctem/security-operator/internal/controller/feature"
)

func init() {
	feature.Register(feature.FalcoFeatureID, 100, func() feature.Feature {
		return &falcoFeature{}
	})
}

const (
	falcoImage   = "falcosecurity/falco-no-driver:0.38.1"
	falcoDSName  = "falco"
	falcoCMName  = "falco-config"
	falcoSAName  = "falco"
	falcoCRName  = "falco"
	falcoCRBName = "falco"
	falcoLogPath = "/var/log/security/falco"
	falcoLogFile = "/var/log/security/falco/events.log"
)

// falcoConfig holds optional config parsed from the FeatureSpec.Config.
type falcoConfig struct {
	Driver string `json:"driver,omitempty"`
	Image  string `json:"image,omitempty"`
}

type falcoFeature struct {
	cfg falcoConfig
}

func (f *falcoFeature) ID() feature.FeatureID {
	return feature.FalcoFeatureID
}

func (f *falcoFeature) Configure(raw []byte) error {
	// Set defaults
	f.cfg.Driver = "modern_ebpf"
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &f.cfg); err != nil {
		return fmt.Errorf("configure falco: %w", err)
	}
	return nil
}

func (f *falcoFeature) Contribute(ctx context.Context, store *feature.DesiredStateStore) error {
	image := falcoImage
	if f.cfg.Image != "" {
		image = f.cfg.Image
	}

	store.AddServiceAccount(falcoSAName, f.buildServiceAccount())
	store.AddClusterRole(falcoCRName, f.buildClusterRole())
	store.AddClusterRoleBinding(falcoCRBName, f.buildClusterRoleBinding(store))
	store.AddConfigMap(falcoCMName, f.buildConfigMap())
	store.AddDaemonSet(falcoDSName, f.buildDaemonSet(image))

	return nil
}

func (f *falcoFeature) OTelConfig() *feature.OTelReceiverConfig {
	return &feature.OTelReceiverConfig{
		ReceiverName: "filelog/falco",
		LogPath:      falcoLogFile + "*",
		ParseFormat:  "json",
		Attributes: map[string]string{
			"security_tool": "falco",
		},
		TargetIndex: "events",
	}
}

func (f *falcoFeature) Assess(ctx context.Context, c client.Client, ns string) feature.FeatureCondition {
	ds := &appsv1.DaemonSet{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: falcoDSName}, ds); err != nil {
		return feature.FeatureCondition{
			Type:    "FalcoReady",
			Status:  "False",
			Reason:  "DaemonSetNotFound",
			Message: fmt.Sprintf("Falco DaemonSet not found: %v", err),
		}
	}
	if ds.Status.NumberReady == 0 {
		return feature.FeatureCondition{
			Type:    "FalcoReady",
			Status:  "False",
			Reason:  "NotReady",
			Message: fmt.Sprintf("Falco DaemonSet has 0 ready nodes (desired: %d)", ds.Status.DesiredNumberScheduled),
		}
	}
	return feature.FeatureCondition{
		Type:    "FalcoReady",
		Status:  "True",
		Reason:  "Ready",
		Message: fmt.Sprintf("Falco running on %d/%d nodes", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled),
	}
}

func (f *falcoFeature) buildServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": falcoSAName},
		},
	}
}

func (f *falcoFeature) buildClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRole",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": falcoCRName},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
}

func (f *falcoFeature) buildClusterRoleBinding(store *feature.DesiredStateStore) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": falcoCRBName},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     falcoCRName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      falcoSAName,
				Namespace: store.GetNamespace(),
			},
		},
	}
}

func (f *falcoFeature) buildConfigMap() *corev1.ConfigMap {
	falcoYAML := `# Falco configuration for security-operator
json_output: true
json_include_output_property: true
json_include_tags_property: true

# Rules files — must include default rules from the container image
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml

# File output for OTel collection
file_output:
  enabled: true
  keep_alive: true
  filename: /var/log/security/falco/events.log

# Stdout output for debugging and pod log visibility
stdout_output:
  enabled: true

# Logging to stderr so kubectl logs can see Falco operational messages
log_stderr: true
log_syslog: false
log_level: info

# Engine configuration
engine:
  kind: modern_ebpf

# Priority threshold
priority: warning

# Metadata enrichment
metadata_download:
  max_wait_millis: 5000
`

	falcoRulesOverride := `# Custom rules for CTEM Security Operator PoC
# Minimal custom rules — base rules from the Falco image are preserved via subPath mount.
# No overrides needed for PoC; Falco default rules are sufficient.
`

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": falcoDSName},
		},
		Data: map[string]string{
			"falco.yaml":             falcoYAML,
			"falco_rules.local.yaml": falcoRulesOverride,
		},
	}
}

func (f *falcoFeature) buildDaemonSet(image string) *appsv1.DaemonSet {
	labels := map[string]string{
		"app":  falcoDSName,
		"role": "security-sensor",
	}

	privileged := true
	hostPathDirectory := corev1.HostPathDirectory
	hostPathDirectoryOrCreate := corev1.HostPathDirectoryOrCreate

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "DaemonSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: falcoSAName,
					HostPID:            true,
					Tolerations: []corev1.Toleration{
						{
							Key:      "node-role.kubernetes.io/master",
							Effect:   corev1.TaintEffectNoSchedule,
							Operator: corev1.TolerationOpExists,
						},
						{
							Key:      "node-role.kubernetes.io/control-plane",
							Effect:   corev1.TaintEffectNoSchedule,
							Operator: corev1.TolerationOpExists,
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "falco",
							Image: image,
							Args: []string{
								"/usr/bin/falco",
								"--modern-bpf",
								"-o", "engine.kind=modern_ebpf",
								"-c", "/etc/falco/falco.yaml",
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							Env: []corev1.EnvVar{
								{
									Name:  "HOST_ROOT",
									Value: "/host",
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "falco-config",
									MountPath: "/etc/falco/falco.yaml",
									SubPath:   "falco.yaml",
									ReadOnly:  true,
								},
								{
									Name:      "falco-config",
									MountPath: "/etc/falco/falco_rules.local.yaml",
									SubPath:   "falco_rules.local.yaml",
									ReadOnly:  true,
								},
								{
									Name:      "dev",
									MountPath: "/host/dev",
								},
								{
									Name:      "proc",
									MountPath: "/host/proc",
									ReadOnly:  true,
								},
								{
									Name:      "boot",
									MountPath: "/host/boot",
									ReadOnly:  true,
								},
								{
									Name:      "lib-modules",
									MountPath: "/host/lib/modules",
									ReadOnly:  true,
								},
								{
									Name:      "containerd-sock",
									MountPath: "/run/containerd/containerd.sock",
									ReadOnly:  true,
								},
								{
									Name:      "falco-log",
									MountPath: falcoLogPath,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "falco-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: falcoCMName,
									},
								},
							},
						},
						{
							Name: "dev",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/dev",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "proc",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/proc",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "boot",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/boot",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "lib-modules",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/lib/modules",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "containerd-sock",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/run/containerd/containerd.sock",
								},
							},
						},
						{
							Name: "falco-log",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: falcoLogPath,
									Type: &hostPathDirectoryOrCreate,
								},
							},
						},
					},
				},
			},
		},
	}
}
