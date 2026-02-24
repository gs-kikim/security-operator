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

// Package tetragon implements the Tetragon feature (Priority 100).
// It deploys Tetragon as a DaemonSet for eBPF-based kprobe monitoring,
// and creates a TracingPolicy CRD for container escape detection.
package tetragon

import (
	"context"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ctem/security-operator/internal/controller/feature"
)

func init() {
	feature.Register(feature.TetragonFeatureID, 100, func() feature.Feature {
		return &tetragonFeature{}
	})
}

const (
	tetragonImage   = "quay.io/cilium/tetragon:v1.2.0"
	tetragonDSName  = "tetragon"
	tetragonSAName  = "tetragon"
	tetragonCRName  = "tetragon"
	tetragonCRBName = "tetragon"
	tetragonTPName  = "container-escape-monitor"
	// OTel log path for Tetragon JSON export file
	tetragonLogPath = "/var/log/security/tetragon/events.log*"
)

// tetragonConfig holds optional config parsed from the FeatureSpec.Config.
type tetragonConfig struct {
	Image string `json:"image,omitempty"`
}

type tetragonFeature struct {
	cfg tetragonConfig
}

func (f *tetragonFeature) ID() feature.FeatureID {
	return feature.TetragonFeatureID
}

func (f *tetragonFeature) Configure(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &f.cfg); err != nil {
		return fmt.Errorf("configure tetragon: %w", err)
	}
	return nil
}

func (f *tetragonFeature) Contribute(ctx context.Context, store *feature.DesiredStateStore) error {
	image := tetragonImage
	if f.cfg.Image != "" {
		image = f.cfg.Image
	}

	store.AddServiceAccount(tetragonSAName, f.buildServiceAccount())
	store.AddClusterRole(tetragonCRName, f.buildClusterRole())
	store.AddClusterRoleBinding(tetragonCRBName, f.buildClusterRoleBinding(store))
	store.AddDaemonSet(tetragonDSName, f.buildDaemonSet(image))
	store.AddUnstructured(tetragonTPName, f.buildTracingPolicy())

	return nil
}

func (f *tetragonFeature) OTelConfig() *feature.OTelReceiverConfig {
	return &feature.OTelReceiverConfig{
		ReceiverName: "filelog/tetragon",
		LogPath:      tetragonLogPath,
		ParseFormat:  "json",
		Attributes: map[string]string{
			"security_tool": "tetragon",
		},
		TargetIndex: "events",
	}
}

func (f *tetragonFeature) Assess(ctx context.Context, c client.Client, ns string) feature.FeatureCondition {
	ds := &appsv1.DaemonSet{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: tetragonDSName}, ds); err != nil {
		return feature.FeatureCondition{
			Type:    "TetragonReady",
			Status:  "False",
			Reason:  "DaemonSetNotFound",
			Message: fmt.Sprintf("Tetragon DaemonSet not found: %v", err),
		}
	}
	if ds.Status.NumberReady == 0 {
		return feature.FeatureCondition{
			Type:    "TetragonReady",
			Status:  "False",
			Reason:  "NotReady",
			Message: fmt.Sprintf("Tetragon DaemonSet has 0 ready nodes (desired: %d)", ds.Status.DesiredNumberScheduled),
		}
	}
	return feature.FeatureCondition{
		Type:    "TetragonReady",
		Status:  "True",
		Reason:  "Ready",
		Message: fmt.Sprintf("Tetragon running on %d/%d nodes", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled),
	}
}

func (f *tetragonFeature) buildServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": tetragonSAName},
		},
	}
}

func (f *tetragonFeature) buildClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRole",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": tetragonCRName},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"cilium.io"},
				Resources: []string{"tracingpolicies", "tracingpoliciesnamespaced"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
}

func (f *tetragonFeature) buildClusterRoleBinding(store *feature.DesiredStateStore) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": tetragonCRBName},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     tetragonCRName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      tetragonSAName,
				Namespace: store.GetNamespace(),
			},
		},
	}
}

func (f *tetragonFeature) buildDaemonSet(image string) *appsv1.DaemonSet {
	labels := map[string]string{
		"app":  tetragonDSName,
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
					ServiceAccountName: tetragonSAName,
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
							Name:  "tetragon",
							Image: image,
							Args: []string{
								"--export-filename=/var/log/security/tetragon/events.log",
								"--export-file-max-size-mb=100",
								"--export-file-rotation-interval=1h",
								"--enable-export-aggregation=false",
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "bpf-maps",
									MountPath: "/sys/fs/bpf",
								},
								{
									Name:      "sys-kernel",
									MountPath: "/sys/kernel/debug",
									ReadOnly:  true,
								},
								{
									Name:      "tetragon-export",
									MountPath: "/var/log/security/tetragon",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "bpf-maps",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/sys/fs/bpf",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "sys-kernel",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/sys/kernel/debug",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "tetragon-export",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/log/security/tetragon",
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

// buildTracingPolicy creates a Tetragon TracingPolicy CRD via Unstructured
// to monitor container escape syscalls: setns, mount, unshare.
func (f *tetragonFeature) buildTracingPolicy() *unstructured.Unstructured {
	tp := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cilium.io/v1alpha1",
			"kind":       "TracingPolicy",
			"metadata": map[string]interface{}{
				"name": tetragonTPName,
			},
			"spec": map[string]interface{}{
				"kprobes": []interface{}{
					map[string]interface{}{
						"call":    "__x64_sys_setns",
						"syscall": true,
						"args": []interface{}{
							map[string]interface{}{
								"index": 0,
								"type":  "int",
							},
							map[string]interface{}{
								"index": 1,
								"type":  "int",
							},
						},
						"selectors": []interface{}{
							map[string]interface{}{
								"matchCapabilities": []interface{}{
									map[string]interface{}{
										"type":     "Effective",
										"operator": "In",
										"values":   []interface{}{"CAP_SYS_ADMIN"},
									},
								},
							},
						},
					},
					map[string]interface{}{
						"call":    "__x64_sys_mount",
						"syscall": true,
						"args": []interface{}{
							map[string]interface{}{
								"index": 0,
								"type":  "string",
							},
							map[string]interface{}{
								"index": 1,
								"type":  "string",
							},
							map[string]interface{}{
								"index": 2,
								"type":  "string",
							},
						},
						"selectors": []interface{}{
							map[string]interface{}{
								"matchCapabilities": []interface{}{
									map[string]interface{}{
										"type":     "Effective",
										"operator": "In",
										"values":   []interface{}{"CAP_SYS_ADMIN"},
									},
								},
							},
						},
					},
					map[string]interface{}{
						"call":    "__x64_sys_unshare",
						"syscall": true,
						"args": []interface{}{
							map[string]interface{}{
								"index": 0,
								"type":  "int",
							},
						},
						"selectors": []interface{}{
							map[string]interface{}{
								"matchCapabilities": []interface{}{
									map[string]interface{}{
										"type":     "Effective",
										"operator": "In",
										"values":   []interface{}{"CAP_SYS_ADMIN"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return tp
}
