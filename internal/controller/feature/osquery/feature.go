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

// Package osquery implements the OSquery feature (Priority 100).
// It deploys OSquery as a non-privileged DaemonSet for SQL-based inventory collection,
// writing results to a file for OTel collection.
package osquery

import (
	"context"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ctem/security-operator/internal/controller/feature"
)

func init() {
	feature.Register(feature.OsqueryFeatureID, 100, func() feature.Feature {
		return &osqueryFeature{}
	})
}

const (
	osqueryImage   = "osquery/osquery:5.12.1"
	osqueryDSName  = "osquery"
	osqueryCMName  = "osquery-config"
	osquerySAName  = "osquery"
	osqueryLogPath = "/var/log/security/osquery"
	osqueryLogFile = "/var/log/security/osquery/results.log"
)

// osqueryConfig holds optional config parsed from the FeatureSpec.Config.
type osqueryConfig struct {
	ScheduleInterval int    `json:"scheduleInterval,omitempty"`
	Image            string `json:"image,omitempty"`
}

type osqueryFeature struct {
	cfg osqueryConfig
}

func (f *osqueryFeature) ID() feature.FeatureID {
	return feature.OsqueryFeatureID
}

func (f *osqueryFeature) Configure(raw []byte) error {
	// Default schedule interval: 300 seconds (5 minutes)
	f.cfg.ScheduleInterval = 300
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &f.cfg); err != nil {
		return fmt.Errorf("configure osquery: %w", err)
	}
	return nil
}

func (f *osqueryFeature) Contribute(ctx context.Context, store *feature.DesiredStateStore) error {
	image := osqueryImage
	if f.cfg.Image != "" {
		image = f.cfg.Image
	}

	store.AddServiceAccount(osquerySAName, f.buildServiceAccount())
	store.AddConfigMap(osqueryCMName, f.buildConfigMap())
	store.AddDaemonSet(osqueryDSName, f.buildDaemonSet(image))

	return nil
}

func (f *osqueryFeature) OTelConfig() *feature.OTelReceiverConfig {
	return &feature.OTelReceiverConfig{
		ReceiverName: "filelog/osquery",
		LogPath:      osqueryLogFile,
		ParseFormat:  "json",
		Attributes: map[string]string{
			"security_tool": "osquery",
		},
		TargetIndex: "inventory",
	}
}

func (f *osqueryFeature) Assess(ctx context.Context, c client.Client, ns string) feature.FeatureCondition {
	ds := &appsv1.DaemonSet{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: osqueryDSName}, ds); err != nil {
		return feature.FeatureCondition{
			Type:    "OsqueryReady",
			Status:  "False",
			Reason:  "DaemonSetNotFound",
			Message: fmt.Sprintf("OSquery DaemonSet not found: %v", err),
		}
	}
	if ds.Status.NumberReady == 0 {
		return feature.FeatureCondition{
			Type:    "OsqueryReady",
			Status:  "False",
			Reason:  "NotReady",
			Message: fmt.Sprintf("OSquery DaemonSet has 0 ready nodes (desired: %d)", ds.Status.DesiredNumberScheduled),
		}
	}
	return feature.FeatureCondition{
		Type:    "OsqueryReady",
		Status:  "True",
		Reason:  "Ready",
		Message: fmt.Sprintf("OSquery running on %d/%d nodes", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled),
	}
}

func (f *osqueryFeature) buildServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": osquerySAName},
		},
	}
}

func (f *osqueryFeature) buildConfigMap() *corev1.ConfigMap {
	scheduleInterval := f.cfg.ScheduleInterval

	osqueryFlagsFile := `--logger_plugin=filesystem
--logger_path=/var/log/security/osquery
--log_result_events=true
--schedule_splay_percent=10
--utc
`

	osqueryPackJSON := fmt.Sprintf(`{
  "queries": {
    "running_processes": {
      "query": "SELECT pid, name, path, cmdline, uid FROM processes;",
      "interval": %d,
      "description": "Enumerate all running processes"
    },
    "listening_ports": {
      "query": "SELECT pid, port, protocol, address FROM listening_ports;",
      "interval": %d,
      "description": "Enumerate all listening network ports"
    },
    "installed_packages": {
      "query": "SELECT name, version, source FROM deb_packages UNION SELECT name, version, source FROM rpm_packages;",
      "interval": %d,
      "description": "Enumerate installed packages (deb and rpm)"
    },
    "users": {
      "query": "SELECT uid, username, shell, directory FROM users;",
      "interval": %d,
      "description": "Enumerate local user accounts"
    },
    "network_interfaces": {
      "query": "SELECT interface, address, mask FROM interface_addresses;",
      "interval": %d,
      "description": "Enumerate network interfaces and addresses"
    },
    "kernel_modules": {
      "query": "SELECT name, size, status FROM kernel_modules;",
      "interval": %d,
      "description": "Enumerate loaded kernel modules"
    }
  }
}`, scheduleInterval, scheduleInterval, scheduleInterval, scheduleInterval, scheduleInterval, scheduleInterval)

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": osqueryDSName},
		},
		Data: map[string]string{
			"osquery.flags": osqueryFlagsFile,
			"security.conf": osqueryPackJSON,
		},
	}
}

func (f *osqueryFeature) buildDaemonSet(image string) *appsv1.DaemonSet {
	labels := map[string]string{
		"app":  osqueryDSName,
		"role": "inventory-collector",
	}

	readOnly := true
	hostPathDirectory := corev1.HostPathDirectory
	hostPathDirectoryOrCreate := corev1.HostPathDirectoryOrCreate
	runAsUser := int64(0)

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
					ServiceAccountName: osquerySAName,
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
							Name:  "osquery",
							Image: image,
							Command: []string{
								"/usr/bin/osqueryd",
								"--flagfile=/etc/osquery/osquery.flags",
								"--config_path=/etc/osquery/security.conf",
							},
							// Not privileged — OSquery only needs read access to /proc and /etc
							SecurityContext: &corev1.SecurityContext{
								RunAsUser: &runAsUser,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "osquery-config",
									MountPath: "/etc/osquery",
									ReadOnly:  true,
								},
								{
									Name:      "proc",
									MountPath: "/host/proc",
									ReadOnly:  readOnly,
								},
								{
									Name:      "etc",
									MountPath: "/host/etc",
									ReadOnly:  readOnly,
								},
								{
									Name:      "osquery-log",
									MountPath: osqueryLogPath,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "osquery-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: osqueryCMName,
									},
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
							Name: "etc",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "osquery-log",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: osqueryLogPath,
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
