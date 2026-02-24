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

// Package otel_pipeline implements the OTel Pipeline feature (Priority 10).
// It deploys the OpenTelemetry Collector as a Gateway Deployment and a Node DaemonSet
// for collecting logs from all other security tools.
package otel_pipeline

import (
	"context"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ctem/security-operator/internal/controller/feature"
)

func init() {
	feature.Register(feature.OTelPipelineFeatureID, 10, func() feature.Feature {
		return &otelPipelineFeature{}
	})
}

const (
	otelImage              = "otel/opentelemetry-collector-contrib:0.103.0"
	gatewayName            = "otel-gateway"
	nodeName               = "otel-node"
	gatewayServiceName     = "otel-gateway"
	otlpGRPCPort           = 4317
	healthCheckPort        = 13133
	defaultGatewayReplicas = int32(1)
)

// otelPipelineConfig holds optional config parsed from the FeatureSpec.Config.
type otelPipelineConfig struct {
	GatewayReplicas *int32 `json:"gatewayReplicas,omitempty"`
	Image           string `json:"image,omitempty"`
}

type otelPipelineFeature struct {
	cfg otelPipelineConfig
}

func (f *otelPipelineFeature) ID() feature.FeatureID {
	return feature.OTelPipelineFeatureID
}

func (f *otelPipelineFeature) Configure(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &f.cfg); err != nil {
		return fmt.Errorf("configure otel_pipeline: %w", err)
	}
	return nil
}

func (f *otelPipelineFeature) Contribute(ctx context.Context, store *feature.DesiredStateStore) error {
	image := otelImage
	if f.cfg.Image != "" {
		image = f.cfg.Image
	}
	replicas := defaultGatewayReplicas
	if f.cfg.GatewayReplicas != nil {
		replicas = *f.cfg.GatewayReplicas
	}

	sa := f.buildServiceAccount()
	store.AddServiceAccount(gatewayName, sa)

	gateway := f.buildGatewayDeployment(image, replicas)
	store.AddDeployment(gatewayName, gateway)

	svc := f.buildGatewayService()
	store.AddService(gatewayServiceName, svc)

	node := f.buildNodeDaemonSet(image)
	store.AddDaemonSet(nodeName, node)

	return nil
}

// OTelConfig returns nil because the otel_pipeline feature IS the OTel infrastructure.
func (f *otelPipelineFeature) OTelConfig() *feature.OTelReceiverConfig {
	return nil
}

func (f *otelPipelineFeature) Assess(ctx context.Context, c client.Client, ns string) feature.FeatureCondition {
	// Check Gateway Deployment ready replicas
	gateway := &appsv1.Deployment{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: gatewayName}, gateway); err != nil {
		return feature.FeatureCondition{
			Type:    "OTelPipelineReady",
			Status:  "False",
			Reason:  "GatewayNotFound",
			Message: fmt.Sprintf("OTel gateway deployment not found: %v", err),
		}
	}
	if gateway.Status.ReadyReplicas == 0 {
		return feature.FeatureCondition{
			Type:    "OTelPipelineReady",
			Status:  "False",
			Reason:  "GatewayNotReady",
			Message: "OTel gateway deployment has 0 ready replicas",
		}
	}

	// Check Node DaemonSet ready
	node := &appsv1.DaemonSet{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: nodeName}, node); err != nil {
		return feature.FeatureCondition{
			Type:    "OTelPipelineReady",
			Status:  "False",
			Reason:  "NodeDaemonSetNotFound",
			Message: fmt.Sprintf("OTel node daemonset not found: %v", err),
		}
	}
	if node.Status.NumberReady == 0 {
		return feature.FeatureCondition{
			Type:    "OTelPipelineReady",
			Status:  "False",
			Reason:  "NodeNotReady",
			Message: "OTel node daemonset has 0 ready nodes",
		}
	}

	return feature.FeatureCondition{
		Type:    "OTelPipelineReady",
		Status:  "True",
		Reason:  "AllReady",
		Message: fmt.Sprintf("Gateway ready replicas: %d, Node ready: %d", gateway.Status.ReadyReplicas, node.Status.NumberReady),
	}
}

func (f *otelPipelineFeature) buildServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": gatewayName,
			},
		},
	}
}

func (f *otelPipelineFeature) buildGatewayDeployment(image string, replicas int32) *appsv1.Deployment {
	labels := map[string]string{
		"app":  gatewayName,
		"role": "gateway",
	}
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: gatewayName,
					Containers: []corev1.Container{
						{
							Name:  "otelcol",
							Image: image,
							Args:  []string{"--config=/etc/otelcol/config.yaml"},
							Ports: []corev1.ContainerPort{
								{Name: "otlp-grpc", ContainerPort: otlpGRPCPort, Protocol: corev1.ProtocolTCP},
								{Name: "health", ContainerPort: healthCheckPort, Protocol: corev1.ProtocolTCP},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.FromInt32(healthCheckPort),
									},
								},
								InitialDelaySeconds: 10,
								PeriodSeconds:       30,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.FromInt32(healthCheckPort),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "otel-gateway-config",
									MountPath: "/etc/otelcol",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "otel-gateway-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "otel-gateway-config",
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

func (f *otelPipelineFeature) buildGatewayService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": gatewayName,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app":  gatewayName,
				"role": "gateway",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "otlp-grpc",
					Port:       otlpGRPCPort,
					TargetPort: intstr.FromInt32(otlpGRPCPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (f *otelPipelineFeature) buildNodeDaemonSet(image string) *appsv1.DaemonSet {
	labels := map[string]string{
		"app":  nodeName,
		"role": "node-collector",
	}

	hostPathDirectory := corev1.HostPathDirectory

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
					ServiceAccountName: gatewayName,
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
							Name:  "otelcol",
							Image: image,
							Args:  []string{"--config=/etc/otelcol/config.yaml"},
							Ports: []corev1.ContainerPort{
								{Name: "health", ContainerPort: healthCheckPort, Protocol: corev1.ProtocolTCP},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "otel-node-collector-config",
									MountPath: "/etc/otelcol",
									ReadOnly:  true,
								},
								{
									Name:      "varlog",
									MountPath: "/var/log",
									ReadOnly:  true,
								},
								{
									Name:      "varlogpods",
									MountPath: "/var/log/pods",
									ReadOnly:  true,
								},
								{
									Name:      "varlogsecurity",
									MountPath: "/var/log/security",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "otel-node-collector-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "otel-node-collector-config",
									},
								},
							},
						},
						{
							Name: "varlog",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/log",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "varlogpods",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/log/pods",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "varlogsecurity",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/log/security",
									Type: &hostPathDirectory,
								},
							},
						},
					},
				},
			},
		},
	}
}
