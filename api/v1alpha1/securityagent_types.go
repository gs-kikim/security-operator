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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// SecurityAgentSpec defines the desired state of SecurityAgent.
type SecurityAgentSpec struct {
	Global   GlobalSpec    `json:"global,omitempty"`
	Features []FeatureSpec `json:"features"`
	Output   OutputSpec    `json:"output"`
	Override *OverrideSpec `json:"override,omitempty"`
}

// FeatureSpec defines a single security feature configuration.
type FeatureSpec struct {
	Name    string                `json:"name"`
	Enabled bool                  `json:"enabled"`
	Config  *runtime.RawExtension `json:"config,omitempty"`
}

// SecurityAgentStatus defines the observed state of SecurityAgent.
type SecurityAgentStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	Features           map[string]string  `json:"features,omitempty"`
}

// OutputSpec defines where security data is sent.
type OutputSpec struct {
	Elasticsearch *ElasticsearchSpec `json:"elasticsearch,omitempty"`
}

// ElasticsearchSpec defines the Elasticsearch connection configuration.
type ElasticsearchSpec struct {
	URL     string      `json:"url"`
	Indices IndicesSpec `json:"indices"`
	TLS     *TLSSpec    `json:"tls,omitempty"`
	Auth    *AuthSpec   `json:"auth,omitempty"`
}

// IndicesSpec defines the Elasticsearch index names for each CTEM stage.
type IndicesSpec struct {
	Events        string `json:"events,omitempty"`
	Inventory     string `json:"inventory,omitempty"`
	Vulnerability string `json:"vulnerability,omitempty"`
}

// TLSSpec defines TLS configuration.
type TLSSpec struct {
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// AuthSpec defines authentication configuration.
type AuthSpec struct {
	SecretRef *SecretRef `json:"secretRef,omitempty"`
}

// SecretRef references a Kubernetes Secret.
type SecretRef struct {
	Name string `json:"name"`
}

// OverrideSpec defines the 2-level override system.
type OverrideSpec struct {
	NodeAgent *ComponentOverride            `json:"nodeAgent,omitempty"`
	PerTool   map[string]*ComponentOverride `json:"perTool,omitempty"`
}

// ComponentOverride defines overrides for a component's pod spec.
type ComponentOverride struct {
	Tolerations  []corev1.Toleration          `json:"tolerations,omitempty"`
	NodeSelector map[string]string            `json:"nodeSelector,omitempty"`
	Resources    *corev1.ResourceRequirements `json:"resources,omitempty"`
	Image        string                       `json:"image,omitempty"`
	Env          []corev1.EnvVar              `json:"env,omitempty"`
}

// GlobalSpec defines global settings shared across all features.
type GlobalSpec struct {
	Namespace        string                        `json:"namespace,omitempty"`
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SecurityAgent is the Schema for the securityagents API.
type SecurityAgent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityAgentSpec   `json:"spec,omitempty"`
	Status SecurityAgentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecurityAgentList contains a list of SecurityAgent.
type SecurityAgentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityAgent `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecurityAgent{}, &SecurityAgentList{})
}
