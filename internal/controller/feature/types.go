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

package feature

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FeatureID is a string identifier for a feature.
type FeatureID string

const (
	OTelPipelineFeatureID FeatureID = "otel_pipeline"
	FalcoFeatureID        FeatureID = "falco"
	TetragonFeatureID     FeatureID = "tetragon"
	OsqueryFeatureID      FeatureID = "osquery"
	TrivyFeatureID        FeatureID = "trivy"
)

// OTelReceiverConfig holds the filelog receiver configuration for OTel Node Collector.
type OTelReceiverConfig struct {
	// ReceiverName is the unique name for this filelog receiver (e.g., "filelog/falco").
	ReceiverName string
	// LogPath is the glob pattern for the log file(s) to watch.
	LogPath string
	// ParseFormat is the parse format for the logs (e.g., "json").
	ParseFormat string
	// Attributes are additional resource attributes to set for this receiver.
	Attributes map[string]string
	// TargetIndex is the Elasticsearch index to route logs to (e.g., "events", "inventory").
	TargetIndex string
}

// FeatureCondition represents the health condition of a feature.
type FeatureCondition struct {
	Type    string
	Status  metav1.ConditionStatus
	Reason  string
	Message string
}
