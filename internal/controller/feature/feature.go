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

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Feature is the interface that all security tool features must implement.
// Each feature manages its own Kubernetes resources and OTel configuration.
type Feature interface {
	// ID returns the unique identifier of this feature.
	ID() FeatureID

	// Configure parses the raw JSON configuration from the FeatureSpec.Config RawExtension.
	// Called once during BuildActiveFeatures before Contribute.
	Configure(raw []byte) error

	// Contribute adds the desired Kubernetes resources for this feature to the store.
	// Called during reconcile Step 2.
	Contribute(ctx context.Context, store *DesiredStateStore) error

	// OTelConfig returns the filelog receiver configuration for the OTel Node Collector.
	// Returns nil if the feature does not require OTel log collection (e.g., Trivy).
	OTelConfig() *OTelReceiverConfig

	// Assess checks the current health of the feature's resources and returns a condition.
	// Called during reconcile Step 7 for status updates.
	Assess(ctx context.Context, c client.Client, ns string) FeatureCondition
}
