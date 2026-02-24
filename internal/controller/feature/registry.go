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
	"fmt"
	"sort"
	"sync"

	securityv1alpha1 "github.com/ctem/security-operator/api/v1alpha1"
)

// registryEntry holds the factory and priority for a registered feature.
type registryEntry struct {
	priority int
	factory  func() Feature
}

var (
	registry      = map[FeatureID]*registryEntry{}
	registryMutex sync.RWMutex
)

// Register adds a feature factory to the global registry.
// Called from each feature's init() function via blank imports in cmd/main.go.
// Panics if the same FeatureID is registered twice.
func Register(id FeatureID, priority int, factory func() Feature) {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	if _, found := registry[id]; found {
		panic(fmt.Sprintf("feature %s is already registered", id))
	}
	registry[id] = &registryEntry{
		priority: priority,
		factory:  factory,
	}
}

// BuildActiveFeatures constructs and configures the enabled features from the CRD spec.
// Returns features sorted by priority (ascending), so lower numbers run first.
func BuildActiveFeatures(specs []securityv1alpha1.FeatureSpec) ([]Feature, error) {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	type prioritizedFeature struct {
		priority int
		feat     Feature
	}

	var active []prioritizedFeature

	for _, spec := range specs {
		if !spec.Enabled {
			continue
		}

		id := FeatureID(spec.Name)
		entry, found := registry[id]
		if !found {
			return nil, fmt.Errorf("feature %s not registered", id)
		}

		feat := entry.factory()

		var raw []byte
		if spec.Config != nil && spec.Config.Raw != nil {
			raw = spec.Config.Raw
		}

		if err := feat.Configure(raw); err != nil {
			return nil, fmt.Errorf("configure feature %s: %w", id, err)
		}

		active = append(active, prioritizedFeature{
			priority: entry.priority,
			feat:     feat,
		})
	}

	// Sort by priority ascending (lower priority number = runs first)
	sort.Slice(active, func(i, j int) bool {
		return active[i].priority < active[j].priority
	})

	result := make([]Feature, len(active))
	for i, pf := range active {
		result[i] = pf.feat
	}
	return result, nil
}
