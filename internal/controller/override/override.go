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

package override

import (
	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/ctem/security-operator/api/v1alpha1"
	"github.com/ctem/security-operator/internal/controller/feature"
)

// ApplyOverrides applies the 2-level override system to the DesiredStateStore:
//   - Level 1 (NodeAgent): applied to ALL DaemonSets (tolerations, nodeSelector, resources, env)
//   - Level 2 (PerTool): applied to a specific DaemonSet by name (tool-specific overrides)
//
// Override merge order: Feature defaults → NodeAgent common → PerTool specific.
func ApplyOverrides(spec *securityv1alpha1.OverrideSpec, store *feature.DesiredStateStore) {
	if spec == nil {
		return
	}

	// Level 1: NodeAgent overrides apply to ALL DaemonSets
	if spec.NodeAgent != nil {
		for _, ds := range store.DaemonSets {
			applyComponentOverride(spec.NodeAgent, ds.Spec.Template.Spec.Containers, &ds.Spec.Template.Spec)
		}
	}

	// Level 2: PerTool overrides apply to the specific DaemonSet by name
	for toolName, toolOverride := range spec.PerTool {
		if toolOverride == nil {
			continue
		}
		ds, found := store.DaemonSets[toolName]
		if !found {
			continue
		}
		applyComponentOverride(toolOverride, ds.Spec.Template.Spec.Containers, &ds.Spec.Template.Spec)

		// Image override for per-tool: update the first container's image
		if toolOverride.Image != "" && len(ds.Spec.Template.Spec.Containers) > 0 {
			ds.Spec.Template.Spec.Containers[0].Image = toolOverride.Image
		}
	}
}

// applyComponentOverride applies a ComponentOverride to a pod spec and its containers.
func applyComponentOverride(override *securityv1alpha1.ComponentOverride, containers []corev1.Container, podSpec *corev1.PodSpec) {
	// Tolerations: append (merge by replacing if same Key+Effect exists)
	if len(override.Tolerations) > 0 {
		podSpec.Tolerations = mergeTolerations(podSpec.Tolerations, override.Tolerations)
	}

	// NodeSelector: merge (override values take precedence)
	if len(override.NodeSelector) > 0 {
		if podSpec.NodeSelector == nil {
			podSpec.NodeSelector = map[string]string{}
		}
		for k, v := range override.NodeSelector {
			podSpec.NodeSelector[k] = v
		}
	}

	// Resources: apply to first container (the main workload container)
	if override.Resources != nil && len(containers) > 0 {
		containers[0].Resources = *override.Resources
	}

	// Env: merge (override env vars take precedence over existing ones with same name)
	if len(override.Env) > 0 && len(containers) > 0 {
		containers[0].Env = mergeEnvVars(containers[0].Env, override.Env)
	}
}

// mergeTolerations merges two toleration slices. Override tolerations take precedence.
func mergeTolerations(base, overrides []corev1.Toleration) []corev1.Toleration {
	result := make([]corev1.Toleration, len(base))
	copy(result, base)

	for _, ov := range overrides {
		found := false
		for i, t := range result {
			if t.Key == ov.Key && t.Effect == ov.Effect {
				result[i] = ov
				found = true
				break
			}
		}
		if !found {
			result = append(result, ov)
		}
	}
	return result
}

// mergeEnvVars merges two env var slices. Override env vars take precedence.
func mergeEnvVars(base, overrides []corev1.EnvVar) []corev1.EnvVar {
	result := make([]corev1.EnvVar, len(base))
	copy(result, base)

	for _, ov := range overrides {
		found := false
		for i, e := range result {
			if e.Name == ov.Name {
				result[i] = ov
				found = true
				break
			}
		}
		if !found {
			result = append(result, ov)
		}
	}
	return result
}
