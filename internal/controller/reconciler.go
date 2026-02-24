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

package controller

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/ctem/security-operator/api/v1alpha1"
	"github.com/ctem/security-operator/internal/controller/feature"
	"github.com/ctem/security-operator/internal/controller/otel"
	"github.com/ctem/security-operator/internal/controller/override"
)

const (
	// finalizerName is the finalizer applied to SecurityAgent to allow cleanup of cluster-scoped resources.
	finalizerName = "security.ctem.io/cleanup"
	// requeuePeriod is how often to re-check even without spec changes.
	requeuePeriod = 30 * time.Second
)

// SecurityAgentReconciler reconciles a SecurityAgent object.
type SecurityAgentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.ctem.io,resources=securityagents,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.ctem.io,resources=securityagents/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.ctem.io,resources=securityagents/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=daemonsets;deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps;services;serviceaccounts;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods;nodes;namespaces;events,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete;escalate;bind
// +kubebuilder:rbac:groups=cilium.io,resources=tracingpolicies;tracingpoliciesnamespaced,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=vulnerabilityreports,verbs=get;list;watch

// Reconcile implements the 7-step reconcile loop for SecurityAgent.
func (r *SecurityAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling SecurityAgent", "name", req.Name, "namespace", req.Namespace)

	// Fetch the SecurityAgent instance
	instance := &securityv1alpha1.SecurityAgent{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get SecurityAgent: %w", err)
	}

	// Handle finalizer for cluster-scoped resource cleanup
	if !instance.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, instance)
	}

	if !controllerutil.ContainsFinalizer(instance, finalizerName) {
		controllerutil.AddFinalizer(instance, finalizerName)
		if err := r.Update(ctx, instance); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Resolve the namespace to deploy resources into
	ns := instance.Namespace
	if instance.Spec.Global.Namespace != "" {
		ns = instance.Spec.Global.Namespace
	}

	// Step 1: Build active features (enabled only, priority-sorted)
	features, err := feature.BuildActiveFeatures(instance.Spec.Features)
	if err != nil {
		log.Error(err, "Failed to build active features")
		return r.updateStatus(ctx, instance, err, nil)
	}
	log.Info("Active features built", "count", len(features))

	// Step 2: Collect desired state from each feature
	store := feature.NewDesiredStateStore(ns)
	for _, feat := range features {
		if err := feat.Contribute(ctx, store); err != nil {
			return r.updateStatus(ctx, instance, fmt.Errorf("contribute feature %s: %w", feat.ID(), err), nil)
		}
	}

	// Step 3: OTel ConfigMap synthesis — collect OTelConfig() from all features
	var otelReceivers []*feature.OTelReceiverConfig
	for _, feat := range features {
		if cfg := feat.OTelConfig(); cfg != nil {
			otelReceivers = append(otelReceivers, cfg)
		}
	}
	if len(otelReceivers) > 0 {
		nodeCM := otel.BuildNodeCollectorConfig(otelReceivers, instance.Spec.Output, ns)
		store.AddConfigMap(otel.NodeCollectorConfigMapName, nodeCM)
	}
	gatewayCM := otel.BuildGatewayConfig(instance.Spec.Output, ns)
	store.AddConfigMap(otel.GatewayConfigMapName, gatewayCM)

	// Step 4: Apply overrides (common nodeAgent + per-tool)
	override.ApplyOverrides(instance.Spec.Override, store)

	// Step 4.5: Inject ES_PASSWORD env var into OTel Gateway if auth is configured
	if instance.Spec.Output.Elasticsearch != nil &&
		instance.Spec.Output.Elasticsearch.Auth != nil &&
		instance.Spec.Output.Elasticsearch.Auth.SecretRef != nil {
		if gw, ok := store.Deployments["otel-gateway"]; ok {
			secretName := instance.Spec.Output.Elasticsearch.Auth.SecretRef.Name
			for i := range gw.Spec.Template.Spec.Containers {
				gw.Spec.Template.Spec.Containers[i].Env = append(
					gw.Spec.Template.Spec.Containers[i].Env,
					corev1.EnvVar{
						Name: "ES_PASSWORD",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
								Key:                  "elastic",
							},
						},
					},
				)
			}
		}
	}

	// Step 5: SSA Apply all desired resources
	if err := store.ApplyAll(ctx, r.Client, instance, r.Scheme); err != nil {
		return r.updateStatus(ctx, instance, fmt.Errorf("apply resources: %w", err), nil)
	}

	// Step 6: GC — delete stale resources from disabled features
	desiredKeys := store.GetAllResourceKeys()
	if err := r.cleanupStale(ctx, instance, ns, desiredKeys); err != nil {
		log.Error(err, "Failed to cleanup stale resources")
		// Non-fatal: continue to update status
	}

	// Step 7: Status update — Assess() each feature + set ObservedGeneration
	return r.updateStatus(ctx, instance, nil, features)
}

// handleDeletion performs cleanup of cluster-scoped resources and removes the finalizer.
func (r *SecurityAgentReconciler) handleDeletion(ctx context.Context, instance *securityv1alpha1.SecurityAgent) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("SecurityAgent being deleted, cleaning up cluster-scoped resources")

	// Delete ClusterRoles and ClusterRoleBindings labeled with this SecurityAgent
	partOfValue := fmt.Sprintf("%s-%s", instance.Namespace, instance.Name)

	crList := &rbacv1.ClusterRoleList{}
	if err := r.List(ctx, crList, client.MatchingLabels{feature.PartOfLabel: partOfValue}); err == nil {
		for i := range crList.Items {
			if err := r.Delete(ctx, &crList.Items[i]); client.IgnoreNotFound(err) != nil {
				log.Error(err, "Failed to delete ClusterRole", "name", crList.Items[i].Name)
			}
		}
	}

	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := r.List(ctx, crbList, client.MatchingLabels{feature.PartOfLabel: partOfValue}); err == nil {
		for i := range crbList.Items {
			if err := r.Delete(ctx, &crbList.Items[i]); client.IgnoreNotFound(err) != nil {
				log.Error(err, "Failed to delete ClusterRoleBinding", "name", crbList.Items[i].Name)
			}
		}
	}

	controllerutil.RemoveFinalizer(instance, finalizerName)
	if err := r.Update(ctx, instance); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

// cleanupStale deletes resources that are no longer desired (from disabled features).
// It compares resources labeled with this SecurityAgent against the desired keys.
func (r *SecurityAgentReconciler) cleanupStale(ctx context.Context, instance *securityv1alpha1.SecurityAgent, ns string, desiredKeys map[string]bool) error {
	log := logf.FromContext(ctx)
	partOfValue := fmt.Sprintf("%s-%s", instance.Namespace, instance.Name)
	listOpts := []client.ListOption{
		client.InNamespace(ns),
		client.MatchingLabels{feature.PartOfLabel: partOfValue},
	}

	// Check DaemonSets
	dsList := &appsv1.DaemonSetList{}
	if err := r.List(ctx, dsList, listOpts...); err == nil {
		for i := range dsList.Items {
			key := "DaemonSet/" + dsList.Items[i].Name
			if !desiredKeys[key] {
				log.Info("Deleting stale DaemonSet", "name", dsList.Items[i].Name)
				if err := r.Delete(ctx, &dsList.Items[i]); client.IgnoreNotFound(err) != nil {
					return fmt.Errorf("delete stale DaemonSet %s: %w", dsList.Items[i].Name, err)
				}
			}
		}
	}

	// Check Deployments
	deployList := &appsv1.DeploymentList{}
	if err := r.List(ctx, deployList, listOpts...); err == nil {
		for i := range deployList.Items {
			key := "Deployment/" + deployList.Items[i].Name
			if !desiredKeys[key] {
				log.Info("Deleting stale Deployment", "name", deployList.Items[i].Name)
				if err := r.Delete(ctx, &deployList.Items[i]); client.IgnoreNotFound(err) != nil {
					return fmt.Errorf("delete stale Deployment %s: %w", deployList.Items[i].Name, err)
				}
			}
		}
	}

	// Check CronJobs
	cjList := &batchv1.CronJobList{}
	if err := r.List(ctx, cjList, listOpts...); err == nil {
		for i := range cjList.Items {
			key := "CronJob/" + cjList.Items[i].Name
			if !desiredKeys[key] {
				log.Info("Deleting stale CronJob", "name", cjList.Items[i].Name)
				if err := r.Delete(ctx, &cjList.Items[i]); client.IgnoreNotFound(err) != nil {
					return fmt.Errorf("delete stale CronJob %s: %w", cjList.Items[i].Name, err)
				}
			}
		}
	}

	// Check ConfigMaps
	cmList := &corev1.ConfigMapList{}
	if err := r.List(ctx, cmList, listOpts...); err == nil {
		for i := range cmList.Items {
			key := "ConfigMap/" + cmList.Items[i].Name
			if !desiredKeys[key] {
				log.Info("Deleting stale ConfigMap", "name", cmList.Items[i].Name)
				if err := r.Delete(ctx, &cmList.Items[i]); client.IgnoreNotFound(err) != nil {
					return fmt.Errorf("delete stale ConfigMap %s: %w", cmList.Items[i].Name, err)
				}
			}
		}
	}

	// Check ServiceAccounts
	saList := &corev1.ServiceAccountList{}
	if err := r.List(ctx, saList, listOpts...); err == nil {
		for i := range saList.Items {
			key := "ServiceAccount/" + saList.Items[i].Name
			if !desiredKeys[key] {
				log.Info("Deleting stale ServiceAccount", "name", saList.Items[i].Name)
				if err := r.Delete(ctx, &saList.Items[i]); client.IgnoreNotFound(err) != nil {
					return fmt.Errorf("delete stale ServiceAccount %s: %w", saList.Items[i].Name, err)
				}
			}
		}
	}

	// Check cluster-scoped ClusterRoles
	crList := &rbacv1.ClusterRoleList{}
	if err := r.List(ctx, crList, client.MatchingLabels{feature.PartOfLabel: partOfValue}); err == nil {
		for i := range crList.Items {
			key := "ClusterRole/" + crList.Items[i].Name
			if !desiredKeys[key] {
				log.Info("Deleting stale ClusterRole", "name", crList.Items[i].Name)
				if err := r.Delete(ctx, &crList.Items[i]); client.IgnoreNotFound(err) != nil {
					return fmt.Errorf("delete stale ClusterRole %s: %w", crList.Items[i].Name, err)
				}
			}
		}
	}

	// Check cluster-scoped ClusterRoleBindings
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := r.List(ctx, crbList, client.MatchingLabels{feature.PartOfLabel: partOfValue}); err == nil {
		for i := range crbList.Items {
			key := "ClusterRoleBinding/" + crbList.Items[i].Name
			if !desiredKeys[key] {
				log.Info("Deleting stale ClusterRoleBinding", "name", crbList.Items[i].Name)
				if err := r.Delete(ctx, &crbList.Items[i]); client.IgnoreNotFound(err) != nil {
					return fmt.Errorf("delete stale ClusterRoleBinding %s: %w", crbList.Items[i].Name, err)
				}
			}
		}
	}

	return nil
}

// updateStatus updates the SecurityAgent status with feature conditions and ObservedGeneration.
func (r *SecurityAgentReconciler) updateStatus(ctx context.Context, instance *securityv1alpha1.SecurityAgent, reconcileErr error, features []feature.Feature) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	statusCopy := instance.DeepCopy()
	now := metav1.Now()

	ns := instance.Namespace
	if instance.Spec.Global.Namespace != "" {
		ns = instance.Spec.Global.Namespace
	}

	// Update feature status from Assess()
	if statusCopy.Status.Features == nil {
		statusCopy.Status.Features = make(map[string]string)
	}

	allReady := true
	for _, feat := range features {
		cond := feat.Assess(ctx, r.Client, ns)
		statusCopy.Status.Features[string(feat.ID())] = string(cond.Status)

		// Upsert condition into Conditions slice
		newCond := metav1.Condition{
			Type:               cond.Type,
			Status:             cond.Status,
			Reason:             cond.Reason,
			Message:            cond.Message,
			LastTransitionTime: now,
		}
		setCondition(&statusCopy.Status.Conditions, newCond)

		if cond.Status != metav1.ConditionTrue {
			allReady = false
		}
	}

	// Set overall Ready condition
	readyCond := metav1.Condition{
		Type:               "Ready",
		LastTransitionTime: now,
	}
	if reconcileErr != nil {
		readyCond.Status = metav1.ConditionFalse
		readyCond.Reason = "ReconcileError"
		readyCond.Message = reconcileErr.Error()
		allReady = false
	} else if allReady || len(features) == 0 {
		readyCond.Status = metav1.ConditionTrue
		readyCond.Reason = "ReconcileSuccess"
		readyCond.Message = "All features reconciled successfully"
	} else {
		readyCond.Status = metav1.ConditionFalse
		readyCond.Reason = "FeaturesNotReady"
		readyCond.Message = "One or more features are not ready"
	}
	setCondition(&statusCopy.Status.Conditions, readyCond)
	statusCopy.Status.ObservedGeneration = instance.Generation

	// Only update if status changed
	if err := r.Status().Update(ctx, statusCopy); err != nil {
		if apierrors.IsConflict(err) {
			log.V(1).Info("Status update conflict, requeueing")
			return ctrl.Result{Requeue: true}, nil
		}
		log.Error(err, "Failed to update status")
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	if reconcileErr != nil {
		return ctrl.Result{RequeueAfter: requeuePeriod}, reconcileErr
	}
	return ctrl.Result{RequeueAfter: requeuePeriod}, nil
}

// setCondition upserts a condition into the conditions slice.
func setCondition(conditions *[]metav1.Condition, newCond metav1.Condition) {
	for i, existing := range *conditions {
		if existing.Type == newCond.Type {
			// Preserve LastTransitionTime if status hasn't changed
			if existing.Status == newCond.Status {
				newCond.LastTransitionTime = existing.LastTransitionTime
			}
			(*conditions)[i] = newCond
			return
		}
	}
	*conditions = append(*conditions, newCond)
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *SecurityAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.SecurityAgent{}).
		WithEventFilter(generationChangedPredicate()).
		Owns(&appsv1.DaemonSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&batchv1.CronJob{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.ServiceAccount{}).
		Named("securityagent").
		Complete(r)
}

// generationChangedPredicate returns a predicate that filters out update events
// where the spec generation has not changed, preventing infinite reconcile loops.
func generationChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// For SecurityAgent: only reconcile if generation changed (spec changed)
			if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
				return true
			}
			// Always reconcile for owned resources (DaemonSet, Deployment, etc.)
			// Check if this is a SecurityAgent by looking at the GVK
			_, isSA := e.ObjectNew.(*securityv1alpha1.SecurityAgent)
			return !isSA
		},
		CreateFunc:  func(e event.CreateEvent) bool { return true },
		DeleteFunc:  func(e event.DeleteEvent) bool { return true },
		GenericFunc: func(e event.GenericEvent) bool { return true },
	}
}

// namespacedName is a helper to build types.NamespacedName.
func namespacedName(ns, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: ns, Name: name}
}

// Ensure namespacedName is used to avoid "declared but not used" error.
var _ = namespacedName
