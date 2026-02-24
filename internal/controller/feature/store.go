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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	securityv1alpha1 "github.com/ctem/security-operator/api/v1alpha1"
)

const (
	// ManagedByLabel is applied to all resources created by this operator.
	ManagedByLabel = "app.kubernetes.io/managed-by"
	// ManagedByValue is the value for the managed-by label.
	ManagedByValue = "security-operator"
	// PartOfLabel identifies which SecurityAgent owns this resource.
	PartOfLabel = "app.kubernetes.io/part-of"
	// FieldOwner is the SSA field manager name.
	FieldOwner = "security-operator"
)

// DesiredStateStore accumulates all Kubernetes resources that the active features want to exist.
// After all Feature.Contribute() calls, ApplyAll() creates/updates them via SSA.
type DesiredStateStore struct {
	namespace string

	DaemonSets          map[string]*appsv1.DaemonSet
	Deployments         map[string]*appsv1.Deployment
	CronJobs            map[string]*batchv1.CronJob
	ConfigMaps          map[string]*corev1.ConfigMap
	Services            map[string]*corev1.Service
	ServiceAccounts     map[string]*corev1.ServiceAccount
	ClusterRoles        map[string]*rbacv1.ClusterRole
	ClusterRoleBindings map[string]*rbacv1.ClusterRoleBinding
	Unstructured        map[string]*unstructured.Unstructured
}

// NewDesiredStateStore creates a new empty store for the given namespace.
func NewDesiredStateStore(namespace string) *DesiredStateStore {
	return &DesiredStateStore{
		namespace:           namespace,
		DaemonSets:          make(map[string]*appsv1.DaemonSet),
		Deployments:         make(map[string]*appsv1.Deployment),
		CronJobs:            make(map[string]*batchv1.CronJob),
		ConfigMaps:          make(map[string]*corev1.ConfigMap),
		Services:            make(map[string]*corev1.Service),
		ServiceAccounts:     make(map[string]*corev1.ServiceAccount),
		ClusterRoles:        make(map[string]*rbacv1.ClusterRole),
		ClusterRoleBindings: make(map[string]*rbacv1.ClusterRoleBinding),
		Unstructured:        make(map[string]*unstructured.Unstructured),
	}
}

// GetNamespace returns the namespace this store manages resources in.
func (s *DesiredStateStore) GetNamespace() string {
	return s.namespace
}

// AddDaemonSet adds a DaemonSet to the store.
func (s *DesiredStateStore) AddDaemonSet(name string, ds *appsv1.DaemonSet) {
	ds.Name = name
	ds.Namespace = s.namespace
	s.DaemonSets[name] = ds
}

// AddDeployment adds a Deployment to the store.
func (s *DesiredStateStore) AddDeployment(name string, deploy *appsv1.Deployment) {
	deploy.Name = name
	deploy.Namespace = s.namespace
	s.Deployments[name] = deploy
}

// AddCronJob adds a CronJob to the store.
func (s *DesiredStateStore) AddCronJob(name string, cj *batchv1.CronJob) {
	cj.Name = name
	cj.Namespace = s.namespace
	s.CronJobs[name] = cj
}

// AddConfigMap adds a ConfigMap to the store.
func (s *DesiredStateStore) AddConfigMap(name string, cm *corev1.ConfigMap) {
	cm.Name = name
	cm.Namespace = s.namespace
	s.ConfigMaps[name] = cm
}

// AddService adds a Service to the store.
func (s *DesiredStateStore) AddService(name string, svc *corev1.Service) {
	svc.Name = name
	svc.Namespace = s.namespace
	s.Services[name] = svc
}

// AddServiceAccount adds a ServiceAccount to the store.
func (s *DesiredStateStore) AddServiceAccount(name string, sa *corev1.ServiceAccount) {
	sa.Name = name
	sa.Namespace = s.namespace
	s.ServiceAccounts[name] = sa
}

// AddClusterRole adds a ClusterRole to the store (cluster-scoped, no namespace).
func (s *DesiredStateStore) AddClusterRole(name string, cr *rbacv1.ClusterRole) {
	cr.Name = name
	s.ClusterRoles[name] = cr
}

// AddClusterRoleBinding adds a ClusterRoleBinding to the store (cluster-scoped, no namespace).
func (s *DesiredStateStore) AddClusterRoleBinding(name string, crb *rbacv1.ClusterRoleBinding) {
	crb.Name = name
	s.ClusterRoleBindings[name] = crb
}

// AddUnstructured adds an arbitrary Unstructured resource (e.g., TracingPolicy CRD) to the store.
// Cluster-scoped resources (like TracingPolicy) should NOT have a namespace set.
func (s *DesiredStateStore) AddUnstructured(name string, obj *unstructured.Unstructured) {
	obj.SetName(name)
	s.Unstructured[name] = obj
}

// GetAllResourceKeys returns a set of "Kind/name" strings for GC comparison.
func (s *DesiredStateStore) GetAllResourceKeys() map[string]bool {
	keys := make(map[string]bool)
	for name := range s.DaemonSets {
		keys["DaemonSet/"+name] = true
	}
	for name := range s.Deployments {
		keys["Deployment/"+name] = true
	}
	for name := range s.CronJobs {
		keys["CronJob/"+name] = true
	}
	for name := range s.ConfigMaps {
		keys["ConfigMap/"+name] = true
	}
	for name := range s.Services {
		keys["Service/"+name] = true
	}
	for name := range s.ServiceAccounts {
		keys["ServiceAccount/"+name] = true
	}
	for name := range s.ClusterRoles {
		keys["ClusterRole/"+name] = true
	}
	for name := range s.ClusterRoleBindings {
		keys["ClusterRoleBinding/"+name] = true
	}
	for name := range s.Unstructured {
		obj := s.Unstructured[name]
		kind := obj.GetKind()
		if kind == "" {
			kind = "Unstructured"
		}
		keys[kind+"/"+name] = true
	}
	return keys
}

// ApplyAll creates or updates all resources in the store via Server-Side Apply.
// Namespaced resources get an OwnerReference pointing to the SecurityAgent.
// Cluster-scoped resources get a label for GC instead of OwnerReference.
func (s *DesiredStateStore) ApplyAll(ctx context.Context, c client.Client, owner *securityv1alpha1.SecurityAgent, scheme *runtime.Scheme) error {
	partOfValue := fmt.Sprintf("%s-%s", owner.Namespace, owner.Name)

	// Apply DaemonSets
	for _, ds := range s.DaemonSets {
		setManagedLabels(ds, partOfValue)
		if err := setOwnerRef(owner, ds, scheme); err != nil {
			return fmt.Errorf("set owner ref DaemonSet %s: %w", ds.Name, err)
		}
		if err := ssaApply(ctx, c, ds); err != nil {
			return fmt.Errorf("apply DaemonSet %s: %w", ds.Name, err)
		}
	}

	// Apply Deployments
	for _, deploy := range s.Deployments {
		setManagedLabels(deploy, partOfValue)
		if err := setOwnerRef(owner, deploy, scheme); err != nil {
			return fmt.Errorf("set owner ref Deployment %s: %w", deploy.Name, err)
		}
		if err := ssaApply(ctx, c, deploy); err != nil {
			return fmt.Errorf("apply Deployment %s: %w", deploy.Name, err)
		}
	}

	// Apply CronJobs
	for _, cj := range s.CronJobs {
		setManagedLabels(cj, partOfValue)
		if err := setOwnerRef(owner, cj, scheme); err != nil {
			return fmt.Errorf("set owner ref CronJob %s: %w", cj.Name, err)
		}
		if err := ssaApply(ctx, c, cj); err != nil {
			return fmt.Errorf("apply CronJob %s: %w", cj.Name, err)
		}
	}

	// Apply ConfigMaps
	for _, cm := range s.ConfigMaps {
		setManagedLabels(cm, partOfValue)
		if err := setOwnerRef(owner, cm, scheme); err != nil {
			return fmt.Errorf("set owner ref ConfigMap %s: %w", cm.Name, err)
		}
		if err := ssaApply(ctx, c, cm); err != nil {
			return fmt.Errorf("apply ConfigMap %s: %w", cm.Name, err)
		}
	}

	// Apply Services
	for _, svc := range s.Services {
		setManagedLabels(svc, partOfValue)
		if err := setOwnerRef(owner, svc, scheme); err != nil {
			return fmt.Errorf("set owner ref Service %s: %w", svc.Name, err)
		}
		if err := ssaApply(ctx, c, svc); err != nil {
			return fmt.Errorf("apply Service %s: %w", svc.Name, err)
		}
	}

	// Apply ServiceAccounts
	for _, sa := range s.ServiceAccounts {
		setManagedLabels(sa, partOfValue)
		if err := setOwnerRef(owner, sa, scheme); err != nil {
			return fmt.Errorf("set owner ref ServiceAccount %s: %w", sa.Name, err)
		}
		if err := ssaApply(ctx, c, sa); err != nil {
			return fmt.Errorf("apply ServiceAccount %s: %w", sa.Name, err)
		}
	}

	// Apply ClusterRoles — cluster-scoped, use labels not OwnerReference
	for _, cr := range s.ClusterRoles {
		setClusterScopedLabels(cr, partOfValue)
		if err := ssaApply(ctx, c, cr); err != nil {
			return fmt.Errorf("apply ClusterRole %s: %w", cr.Name, err)
		}
	}

	// Apply ClusterRoleBindings — cluster-scoped, use labels not OwnerReference
	for _, crb := range s.ClusterRoleBindings {
		setClusterScopedLabels(crb, partOfValue)
		if err := ssaApply(ctx, c, crb); err != nil {
			return fmt.Errorf("apply ClusterRoleBinding %s: %w", crb.Name, err)
		}
	}

	// Apply Unstructured resources (e.g., TracingPolicy)
	for _, obj := range s.Unstructured {
		labels := obj.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		labels[ManagedByLabel] = ManagedByValue
		labels[PartOfLabel] = partOfValue
		obj.SetLabels(labels)
		if err := ssaApplyUnstructured(ctx, c, obj); err != nil {
			return fmt.Errorf("apply %s %s: %w", obj.GetKind(), obj.GetName(), err)
		}
	}

	return nil
}

// setManagedLabels sets standard operator labels on a namespaced resource.
func setManagedLabels(obj metav1.Object, partOfValue string) {
	labels := obj.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	labels[ManagedByLabel] = ManagedByValue
	labels[PartOfLabel] = partOfValue
	obj.SetLabels(labels)
}

// setClusterScopedLabels sets standard operator labels on a cluster-scoped resource.
func setClusterScopedLabels(obj metav1.Object, partOfValue string) {
	setManagedLabels(obj, partOfValue)
}

// setOwnerRef sets the OwnerReference on a namespaced resource.
// Only sets OwnerReference when the resource is in the same namespace as the owner,
// since cross-namespace OwnerReferences are invalid in Kubernetes.
func setOwnerRef(owner *securityv1alpha1.SecurityAgent, obj client.Object, scheme *runtime.Scheme) error {
	if obj.GetNamespace() != owner.Namespace {
		// Cross-namespace: use labels instead of OwnerReference
		return nil
	}
	return controllerutil.SetControllerReference(owner, obj, scheme)
}

// ssaApply performs a Server-Side Apply patch.
func ssaApply(ctx context.Context, c client.Client, obj client.Object) error {
	obj.SetManagedFields(nil)
	if err := c.Patch(ctx, obj, client.Apply,
		client.FieldOwner(FieldOwner),
		client.ForceOwnership,
	); err != nil {
		if apierrors.IsNotFound(err) {
			// Fallback: create if SSA fails with not-found (shouldn't happen with SSA, but be safe)
			return c.Create(ctx, obj)
		}
		return err
	}
	return nil
}

// ssaApplyUnstructured performs a Server-Side Apply patch for Unstructured resources.
func ssaApplyUnstructured(ctx context.Context, c client.Client, obj *unstructured.Unstructured) error {
	obj.SetManagedFields(nil)
	if err := c.Patch(ctx, obj, client.Apply,
		client.FieldOwner(FieldOwner),
		client.ForceOwnership,
	); err != nil {
		if apierrors.IsNotFound(err) {
			return c.Create(ctx, obj)
		}
		return err
	}
	return nil
}
