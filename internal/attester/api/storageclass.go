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

package api

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
)

// RBAC is in charts/topolvm/templates/attester, not in kubebuilder markers:
// topolvm's `make manifests` would merge markers into topolvm-controller's role.

// isDefaultClassAnnotation marks the cluster's default StorageClass.
const isDefaultClassAnnotation = "storageclass.kubernetes.io/is-default-class"

// usesStorageClass reports whether any volume of pod is provisioned from
// s.StorageClassName, through a PVC or a generic ephemeral volume (whose PVC
// carries the template's class). A missing PVC counts as not matching.
func (s *Server) usesStorageClass(ctx context.Context, pod *corev1.Pod) (bool, error) {
	for _, v := range pod.Spec.Volumes {
		var className *string
		switch {
		case v.PersistentVolumeClaim != nil:
			var pvc corev1.PersistentVolumeClaim
			key := types.NamespacedName{Namespace: pod.Namespace, Name: v.PersistentVolumeClaim.ClaimName}
			if err := s.Reader.Get(ctx, key, &pvc); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return false, fmt.Errorf("get PVC %s: %w", key, err)
			}
			className = pvc.Spec.StorageClassName
		case v.Ephemeral != nil && v.Ephemeral.VolumeClaimTemplate != nil:
			className = v.Ephemeral.VolumeClaimTemplate.Spec.StorageClassName
		default:
			continue
		}

		name := ""
		if className != nil {
			name = *className
		}
		if name == "" {
			var err error
			if name, err = s.defaultStorageClass(ctx); err != nil {
				return false, err
			}
		}
		if name == s.StorageClassName {
			return true, nil
		}
	}
	return false, nil
}

// defaultStorageClass returns the name of the cluster's default StorageClass,
// or "" when there is none.
func (s *Server) defaultStorageClass(ctx context.Context) (string, error) {
	var classes storagev1.StorageClassList
	if err := s.Reader.List(ctx, &classes); err != nil {
		return "", fmt.Errorf("list StorageClasses: %w", err)
	}
	for _, sc := range classes.Items {
		if sc.Annotations[isDefaultClassAnnotation] == "true" {
			return sc.Name, nil
		}
	}
	return "", nil
}
