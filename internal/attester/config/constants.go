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

// Package config holds the names attester shares between the API server, the
// node agent and the manifests: audiences, labels and defaults.
package config

import (
	"slices"
	"time"
)

const (
	// DefaultStorageClass is the StorageClass a calling Pod must use.
	DefaultStorageClass = "aidaptiv-cache"
	// DefaultVolumeGroup is the LVM volume group behind that StorageClass
	// (TopoLVM device-class "aidaptiv").
	DefaultVolumeGroup = "vg_aidaptiv"
	// DefaultNamespace is where the attester runs when nothing else says so
	// (TopoLVM's namespace).
	DefaultNamespace = "topolvm-system"
	// DefaultAPIServiceName is the Service name (after the kustomize prefix)
	// Pods reach the API through.
	DefaultAPIServiceName = "topolvm-attester"
	// DefaultAttesterServiceAccount is the attester's ServiceAccount (after
	// the kustomize prefix). Attestations and agent tokens are issued to it.
	DefaultAttesterServiceAccount = "topolvm-attester"
	// DefaultAgentServiceAccount is the agents' ServiceAccount (after the
	// kustomize prefix). Agents attest their reports with it.
	DefaultAgentServiceAccount = "topolvm-attester-agent"

	// AudienceAPI is the audience of the ServiceAccount token a Pod presents
	// to the API (a projected serviceAccountToken volume).
	AudienceAPI = "topolvm-attester"
	// AudienceAgent is the audience of the tokens the attester presents to
	// agents.
	AudienceAgent = "topolvm-attester-agent"
	// AgentTokenTTL is the lifetime of attester-to-agent tokens.
	AgentTokenTTL = 10 * time.Minute

	// AgentLabelKey and AgentLabelValue select the agent Pods, the way the
	// TopoLVM chart labels its components (app.kubernetes.io/name is "topolvm"
	// for all of them).
	AgentLabelKey   = "app.kubernetes.io/component"
	AgentLabelValue = "attester-agent"
	// DefaultAgentPort is the port the agent listens on.
	DefaultAgentPort = 9449
)

// CheckFunctions are the Sails sub-commands the API exposes. Each is served at
// "/<name>" by the attester and at "/v1/check/<name>" by the agent.
var CheckFunctions = []string{"mem_buf_set", "mem_buf_cpy", "support_finetune", "support_inference"}

// IsCheckFunction reports whether name is one of CheckFunctions.
func IsCheckFunction(name string) bool {
	return slices.Contains(CheckFunctions, name)
}
