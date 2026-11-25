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

// The attester agent runs as a DaemonSet on aiDAPTIV nodes and runs Sails against
// the NVMe disks of the node's volume group when the attester asks.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"k8s.io/apimachinery/pkg/types"

	"github.com/topolvm/topolvm/internal/attester/agent"
	"github.com/topolvm/topolvm/internal/attester/attest"
	"github.com/topolvm/topolvm/internal/attester/config"
	"github.com/topolvm/topolvm/internal/attester/kubeauth"
)

// Execute runs topolvm-attester-agent; hypertopolvm calls it.
func Execute() {
	var listenAddr, sailsPath, volumeGroup, lvmPrefix, attesterNamespace, attesterSA, sysClassBlock string
	var serviceAccount, podName, podUID, nodeName string
	var checkTimeout time.Duration
	flag.StringVar(&listenAddr, "listen-address", fmt.Sprintf(":%d", config.DefaultAgentPort),
		"The address the agent API binds to.")
	flag.StringVar(&sailsPath, "sails", "/shared/Sails", "Path of the Sails binary.")
	flag.StringVar(&volumeGroup, "volume-group", config.DefaultVolumeGroup,
		"Volume group checked when a request names none.")
	flag.StringVar(&lvmPrefix, "lvm-command-prefix", strings.Join(agent.DefaultLVMCommandPrefix, " "),
		"Words prepended to every LVM command; the default runs LVM in the host namespaces (needs hostPID). "+
			"Empty runs LVM from the agent image.")
	flag.StringVar(&attesterNamespace, "attester-namespace", envOr("POD_NAMESPACE", config.DefaultNamespace),
		"Namespace of the attester's (and the agent's) ServiceAccount. Defaults to POD_NAMESPACE.")
	flag.StringVar(&attesterSA, "attester-service-account", config.DefaultAttesterServiceAccount,
		"The only ServiceAccount whose tokens (audience "+config.AudienceAgent+") the agent accepts.")
	flag.StringVar(&serviceAccount, "service-account", envOr("POD_SERVICE_ACCOUNT", config.DefaultAgentServiceAccount),
		"The agent's own ServiceAccount, which attests check reports. Defaults to POD_SERVICE_ACCOUNT.")
	flag.StringVar(&podName, "pod-name", os.Getenv("POD_NAME"),
		"The agent's own Pod, which reports are bound to. Defaults to POD_NAME.")
	flag.StringVar(&podUID, "pod-uid", os.Getenv("POD_UID"), "UID of --pod-name. Defaults to POD_UID.")
	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"), "The node the agent runs on. Defaults to NODE_NAME.")
	flag.StringVar(&sysClassBlock, "sys-class-block", agent.DefaultSysClassBlock,
		"sysfs directory used to resolve the disks behind a physical volume.")
	flag.DurationVar(&checkTimeout, "check-timeout", 2*time.Minute, "Time limit of one check (pvs plus Sails).")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	logger := ctrl.Log.WithName("agent")

	checker := &agent.Checker{
		Sails:            sailsPath,
		LVMCommandPrefix: strings.Fields(lvmPrefix),
		SysClassBlock:    sysClassBlock,
		Timeout:          checkTimeout,
	}
	cs, err := kubernetes.NewForConfig(ctrl.GetConfigOrDie())
	if err != nil {
		logger.Error(err, "unable to create the Kubernetes client")
		os.Exit(1)
	}
	if podName == "" || podUID == "" || nodeName == "" {
		// The attester only accepts reports bound to the agent Pod on the
		// node it asked about; without these the agent is useless.
		logger.Error(errors.New("POD_NAME, POD_UID and NODE_NAME are required"), "missing identity")
		os.Exit(1)
	}
	attester := kubeauth.ServiceAccountUsername(attesterNamespace, attesterSA)
	srv := &agent.Server{
		Checker:  checker,
		Auth:     &kubeauth.Reviewer{Client: cs.AuthenticationV1()},
		Attester: attester,
		Attest: &attest.Attester{Minter: &kubeauth.Minter{
			Client: cs.CoreV1(), Namespace: attesterNamespace, ServiceAccount: serviceAccount,
			Pod: &kubeauth.BoundPod{Name: podName, UID: types.UID(podUID)},
		}},
		NodeName:           nodeName,
		DefaultVolumeGroup: volumeGroup,
	}

	ctx := ctrl.SetupSignalHandler()
	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return log.IntoContext(ctx, logger) },
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	logger.Info("starting attester agent", "address", listenAddr, "sails", sailsPath, "volumeGroup", volumeGroup,
		"lvmCommandPrefix", checker.LVMCommandPrefix, "attester", attester, "node", nodeName, "pod", podName)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error(err, "agent server failed")
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
