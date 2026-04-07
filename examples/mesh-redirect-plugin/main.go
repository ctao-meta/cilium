// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/api/v1/datapathplugins"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	ciliumVersionMetadataKey = "cilium_version"
	pluginName               = "mesh-redirect"

	preHookName = "before"
)

// Programs we want to hook for mesh traffic redirection.
// These are TC ingress entry-point programs where sk_assign works.
var hookTargets = map[string]bool{
	"cil_from_netdev":    true, // cross-node inbound (physical NIC ingress)
	"cil_from_container": true, // same-node pod-to-pod + outbound (host-side veth ingress)
}

func main() {
	unixSocketPath := flag.String(
		"unix-socket-path", "",
		"UNIX socket to listen on",
	)
	flag.Parse()

	logger := slog.Default()
	logger.Info("Starting mesh-redirect plugin", "listenPath", *unixSocketPath)
	os.Remove(*unixSocketPath)

	if err := runServer(logger, *unixSocketPath); err != nil {
		logger.Error("Plugin server stopped", "error", err)
		os.Exit(1)
	}
}

func runServer(logger *slog.Logger, sockPath string) error {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return fmt.Errorf("resolving address: %w", err)
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("starting listener: %w", err)
	}

	server := grpc.NewServer()
	datapathplugins.RegisterDatapathPluginServer(server, &meshRedirectPlugin{
		logger: logger,
	})

	return server.Serve(listener)
}

type meshRedirectPlugin struct {
	logger *slog.Logger
}

func (p *meshRedirectPlugin) PrepareCollection(
	ctx context.Context,
	req *datapathplugins.PrepareCollectionRequest,
) (*datapathplugins.PrepareCollectionResponse, error) {
	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec

	// Only hook TC (skb) attachment contexts.
	switch req.AttachmentContext.Context.(type) {
	case *datapathplugins.AttachmentContext_Host_,
		*datapathplugins.AttachmentContext_Lxc,
		*datapathplugins.AttachmentContext_Overlay_:
		hooks = p.prepareHooks(req.GetCollection().GetPrograms())
	default:
		return &datapathplugins.PrepareCollectionResponse{}, nil
	}

	id := uuid.New().String()
	resp := &datapathplugins.PrepareCollectionResponse{
		Hooks:  hooks,
		Cookie: id,
	}

	p.logger.Info("PrepareCollection",
		"ciliumVersion", ciliumVersion(ctx),
		"traceId", id,
		"hooks", len(hooks),
	)

	return resp, nil
}

func (p *meshRedirectPlugin) prepareHooks(
	programs map[string]*datapathplugins.PrepareCollectionRequest_CollectionSpec_ProgramSpec,
) []*datapathplugins.PrepareCollectionResponse_HookSpec {
	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec

	for name, prog := range programs {
		if !hookTargets[name] {
			continue
		}
		// Only hook entry-point programs (section ends with "/entry").
		if prog.SectionName != "tc/entry" {
			continue
		}

		hooks = append(hooks,
			&datapathplugins.PrepareCollectionResponse_HookSpec{
				Type:   datapathplugins.HookType_PRE,
				Target: name,
			},
		)
	}

	return hooks
}

func (p *meshRedirectPlugin) InstrumentCollection(
	ctx context.Context,
	req *datapathplugins.InstrumentCollectionRequest,
) (*datapathplugins.InstrumentCollectionResponse, error) {
	if err := loadAndPin(req.GetHooks(), req.GetPins()); err != nil {
		p.logger.Error("InstrumentCollection",
			"ciliumVersion", ciliumVersion(ctx),
			"traceId", req.GetCookie(),
			"error", err,
		)
		return nil, err
	}

	p.logger.Info("InstrumentCollection",
		"ciliumVersion", ciliumVersion(ctx),
		"traceId", req.GetCookie(),
		"hooks", len(req.GetHooks()),
	)

	return &datapathplugins.InstrumentCollectionResponse{}, nil
}

func loadAndPin(
	hooks []*datapathplugins.InstrumentCollectionRequest_Hook,
	pinsDir string,
) error {
	spec, err := loadRedirect()
	if err != nil {
		return fmt.Errorf("loading BPF spec: %w", err)
	}

	// Group hooks by target.
	hooksByTarget := map[string][]*datapathplugins.InstrumentCollectionRequest_Hook{}
	for _, hook := range hooks {
		hooksByTarget[hook.Target] = append(hooksByTarget[hook.Target], hook)
	}

	// Determine which BPF programs are actually requested.
	requestedProgs := map[string]bool{}
	for _, hook := range hooks {
		if hook.Type == datapathplugins.HookType_PRE {
			requestedProgs[preHookName] = true
		}
	}

	var sharedMap *ebpf.Map

	for target, targetHooks := range hooksByTarget {
		cloned := spec.Copy()

		// Remove BPF programs that aren't requested to avoid load failures
		// (unrequested freplace programs would have no attach target).
		for name := range cloned.Programs {
			if !requestedProgs[name] {
				delete(cloned.Programs, name)
			}
		}

		// Load the target Cilium program by ID.
		targetProg, err := ebpf.NewProgramFromID(
			ebpf.ProgramID(targetHooks[0].AttachTarget.ProgramId),
		)
		if err != nil {
			return fmt.Errorf(
				"loading target program for %s: %w", target, err,
			)
		}
		defer targetProg.Close()

		// Set attach target and subprog name for each hook.
		for _, hook := range targetHooks {
			progName := preHookName
			cloned.Programs[progName].AttachTarget = targetProg
			cloned.Programs[progName].AttachTo = hook.AttachTarget.SubprogName
		}

		// Load the collection, reusing the shared map if available.
		opts := ebpf.CollectionOptions{}
		if sharedMap != nil {
			opts.MapReplacements = map[string]*ebpf.Map{
				"mesh_redirect_map": sharedMap,
			}
		}

		coll, err := ebpf.NewCollectionWithOptions(cloned, opts)
		if err != nil {
			return fmt.Errorf("loading collection for %s: %w", target, err)
		}
		defer coll.Close()

		// Capture the map from the first collection so subsequent ones share it.
		if sharedMap == nil {
			sharedMap = coll.Maps["mesh_redirect_map"]
		}

		// Pin each hook program.
		for _, hook := range targetHooks {
			prog := coll.Programs[preHookName]
			if err := prog.Pin(hook.PinPath); err != nil {
				return fmt.Errorf("pinning %s to %s: %w", preHookName, hook.PinPath, err)
			}
		}
	}

	// Pin the shared map so the control plane can populate it.
	if sharedMap != nil {
		mapPinPath := pinsDir + "/mesh_redirect_map"
		if err := sharedMap.Pin(mapPinPath); err != nil {
			return fmt.Errorf("pinning mesh_redirect_map: %w", err)
		}
	}

	return nil
}

func ciliumVersion(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if v := md.Get(ciliumVersionMetadataKey); len(v) == 1 {
			return v[0]
		}
	}
	return "unknown"
}
