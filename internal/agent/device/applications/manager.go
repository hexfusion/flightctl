package applications

import (
	"context"
	"fmt"

	"github.com/flightctl/flightctl/api/v1alpha1"
	"github.com/flightctl/flightctl/internal/agent/client"
	"github.com/flightctl/flightctl/internal/agent/device/applications/provider"
	"github.com/flightctl/flightctl/internal/agent/device/dependency"
	"github.com/flightctl/flightctl/internal/agent/device/errors"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/internal/agent/device/status"
	"github.com/flightctl/flightctl/internal/agent/device/systeminfo"
	"github.com/flightctl/flightctl/pkg/log"
)

const (
	pullAuthPath = "/root/.config/containers/auth.json"
)

var _ Manager = (*manager)(nil)

type manager struct {
	podmanMonitor *PodmanMonitor
	podmanClient  *client.Podman
	readWriter    fileio.ReadWriter
	log           *log.PrefixLogger
}

func NewManager(
	log *log.PrefixLogger,
	readWriter fileio.ReadWriter,
	podmanClient *client.Podman,
	systemInfo systeminfo.Manager,
) Manager {
	bootTime := systemInfo.BootTime()
	return &manager{
		readWriter:    readWriter,
		podmanMonitor: NewPodmanMonitor(log, podmanClient, bootTime, readWriter),
		podmanClient:  podmanClient,
		log:           log,
	}
}

func (m *manager) Ensure(ctx context.Context, provider provider.Provider) error {
	appType := provider.Spec().AppType
	switch appType {
	case v1alpha1.AppTypeCompose:
		if m.podmanMonitor.Has(provider.Spec().ID) {
			return nil
		}
		if err := provider.Install(ctx); err != nil {
			// For embedded apps, don't fail the sync - just log and track them
			// They'll show as failed/degraded in status
			if provider.Spec().Embedded {
				m.log.Warnf("Embedded application %s failed to install: %v", provider.Name(), err)
				// Still add to monitor to track its failed state
				return m.podmanMonitor.Ensure(NewApplication(provider))
			}
			return fmt.Errorf("installing application: %w", err)
		}
		return m.podmanMonitor.Ensure(NewApplication(provider))
	default:
		return fmt.Errorf("%w: %s", errors.ErrUnsupportedAppType, appType)
	}
}

func (m *manager) Remove(ctx context.Context, provider provider.Provider) error {
	appType := provider.Spec().AppType
	switch appType {
	case v1alpha1.AppTypeCompose:
		if err := provider.Remove(ctx); err != nil {
			return fmt.Errorf("removing application: %w", err)
		}
		return m.podmanMonitor.Remove(NewApplication(provider))
	default:
		return fmt.Errorf("%w: %s", errors.ErrUnsupportedAppType, appType)
	}
}

func (m *manager) Update(ctx context.Context, provider provider.Provider) error {
	appType := provider.Spec().AppType
	switch appType {
	case v1alpha1.AppTypeCompose:
		if err := provider.Remove(ctx); err != nil {
			return fmt.Errorf("removing application: %w", err)
		}
		if err := provider.Install(ctx); err != nil {
			return fmt.Errorf("installing application: %w", err)
		}
		return m.podmanMonitor.Update(NewApplication(provider))
	default:
		return fmt.Errorf("%w: %s", errors.ErrUnsupportedAppType, appType)
	}
}

func (m *manager) BeforeUpdate(ctx context.Context, desired *v1alpha1.DeviceSpec) error {
	m.log.Debug("Pre-checking application dependencies")
	defer m.log.Debug("Finished pre-checking application dependencies")

	_, err := provider.FromDeviceSpec(ctx, m.log, m.podmanMonitor.client, m.readWriter, desired, provider.WithVerify())
	if err != nil {
		return fmt.Errorf("spec declared application verification failed: %w", err)
	}

	// Skip verification of embedded apps - they're already on disk and may have
	// test/invalid images that would fail prefetch. They'll be validated during
	// actual execution if they're not already running.
	_, err = provider.FromFilesystem(ctx, m.log, m.podmanMonitor.client, m.readWriter)
	if err != nil {
		return fmt.Errorf("embedded application discovery failed: %w", err)
	}

	return nil
}

func (m *manager) resolvePullSecret(desired *v1alpha1.DeviceSpec) (*client.PullSecret, error) {
	secret, found, err := client.ResolvePullSecret(m.log, m.readWriter, desired, pullAuthPath)
	if err != nil {
		return nil, fmt.Errorf("resolving pull secret: %w", err)
	}
	if !found {
		return nil, nil
	}
	return secret, nil
}

func (m *manager) collectOCITargets(providers []provider.Provider, secret *client.PullSecret) ([]dependency.OCIPullTarget, error) {
	var targets []dependency.OCIPullTarget
	for _, provider := range providers {
		providerTargets, err := provider.OCITargets(secret)
		if err != nil {
			return nil, fmt.Errorf("provider oci targets: %w", err)
		}
		targets = append(targets, providerTargets...)
	}
	return targets, nil
}

func (m *manager) AfterUpdate(ctx context.Context) error {
	// execute actions for applications using the podman runtime - this includes
	// compose and quadlets
	if err := m.podmanMonitor.ExecuteActions(ctx); err != nil {
		return fmt.Errorf("error executing actions: %w", err)
	}
	return nil
}

func (m *manager) Status(ctx context.Context, status *v1alpha1.DeviceStatus, opts ...status.CollectorOpt) error {
	applicationsStatus, applicationSummary, err := m.podmanMonitor.Status()
	if err != nil {
		return err
	}

	status.ApplicationsSummary.Status = applicationSummary.Status
	status.ApplicationsSummary.Info = applicationSummary.Info
	status.Applications = applicationsStatus
	return nil
}

func (m *manager) Stop(ctx context.Context) error {
	return m.podmanMonitor.Stop(ctx)
}

// CollectOCITargets returns a function that collects OCI targets from applications
func (m *manager) CollectOCITargets(ctx context.Context, current, desired *v1alpha1.DeviceSpec) ([]dependency.OCIPullTarget, error) {
	m.log.Debug("Collecting OCI targets from applications")

	providers, err := provider.FromDeviceSpec(ctx, m.log, m.podmanMonitor.client, m.readWriter, desired)
	if err != nil {
		return nil, fmt.Errorf("parsing applications: %w", err)
	}

	embeddedProviders, err := provider.FromFilesystem(ctx, m.log, m.podmanMonitor.client, m.readWriter)
	if err != nil {
		m.log.Warnf("Failed to parse embedded applications for OCI targets: %v", err)
	} else {
		providers = append(providers, embeddedProviders...)
	}

	if len(providers) == 0 {
		m.log.Debug("No applications to collect OCI targets from")
		return nil, nil
	}

	// resolve pull secret
	secret, err := m.resolvePullSecret(desired)
	if err != nil {
		return nil, fmt.Errorf("resolving pull secret: %w", err)
	}

	targets, err := m.collectOCITargets(providers, secret)
	if err != nil {
		return nil, fmt.Errorf("collecting OCI targets: %w", err)
	}

	return targets, nil
}
