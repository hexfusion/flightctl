package applications

import (
	"context"
	"fmt"

	"github.com/flightctl/flightctl/api/v1alpha1"
	"github.com/flightctl/flightctl/internal/agent/client"
	"github.com/flightctl/flightctl/internal/agent/device/applications/provider"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/internal/agent/device/spec"
	"github.com/flightctl/flightctl/pkg/log"
)

type Controller struct {
	podman     *client.Podman
	readWriter fileio.ReadWriter
	manager    Manager
	log        *log.PrefixLogger
}

func NewController(
	podman *client.Podman,
	manager Manager,
	readWriter fileio.ReadWriter,
	log *log.PrefixLogger,
) *Controller {
	return &Controller{
		log:        log,
		manager:    manager,
		podman:     podman,
		readWriter: readWriter,
	}
}

func (c *Controller) Sync(ctx context.Context, current, desired *v1alpha1.Device) error {
	c.log.Debug("Syncing device applcations")
	defer c.log.Debug("Finished syncing device applications")

	currentSpec := current.Spec
	currentAppProviders, err := provider.FromDeviceSpec(
		ctx,
		c.log,
		c.podman,
		c.readWriter,
		currentSpec,
		provider.WithVerify(),
	)
	if err != nil {
		return fmt.Errorf("current app providers: %w", err)
	}

	desiredSpec := desired.Spec
	desiredAppProviders, err := provider.FromDeviceSpec(
		ctx,
		c.log,
		c.podman,
		c.readWriter,
		desiredSpec,
		provider.WithVerify(),
	)
	if err != nil {
		return fmt.Errorf("desired app providers: %w", err)
	}

	// during rollback, embedded apps should maintain their current state
	// they should not be added to either current or desired to avoid any changes
	isRollback := spec.IsRollback(current, desired)
	if !isRollback {
		// Skip verification for embedded apps - they're already on disk
		// Validation will happen during execution if needed
		embeddedProviders, err := provider.FromFilesystem(
			ctx,
			c.log,
			c.podman,
			c.readWriter,
			// No WithVerify() - embedded apps may have test/invalid images
		)
		if err != nil {
			return fmt.Errorf("embedded app providers: %w", err)
		}
		desiredAppProviders = append(desiredAppProviders, embeddedProviders...)
	}

	return syncProviders(ctx, c.log, c.manager, currentAppProviders, desiredAppProviders)
}

func syncProviders(
	ctx context.Context,
	log *log.PrefixLogger,
	manager Manager,
	currentProviders, desiredProviders []provider.Provider,
) error {
	diff, err := provider.GetDiff(currentProviders, desiredProviders)
	if err != nil {
		return err
	}

	for _, provider := range diff.Removed {
		log.Debugf("Removing application: %s", provider.Name())
		if err := manager.Remove(ctx, provider); err != nil {
			return err
		}
	}

	for _, provider := range diff.Ensure {
		log.Debugf("Ensuring application: %s", provider.Name())
		if err := manager.Ensure(ctx, provider); err != nil {
			return err
		}
	}

	for _, provider := range diff.Changed {
		log.Debugf("Updating application: %s", provider.Name())
		if err := manager.Update(ctx, provider); err != nil {
			return err
		}
	}

	return nil
}
