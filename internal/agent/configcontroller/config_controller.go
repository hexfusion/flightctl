package configcontroller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/flightctl/flightctl/api/v1alpha1"
	"github.com/flightctl/flightctl/client"
	"github.com/flightctl/flightctl/internal/agent/device"
	"github.com/flightctl/flightctl/internal/agent/export"
	"github.com/flightctl/flightctl/internal/agent/observe"
)

const (
	// name of the client certificate file
	clientCertFile = "client.crt"
	// maxUpdateBackoff is the maximum time to react to a change as we back off
	// in the face of errors.
	maxUpdateBackoff = 60 * time.Second
	// updateDelay is the time to wait before we react to change.
	updateDelay = 5 * time.Second
)

type ConfigController struct {
	caFilePath           string
	device               *device.Device
	deviceWriter         *device.Writer
	deviceStatusExporter export.DeviceStatus
	deviceObserver       *observe.Device
	queue                workqueue.RateLimitingInterface

	enrollmentClient        *client.Enrollment
	enrollmentVerifyBackoff wait.Backoff
	enrollmentEndpoint      string

	managementClient       *client.Management
	managementEndpoint     string
	managementCertFilePath string
	managementKeyFilePath  string

	// The device fingerprint
	enrollmentCSR []byte
	// The log prefix used for testing
	logPrefix string
	// The directory to write the certificate to
	certDir string
}

func New(
	device *device.Device,
	enrollmentClient *client.Enrollment,
	enrollmentEndpoint string,
	managementEndpoint string,
	caFilePath string,
	managementCertFilePath string,
	managementKeyFilePath string,
	deviceWriter *device.Writer,
	deviceStatusExporter export.DeviceStatus,
	enrollmentCSR []byte,
	logPrefix string,
) *ConfigController {

	enrollmentVerifyBackoff := wait.Backoff{
		Cap:      3 * time.Minute,
		Duration: 10 * time.Second,
		Factor:   1.5,
		Steps:    24,
	}

	c := &ConfigController{
		enrollmentClient:        enrollmentClient,
		enrollmentVerifyBackoff: enrollmentVerifyBackoff,
		enrollmentEndpoint:      enrollmentEndpoint,
		device:                  device,
		deviceWriter:            deviceWriter,
		deviceStatusExporter:    deviceStatusExporter,
		caFilePath:              caFilePath,
		managementEndpoint:      managementEndpoint,
		managementCertFilePath:  managementCertFilePath,
		managementKeyFilePath:   managementKeyFilePath,
		enrollmentCSR:           enrollmentCSR,
		logPrefix:               logPrefix,
	}

	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(updateDelay), 1)},
		workqueue.NewItemExponentialFailureRateLimiter(1*time.Second, maxUpdateBackoff)), "deviceconfig")

	return c
}

func (c *ConfigController) Run(ctx context.Context) {
	klog.Infof("%sstarting device config controller", c.logPrefix)
	defer klog.Infof("%sstopping device config controller", c.logPrefix)

	go wait.UntilWithContext(ctx, c.worker, time.Second)

	for {
		observedDevice := c.deviceObserver.Get(ctx)
		existingDevice := c.deviceStatusExporter.Get(ctx)
		if !equality.Semantic.DeepEqual(existingDevice, observedDevice) {
			klog.V(4).Infof("%s device changed, syncing", c.logPrefix)
		}

		// add regardless of change let the queue handle the rest
		c.queue.Add(observedDevice)
	}
}

type Ignition struct {
	Raw  json.RawMessage `json:"inline"`
	Name string          `json:"name"`
}

func (c *ConfigController) ensureConfig(_ context.Context, device *v1alpha1.Device) error {
	if device.Spec.Config == nil {
		return fmt.Errorf("device config is nil")
	}

	for _, config := range *device.Spec.Config {
		configBytes, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("marshalling config failed: %w", err)
		}

		var ignition Ignition
		err = json.Unmarshal(configBytes, &ignition)
		if err != nil {
			return fmt.Errorf("unmarshalling config failed: %w", err)
		}

		ignitionConfig, err := ParseAndConvertConfig(ignition.Raw)
		if err != nil {
			return fmt.Errorf("parsing and converting config failed: %w", err)
		}

		return c.deviceWriter.WriteIgnitionFiles(ignitionConfig.Storage.Files...)
	}

	return nil
}

func (c *ConfigController) inform(ctx context.Context, device *v1alpha1.Device) {
	if !c.deviceObserver.HasSynced(ctx) || !c.deviceStatusExporter.HasSynced(ctx) {
		klog.V(4).Infof("%s device controller not synced, skipping", c.logPrefix)
		return
	}
	observedDevice := c.deviceObserver.Get(ctx)
	existingDevice := c.deviceStatusExporter.Get(ctx)
	if !equality.Semantic.DeepEqual(existingDevice, observedDevice) {
		klog.V(4).Infof("%s device changed, syncing", c.logPrefix)
	}

	// add regardless of change let the queue handle the rest
	c.queue.Add(observedDevice)
}

func (c *ConfigController) worker(ctx context.Context) {
	for c.processNext(ctx) {
	}
}

func (c *ConfigController) processNext(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.sync(ctx, key.(*v1alpha1.Device))
	c.handleErr(err, key)

	return true
}

func (c *ConfigController) handleErr(err error, key interface{}) {
	if err == nil {
		// work is done
		c.queue.Forget(key)
		return
	}

	klog.V(2).Infof("Error syncing device %v (retries %d): %v", key, c.queue.NumRequeues(key), err)
	c.queue.AddRateLimited(key)
}

func (c *ConfigController) sync(ctx context.Context, device *v1alpha1.Device) error {
	deviceStatus := c.deviceStatusExporter.Get(ctx)
	// ensure the device is enrolled
	if err := c.ensureDeviceEnrollment(ctx, device); err != nil {
		klog.Errorf("%s enrollment did not succeed: %v", c.logPrefix, err)
		return err
	}

	// post enrollment update status
	condition := v1alpha1.DeviceCondition{
		Type:   "Enrolled",
		Status: v1alpha1.True,
	}
	deviceStatus.Conditions = &[]v1alpha1.DeviceCondition{condition}
	_, updateErr := c.managementClient.UpdateDeviceStatus(ctx, *device.Metadata.Name, deviceStatus)
	if updateErr != nil {
		klog.Errorf("%sfailed to update device status: %v", c.logPrefix, updateErr)
		return updateErr
	}

	// ensure the device is configured
	if err := c.ensureConfig(ctx, device); err != nil {
		// TODO
	}

	return nil
}