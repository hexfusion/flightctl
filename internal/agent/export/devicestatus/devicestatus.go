package devicestatus

import (
	"context"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/flightctl/flightctl/api/v1alpha1"
	"github.com/flightctl/flightctl/internal/tpm"
	"github.com/flightctl/flightctl/pkg/executer"
)

var _ Getter = (*Manager)(nil)

// NewCollector creates a new device status collector.
func NewManager(tpm *tpm.TPM, executor executer.Executer) *Manager {
	exporters := []Exporter{
		newSystemD(executor),
		newContainer(executor),
		newSystemInfo(tpm),
	}

	return &Manager{
		exporters: exporters,
	}
}

// Manager aggregates device status from various exporters.
type Manager struct {
	exporters    []Exporter
	pollInterval time.Duration
	logPrefix    string
	cancelFn     context.CancelFunc

	mu           sync.Mutex
	deviceStatus v1alpha1.DeviceStatus
	hasSynced    bool
}

type Exporter interface {
	Export(ctx context.Context, device *v1alpha1.DeviceStatus) error
}

type Getter interface {
	Get(context.Context) v1alpha1.DeviceStatus
	HasSynced(context.Context) bool
}

func (m *Manager) Run(ctx context.Context) error {
	klog.Infof("%sstarting device exporter", m.logPrefix)
	defer klog.Infof("%sstopping device exporter", m.logPrefix)

	ctx, m.cancelFn = context.WithCancel(ctx)

	wait.PollInfiniteWithContext(ctx, m.pollInterval, func(ctx context.Context) (bool, error) {
		deviceStatus, err := m.aggregateDeviceStatus(ctx)
		if err != nil {
			klog.Errorf("error getting device status: %v", err)
			return false, nil
		}
		m.mu.Lock()
		m.deviceStatus = deviceStatus
		m.hasSynced = true
		m.mu.Unlock()
		return true, nil
	})

	return nil
}

func (m *Manager) aggregateDeviceStatus(ctx context.Context) (v1alpha1.DeviceStatus, error) {
	deviceStatus := v1alpha1.DeviceStatus{}
	for _, exporter := range m.exporters {
		err := exporter.Export(ctx, &deviceStatus)
		if err != nil {
			klog.Errorf("failed getting status from exporter: %v", err)
			continue
		}
	}

	return deviceStatus, nil
}

func (m *Manager) Get(context.Context) v1alpha1.DeviceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deviceStatus
}

func (m *Manager) HasSynced(context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hasSynced
}