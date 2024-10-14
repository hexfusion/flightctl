// Code generated by MockGen. DO NOT EDIT.
// Source: internal/agent/device/applications/applications.go
//
// Generated by this command:
//
//	mockgen -source=internal/agent/device/applications/applications.go -destination=internal/agent/device/applications/mock_applications.go -package=applications
//

// Package applications is a generated GoMock package.
package applications

import (
	context "context"
	reflect "reflect"

	v1alpha1 "github.com/flightctl/flightctl/api/v1alpha1"
	gomock "go.uber.org/mock/gomock"
)

// MockMonitor is a mock of Monitor interface.
type MockMonitor struct {
	ctrl     *gomock.Controller
	recorder *MockMonitorMockRecorder
}

// MockMonitorMockRecorder is the mock recorder for MockMonitor.
type MockMonitorMockRecorder struct {
	mock *MockMonitor
}

// NewMockMonitor creates a new mock instance.
func NewMockMonitor(ctrl *gomock.Controller) *MockMonitor {
	mock := &MockMonitor{ctrl: ctrl}
	mock.recorder = &MockMonitorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMonitor) EXPECT() *MockMonitorMockRecorder {
	return m.recorder
}

// Run mocks base method.
func (m *MockMonitor) Run(ctx context.Context) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Run", ctx)
}

// Run indicates an expected call of Run.
func (mr *MockMonitorMockRecorder) Run(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Run", reflect.TypeOf((*MockMonitor)(nil).Run), ctx)
}

// Status mocks base method.
func (m *MockMonitor) Status() []v1alpha1.DeviceApplicationStatus {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].([]v1alpha1.DeviceApplicationStatus)
	return ret0
}

// Status indicates an expected call of Status.
func (mr *MockMonitorMockRecorder) Status() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockMonitor)(nil).Status))
}

// MockManager is a mock of Manager interface.
type MockManager struct {
	ctrl     *gomock.Controller
	recorder *MockManagerMockRecorder
}

// MockManagerMockRecorder is the mock recorder for MockManager.
type MockManagerMockRecorder struct {
	mock *MockManager
}

// NewMockManager creates a new mock instance.
func NewMockManager(ctrl *gomock.Controller) *MockManager {
	mock := &MockManager{ctrl: ctrl}
	mock.recorder = &MockManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManager) EXPECT() *MockManagerMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockManager) Add(app Application) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", app)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockManagerMockRecorder) Add(app any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockManager)(nil).Add), app)
}

// ExecuteActions mocks base method.
func (m *MockManager) ExecuteActions(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExecuteActions", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// ExecuteActions indicates an expected call of ExecuteActions.
func (mr *MockManagerMockRecorder) ExecuteActions(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecuteActions", reflect.TypeOf((*MockManager)(nil).ExecuteActions), ctx)
}

// Remove mocks base method.
func (m *MockManager) Remove(app Application) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remove", app)
	ret0, _ := ret[0].(error)
	return ret0
}

// Remove indicates an expected call of Remove.
func (mr *MockManagerMockRecorder) Remove(app any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockManager)(nil).Remove), app)
}

// Run mocks base method.
func (m *MockManager) Run(ctx context.Context) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Run", ctx)
}

// Run indicates an expected call of Run.
func (mr *MockManagerMockRecorder) Run(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Run", reflect.TypeOf((*MockManager)(nil).Run), ctx)
}

// Status mocks base method.
func (m *MockManager) Status() ([]v1alpha1.DeviceApplicationStatus, v1alpha1.ApplicationsSummaryStatusType, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].([]v1alpha1.DeviceApplicationStatus)
	ret1, _ := ret[1].(v1alpha1.ApplicationsSummaryStatusType)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Status indicates an expected call of Status.
func (mr *MockManagerMockRecorder) Status() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockManager)(nil).Status))
}

// Update mocks base method.
func (m *MockManager) Update(app Application) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", app)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockManagerMockRecorder) Update(app any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockManager)(nil).Update), app)
}

// MockApplication is a mock of Application interface.
type MockApplication struct {
	ctrl     *gomock.Controller
	recorder *MockApplicationMockRecorder
}

// MockApplicationMockRecorder is the mock recorder for MockApplication.
type MockApplicationMockRecorder struct {
	mock *MockApplication
}

// NewMockApplication creates a new mock instance.
func NewMockApplication(ctrl *gomock.Controller) *MockApplication {
	mock := &MockApplication{ctrl: ctrl}
	mock.recorder = &MockApplicationMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockApplication) EXPECT() *MockApplicationMockRecorder {
	return m.recorder
}

// AddContainer mocks base method.
func (m *MockApplication) AddContainer(container Container) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddContainer", container)
}

// AddContainer indicates an expected call of AddContainer.
func (mr *MockApplicationMockRecorder) AddContainer(container any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddContainer", reflect.TypeOf((*MockApplication)(nil).AddContainer), container)
}

// Container mocks base method.
func (m *MockApplication) Container(name string) (*Container, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Container", name)
	ret0, _ := ret[0].(*Container)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// Container indicates an expected call of Container.
func (mr *MockApplicationMockRecorder) Container(name any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Container", reflect.TypeOf((*MockApplication)(nil).Container), name)
}

// EnvVars mocks base method.
func (m *MockApplication) EnvVars() map[string]string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EnvVars")
	ret0, _ := ret[0].(map[string]string)
	return ret0
}

// EnvVars indicates an expected call of EnvVars.
func (mr *MockApplicationMockRecorder) EnvVars() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EnvVars", reflect.TypeOf((*MockApplication)(nil).EnvVars))
}

// Name mocks base method.
func (m *MockApplication) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name.
func (mr *MockApplicationMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockApplication)(nil).Name))
}

// Path mocks base method.
func (m *MockApplication) Path() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Path")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Path indicates an expected call of Path.
func (mr *MockApplicationMockRecorder) Path() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Path", reflect.TypeOf((*MockApplication)(nil).Path))
}

// SetEnvVars mocks base method.
func (m *MockApplication) SetEnvVars(envVars map[string]string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetEnvVars", envVars)
	ret0, _ := ret[0].(bool)
	return ret0
}

// SetEnvVars indicates an expected call of SetEnvVars.
func (mr *MockApplicationMockRecorder) SetEnvVars(envVars any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetEnvVars", reflect.TypeOf((*MockApplication)(nil).SetEnvVars), envVars)
}

// Status mocks base method.
func (m *MockApplication) Status() (*v1alpha1.DeviceApplicationStatus, v1alpha1.ApplicationsSummaryStatusType, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].(*v1alpha1.DeviceApplicationStatus)
	ret1, _ := ret[1].(v1alpha1.ApplicationsSummaryStatusType)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Status indicates an expected call of Status.
func (mr *MockApplicationMockRecorder) Status() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockApplication)(nil).Status))
}

// Type mocks base method.
func (m *MockApplication) Type() AppType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Type")
	ret0, _ := ret[0].(AppType)
	return ret0
}

// Type indicates an expected call of Type.
func (mr *MockApplicationMockRecorder) Type() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Type", reflect.TypeOf((*MockApplication)(nil).Type))
}
