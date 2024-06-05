// Code generated by MockGen. DO NOT EDIT.
// Source: internal/agent/device/app/app.go
//
// Generated by this command:
//
//	mockgen -source=internal/agent/device/app/app.go -destination=internal/agent/device/app/mock_app.go -package=app
//

// Package app is a generated GoMock package.
package app

import (
	context "context"
	reflect "reflect"

	v1alpha1 "github.com/flightctl/flightctl/api/v1alpha1"
	gomock "go.uber.org/mock/gomock"
)

// MockEngine is a mock of Engine interface.
type MockEngine struct {
	ctrl     *gomock.Controller
	recorder *MockEngineMockRecorder
}

// MockEngineMockRecorder is the mock recorder for MockEngine.
type MockEngineMockRecorder struct {
	mock *MockEngine
}

// NewMockEngine creates a new mock instance.
func NewMockEngine(ctrl *gomock.Controller) *MockEngine {
	mock := &MockEngine{ctrl: ctrl}
	mock.recorder = &MockEngineMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEngine) EXPECT() *MockEngineMockRecorder {
	return m.recorder
}

// GetStatus mocks base method.
func (m *MockEngine) GetStatus(ctx context.Context, id string) (*v1alpha1.ApplicationStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetStatus", ctx, id)
	ret0, _ := ret[0].(*v1alpha1.ApplicationStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetStatus indicates an expected call of GetStatus.
func (mr *MockEngineMockRecorder) GetStatus(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetStatus", reflect.TypeOf((*MockEngine)(nil).GetStatus), ctx, id)
}

// List mocks base method.
func (m *MockEngine) List(ctx context.Context, matchPatterns ...string) ([]v1alpha1.ApplicationStatus, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx}
	for _, a := range matchPatterns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "List", varargs...)
	ret0, _ := ret[0].([]v1alpha1.ApplicationStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockEngineMockRecorder) List(ctx any, matchPatterns ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx}, matchPatterns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockEngine)(nil).List), varargs...)
}

// MockRuntime is a mock of Runtime interface.
type MockRuntime struct {
	ctrl     *gomock.Controller
	recorder *MockRuntimeMockRecorder
}

// MockRuntimeMockRecorder is the mock recorder for MockRuntime.
type MockRuntimeMockRecorder struct {
	mock *MockRuntime
}

// NewMockRuntime creates a new mock instance.
func NewMockRuntime(ctrl *gomock.Controller) *MockRuntime {
	mock := &MockRuntime{ctrl: ctrl}
	mock.recorder = &MockRuntimeMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRuntime) EXPECT() *MockRuntimeMockRecorder {
	return m.recorder
}

// GetStatus mocks base method.
func (m *MockRuntime) GetStatus(ctx context.Context, id string) (*v1alpha1.ApplicationStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetStatus", ctx, id)
	ret0, _ := ret[0].(*v1alpha1.ApplicationStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetStatus indicates an expected call of GetStatus.
func (mr *MockRuntimeMockRecorder) GetStatus(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetStatus", reflect.TypeOf((*MockRuntime)(nil).GetStatus), ctx, id)
}

// ImageExists mocks base method.
func (m *MockRuntime) ImageExists(ctx context.Context, name string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageExists", ctx, name)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImageExists indicates an expected call of ImageExists.
func (mr *MockRuntimeMockRecorder) ImageExists(ctx, name any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageExists", reflect.TypeOf((*MockRuntime)(nil).ImageExists), ctx, name)
}

// List mocks base method.
func (m *MockRuntime) List(ctx context.Context, matchPatterns ...string) ([]v1alpha1.ApplicationStatus, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx}
	for _, a := range matchPatterns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "List", varargs...)
	ret0, _ := ret[0].([]v1alpha1.ApplicationStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockRuntimeMockRecorder) List(ctx any, matchPatterns ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx}, matchPatterns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockRuntime)(nil).List), varargs...)
}

// PullImage mocks base method.
func (m *MockRuntime) PullImage(ctx context.Context, name string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PullImage", ctx, name)
	ret0, _ := ret[0].(error)
	return ret0
}

// PullImage indicates an expected call of PullImage.
func (mr *MockRuntimeMockRecorder) PullImage(ctx, name any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PullImage", reflect.TypeOf((*MockRuntime)(nil).PullImage), ctx, name)
}
