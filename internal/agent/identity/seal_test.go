package identity

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/pkg/executer"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestPasswordSealer_KeySelection tests that the right sealing key is chosen
func TestPasswordSealer_KeySelection(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("flightctl-agent uses host-only key", func(t *testing.T) {
		mockRW := fileio.NewMockReadWriter(ctrl)
		mockExec := executer.NewMockExecuter(ctrl)
		log := log.NewPrefixLogger("test")

		// Create a temp file for the test
		tempFile, err := os.CreateTemp("", "test-*.tmp")
		require.NoError(err)
		defer os.Remove(tempFile.Name())

		// Mock system checks
		mockExec.EXPECT().LookPath("systemd-creds").Return("/usr/bin/systemd-creds", nil)
		mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemd-creds", "--version").Return(
			"systemd 253 (253.10-1.fc38)\n", "", 0).AnyTimes()
		mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemd-creds", "has-tpm2").Return(
			"", "", 0).AnyTimes()

		// Mock directory creation
		mockRW.EXPECT().MkdirAll(gomock.Any(), gomock.Any()).Return(nil)

		// Mock temp file creation and cleanup
		mockExec.EXPECT().TempFile(gomock.Any(), gomock.Any()).Return(tempFile, nil)
		mockRW.EXPECT().WriteFile(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		mockRW.EXPECT().ReadFile(gomock.Any()).Return([]byte("test"), nil).AnyTimes()
		mockRW.EXPECT().OverwriteAndWipe(gomock.Any()).Return(nil).AnyTimes()
		mockRW.EXPECT().RemoveFile(gomock.Any()).Return(nil).AnyTimes()
		mockRW.EXPECT().PathExists(gomock.Any()).Return(true, nil).AnyTimes()

		// Expect the actual encrypt command with host-only key
		cmd := &exec.Cmd{}
		mockExec.EXPECT().CommandContext(
			gomock.Any(), gomock.Any(),
			"encrypt", "--with-key=host", "--name=test-password", gomock.Any(), gomock.Any(),
		).Return(cmd).Times(1)

		sealer, _ := NewSealer(log, mockRW, mockExec)
		err = sealer.Seal(context.Background(), "flightctl-agent", SealKeyHost, []byte("test"))

		require.NoError(err)
	})
}

// TestPasswordSealer_GeneratePassword tests password generation
func TestPasswordSealer_GeneratePassword(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRW := fileio.NewMockReadWriter(ctrl)
	mockExec := executer.NewMockExecuter(ctrl)
	log := log.NewPrefixLogger("test")

	// Mock system checks
	mockExec.EXPECT().LookPath("systemd-creds").Return("/usr/bin/systemd-creds", nil)
	mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemd-creds", "--version").Return(
		"systemd 253 (253.10-1.fc38)\n", "", 0).AnyTimes()
	mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemd-creds", "has-tpm2").Return(
		"", "", 0).AnyTimes()

	// Mock directory creation
	mockRW.EXPECT().MkdirAll(gomock.Any(), gomock.Any()).Return(nil)

	// Mock temp file creation
	tempFile := &os.File{}
	mockExec.EXPECT().TempFile(gomock.Any(), gomock.Any()).Return(tempFile, nil)
	mockRW.EXPECT().WriteFile(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	// Mock encryption command
	cmd := &exec.Cmd{}
	mockExec.EXPECT().CommandContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(cmd)
	mockRW.EXPECT().PathExists(gomock.Any()).Return(true, nil)

	// Mock cleanup
	mockRW.EXPECT().OverwriteAndWipe(gomock.Any()).Return(nil).AnyTimes()
	mockRW.EXPECT().RemoveFile(gomock.Any()).Return(nil).AnyTimes()

	// We'll capture the password written to temp file
	var capturedPassword []byte
	mockRW.EXPECT().ReadFile(gomock.Any()).
		DoAndReturn(func(path string) ([]byte, error) {
			return capturedPassword, nil
		}).AnyTimes()

	sealer, _ := NewSealer(log, mockRW, mockExec)
	// Generate password (would normally come from identity layer)
	password := make([]byte, 32)
	for i := range password {
		password[i] = byte(i)
	}

	// Seal it
	err := sealer.Seal(context.Background(), "test-service", SealKeyHost, password)
	require.NoError(err)
}

// TestPasswordSealer_VerifyFromPath tests verification of sealed credentials
func TestPasswordSealer_VerifyFromPath(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("successful verification", func(t *testing.T) {
		mockRW := fileio.NewMockReadWriter(ctrl)
		mockExec := executer.NewMockExecuter(ctrl)
		log := log.NewPrefixLogger("test")

		mockExec.EXPECT().LookPath(gomock.Any()).Return("/usr/bin/systemd-creds", nil).AnyTimes()
		mockExec.EXPECT().ExecuteWithContext(gomock.Any(), gomock.Any(), "--version").
			Return("systemd 252\n", "", 0).AnyTimes()
		mockRW.EXPECT().PathExists("/test/sealed").Return(true, nil)
		mockExec.EXPECT().ExecuteWithContext(gomock.Any(), gomock.Any(), "decrypt", "/test/sealed", "-").
			Return("password", "", 0)

		sealer, _ := NewSealer(log, mockRW, mockExec)
		err := sealer.VerifyFromPath(context.Background(), "/test/sealed")
		require.NoError(err)
	})

	t.Run("file not found", func(t *testing.T) {
		mockRW := fileio.NewMockReadWriter(ctrl)
		mockExec := executer.NewMockExecuter(ctrl)
		log := log.NewPrefixLogger("test")

		mockExec.EXPECT().LookPath(gomock.Any()).Return("/usr/bin/systemd-creds", nil).AnyTimes()
		mockExec.EXPECT().ExecuteWithContext(gomock.Any(), gomock.Any(), "--version").
			Return("systemd 252\n", "", 0).AnyTimes()
		mockRW.EXPECT().PathExists("/test/sealed").Return(false, nil)

		sealer, _ := NewSealer(log, mockRW, mockExec)
		err := sealer.VerifyFromPath(context.Background(), "/test/sealed")
		require.Error(err)
		require.Contains(err.Error(), "sealed file not found")
	})
}
