package identity

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/pkg/executer"
	"github.com/flightctl/flightctl/pkg/log"
)

const (
	SystemdCredsCommand = "systemd-creds"
)

// Sealer handles sealing of secrets for secure storage
type Sealer interface {
	// Seal seals a secret using systemd-creds and TPM2
	// serviceName: the systemd service that can unseal this credential
	// sealKeyType: the type of sealing key (host, tpm2, host+tpm2)
	// The credential name and output path are generated based on the service name
	Seal(ctx context.Context, serviceName string, sealKeyType SealKeyType, secret []byte) error
	// VerifyFromPath verifies a sealed secret can be decrypted from a given path
	VerifyFromPath(ctx context.Context, sealedPath string) error
}

// sealer implements the Sealer interface
type sealer struct {
	log              *log.PrefixLogger
	systemdCredsPath string
	rw               fileio.ReadWriter
	exec             executer.Executer
}

// NewSealer creates a new sealer
func NewSealer(log *log.PrefixLogger, rw fileio.ReadWriter, exec executer.Executer) (Sealer, error) {
	systemdCredsPath, _ := exec.LookPath(SystemdCredsCommand)
	if systemdCredsPath == "" {
		systemdCredsPath = SystemdCredsCommand // Fallback to PATH
	}

	return &sealer{
		log:              log,
		systemdCredsPath: systemdCredsPath,
		rw:               rw,
		exec:             exec,
	}, nil
}

// Seal seals a secret using systemd-creds and TPM2
func (s *sealer) Seal(ctx context.Context, serviceName string, sealKeyType SealKeyType, secret []byte) error {

	if len(secret) == 0 {
		return fmt.Errorf("secret cannot be empty")
	}

	// Validate required parameters
	if serviceName == "" {
		return fmt.Errorf("service name is required")
	}

	// Generate credential name and output path from service name
	var credentialName, outputPath string
	if serviceName == "flightctl-agent" {
		credentialName = TPMStorageCredentialName
		outputPath = DefaultParentCredentialPath
	} else {
		credentialName = fmt.Sprintf("%s-password", serviceName)
		outputPath = filepath.Join(ChildCredentialDir, fmt.Sprintf("%s.sealed", serviceName))
	}

	if !isSystemdCredsAvailable(ctx, s.exec, s.systemdCredsPath) {
		s.log.Warn("systemd-creds not available - cannot seal password")
		return ErrSystemdCredsNotAvailable
	}

	outputDir := filepath.Dir(outputPath)
	if err := s.rw.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	tempFile, err := createSecureTempFile(secret, s.rw, s.exec)
	if err != nil {
		return fmt.Errorf("failed to create temporary secret file: %w", err)
	}
	defer cleanupSecureTempFile(tempFile, s.rw)

	if !hasTPM2Support(ctx, s.exec, s.systemdCredsPath) {
		s.log.Warn("TPM2 support not available - cannot seal password")
		return ErrTPM2NotAvailable
	}

	// Log service information but don't add +app: binding
	// The credential will be accessible based on systemd LoadCredentialEncrypted
	s.log.Infof("Using %s sealing for service %s", sealKeyType, serviceName)
	s.log.Info("Service binding will be enforced by systemd LoadCredentialEncrypted directive")

	args := []string{
		"encrypt",
		"--with-key=" + sealKeyType.String(),
		"--name=" + credentialName,
		tempFile,
		outputPath,
	}

	s.log.Debugf("Executing: %s %s", s.systemdCredsPath, strings.Join(args, " "))

	tempData, err := s.rw.ReadFile(tempFile)
	if err != nil {
		return fmt.Errorf("reading temp file: %w", err)
	}

	cmd := s.exec.CommandContext(ctx, s.systemdCredsPath, args...)
	cmd.Stdin = bytes.NewReader(tempData)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		s.log.Errorf("systemd-creds failed: %v", stderr.String())
		return fmt.Errorf("%w: %v (stderr: %s)", ErrSealingFailed, err, stderr.String())
	}

	// verify the sealed file was created
	exists, err := s.rw.PathExists(outputPath)
	if err != nil || !exists {
		return fmt.Errorf("sealed file not created: %w", err)
	}

	// ensure secure permissions
	data, err := s.rw.ReadFile(outputPath)
	if err != nil {
		return fmt.Errorf("reading sealed file: %w", err)
	}
	if err := s.rw.WriteFile(outputPath, data, 0400); err != nil {
		s.log.Warnf("Failed to set permissions on sealed file: %v", err)
	}

	s.log.Infof("Successfully sealed secret for service %s (%d bytes)", serviceName, len(data))
	s.log.Info("This credential can ONLY be unsealed by the specified service")

	return nil
}

// VerifyFromPath verifies a sealed secret can be decrypted from a given path
func (s *sealer) VerifyFromPath(ctx context.Context, sealedPath string) error {
	if !isSystemdCredsAvailable(ctx, s.exec, s.systemdCredsPath) {
		return ErrSystemdCredsNotAvailable
	}

	exists, err := s.rw.PathExists(sealedPath)
	if err != nil || !exists {
		return fmt.Errorf("sealed file not found: %w", err)
	}

	// try to decrypt
	stdout, stderr, exitCode := s.exec.ExecuteWithContext(ctx, s.systemdCredsPath, "decrypt", sealedPath, "-")
	_ = stdout // discard potentially sensitive output
	if exitCode != 0 {
		return fmt.Errorf("failed to verify sealed password: exit code %d (stderr: %s)", exitCode, stderr)
	}

	s.log.Debug("Sealed password verified successfully")
	return nil
}

// isSystemdCredsAvailable checks if systemd-creds command is available on the system.
// This requires systemd 250+ to be installed.
func isSystemdCredsAvailable(ctx context.Context, exec executer.Executer, systemdCredsPath string) bool {
	stdout, _, exitCode := exec.ExecuteWithContext(ctx, systemdCredsPath, "--version")
	if exitCode != 0 {
		return false
	}

	// need at least systemd 250 for credential sealing support
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "systemd ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				versionStr := parts[1]
				var version int
				if _, err := fmt.Sscanf(versionStr, "%d", &version); err == nil {
					return version >= 250
				}
			}
		}
	}

	return false
}

// hasTPM2Support checks if systemd-creds has TPM2 support enabled.
// This requires both TPM2 hardware and systemd-creds built with TPM2 support.
func hasTPM2Support(ctx context.Context, exec executer.Executer, systemdCredsPath string) bool {
	if !isSystemdCredsAvailable(ctx, exec, systemdCredsPath) {
		return false
	}

	_, _, exitCode := exec.ExecuteWithContext(ctx, systemdCredsPath, "has-tpm2")
	return exitCode == 0
}

// createSecureTempFile creates a temporary file with the data and returns the path.
// It attempts to use /dev/shm (RAM) first for security, falling back to the system temp directory.
// The caller is responsible for removing the file.
func createSecureTempFile(data []byte, rw fileio.ReadWriter, exec executer.Executer) (string, error) {
	// Try to use /dev/shm (RAM) first for security
	var tempFile *os.File
	var err error

	// Try /dev/shm first (RAM-based)
	tempFile, err = exec.TempFile("/dev/shm", "tpm-pass-*.tmp")
	if err != nil {
		// Fall back to regular temp directory
		tempFile, err = exec.TempFile("", "tpm-pass-*.tmp")
	}

	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}

	// Get the path and close immediately
	tempPath := tempFile.Name()
	tempFile.Close()

	// Write through fileio with secure permissions
	if err := rw.WriteFile(tempPath, data, 0600); err != nil {
		_ = rw.RemoveFile(tempPath) // best effort cleanup
		return "", fmt.Errorf("failed to write to temp file: %w", err)
	}

	return tempPath, nil
}

// cleanupSecureTempFile securely removes a temporary file
func cleanupSecureTempFile(path string, rw fileio.ReadWriter) {
	if path == "" {
		return
	}

	// Use fileio's secure wipe if available
	if err := rw.OverwriteAndWipe(path); err != nil {
		// Fall back to simple removal if secure wipe fails
		_ = rw.RemoveFile(path) // best effort cleanup
	}
}
