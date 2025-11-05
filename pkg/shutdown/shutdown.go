package shutdown

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	DefaultGracefulShutdownTimeout = 30 * time.Second
)

func HandleSignals(log *logrus.Logger, cancel context.CancelFunc, timeout time.Duration) {
	go func() {
		signals := make(chan os.Signal, 2)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
		defer func() {
			signal.Stop(signals)
			close(signals)
		}()

		s := <-signals
		log.Infof("Shutdown signal received, initiating graceful shutdown: %s", s.String())

		<-time.After(timeout)
		log.Errorf("Graceful shutdown timeout (%v) exceeded, forcing shutdown", timeout)
		cancel()
	}()
}
