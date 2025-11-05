package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	apiserver "github.com/flightctl/flightctl/internal/api_server"
	"github.com/flightctl/flightctl/internal/api_server/agentserver"
	"github.com/flightctl/flightctl/internal/api_server/middleware"
	"github.com/flightctl/flightctl/internal/client"
	"github.com/flightctl/flightctl/internal/config"
	"github.com/flightctl/flightctl/internal/crypto"
	"github.com/flightctl/flightctl/internal/instrumentation/metrics"
	"github.com/flightctl/flightctl/internal/instrumentation/metrics/domain"
	"github.com/flightctl/flightctl/internal/instrumentation/tracing"
	"github.com/flightctl/flightctl/internal/kvstore"
	"github.com/flightctl/flightctl/internal/org/cache"
	"github.com/flightctl/flightctl/internal/org/resolvers"
	"github.com/flightctl/flightctl/internal/rendered"
	"github.com/flightctl/flightctl/internal/store"
	"github.com/flightctl/flightctl/internal/util"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/flightctl/flightctl/pkg/queues"
	"github.com/flightctl/flightctl/pkg/shutdown"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func main() {
	log := log.InitLogs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdown.HandleSignals(log, cancel, shutdown.DefaultGracefulShutdownTimeout)
	if err := runCmd(ctx, log); err != nil {
		log.Fatalf("API service error: %v", err)
	}
}

//nolint:gocyclo
func runCmd(ctx context.Context, log *logrus.Logger) error {
	log.Println("Starting API service")
	defer log.Println("API service stopped")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cfg, err := config.LoadOrGenerate(config.ConfigFile())
	if err != nil {
		return fmt.Errorf("reading configuration: %w", err)
	}
	log.Printf("Using config: %s", cfg)

	logLvl, err := logrus.ParseLevel(cfg.Service.LogLevel)
	if err != nil {
		logLvl = logrus.InfoLevel
	}
	log.SetLevel(logLvl)

	ca, _, err := crypto.EnsureCA(cfg.CA)
	if err != nil {
		return fmt.Errorf("ensuring CA cert: %w", err)
	}

	var serverCerts *crypto.TLSCertificateConfig

	// check for user-provided certificate files
	if cfg.Service.SrvCertFile != "" || cfg.Service.SrvKeyFile != "" {
		if canReadCertAndKey, err := crypto.CanReadCertAndKey(cfg.Service.SrvCertFile, cfg.Service.SrvKeyFile); !canReadCertAndKey {
			return fmt.Errorf("cannot read provided server certificate or key: %w", err)
		}

		serverCerts, err = crypto.GetTLSCertificateConfig(cfg.Service.SrvCertFile, cfg.Service.SrvKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load provided certificate: %w", err)
		}
	} else {
		srvCertFile := crypto.CertStorePath(cfg.Service.ServerCertName+".crt", cfg.Service.CertStore)
		srvKeyFile := crypto.CertStorePath(cfg.Service.ServerCertName+".key", cfg.Service.CertStore)

		// check if existing self-signed certificate is available
		if canReadCertAndKey, _ := crypto.CanReadCertAndKey(srvCertFile, srvKeyFile); canReadCertAndKey {
			serverCerts, err = crypto.GetTLSCertificateConfig(srvCertFile, srvKeyFile)
			if err != nil {
				return fmt.Errorf("failed to load existing self-signed certificate: %w", err)
			}
		} else {
			// default to localhost if no alternative names are set
			if len(cfg.Service.AltNames) == 0 {
				cfg.Service.AltNames = []string{"localhost"}
			}

			serverCerts, err = ca.MakeAndWriteServerCertificate(ctx, srvCertFile, srvKeyFile, cfg.Service.AltNames, cfg.CA.ServerCertValidityDays)
			if err != nil {
				return fmt.Errorf("failed to create self-signed certificate: %w", err)
			}
		}
	}

	// check for expired certificate
	for _, x509Cert := range serverCerts.Certs {
		expired := time.Now().After(x509Cert.NotAfter)
		log.Printf("checking certificate: subject='%s', issuer='%s', expiry='%v'",
			x509Cert.Subject.CommonName, x509Cert.Issuer.CommonName, x509Cert.NotAfter)

		if expired {
			log.Warnf("server certificate for '%s' issued by '%s' has expired on: %v",
				x509Cert.Subject.CommonName, x509Cert.Issuer.CommonName, x509Cert.NotAfter)
		}
	}

	clientCertFile := crypto.CertStorePath(cfg.CA.ClientBootstrapCertName+".crt", cfg.Service.CertStore)
	clientKeyFile := crypto.CertStorePath(cfg.CA.ClientBootstrapCertName+".key", cfg.Service.CertStore)
	_, _, err = ca.EnsureClientCertificate(ctx, clientCertFile, clientKeyFile, cfg.CA.ClientBootstrapCommonName, cfg.CA.ClientBootstrapValidityDays)
	if err != nil {
		return fmt.Errorf("ensuring bootstrap client cert: %w", err)
	}

	// also write out a client config file

	caPemBytes, err := ca.GetCABundle()
	if err != nil {
		return fmt.Errorf("loading CA certificate bundle: %w", err)
	}

	err = client.WriteConfig(config.ClientConfigFile(), cfg.Service.BaseUrl, "", caPemBytes, nil)
	if err != nil {
		return fmt.Errorf("writing client config: %w", err)
	}

	tracerShutdown := tracing.InitTracer(log, cfg, "flightctl-api")
	defer func() {
		if err := tracerShutdown(ctx); err != nil {
			log.Errorf("failed to shut down tracer: %v", err)
		}
	}()

	log.Println("Initializing data store")
	db, err := store.InitDB(cfg, log)
	if err != nil {
		return fmt.Errorf("initializing data store: %w", err)
	}

	store := store.NewStore(db, log.WithField("pkg", "store"))
	defer store.Close()

	tlsConfig, agentTlsConfig, err := crypto.TLSConfigForServer(ca.GetCABundleX509(), serverCerts)
	if err != nil {
		return fmt.Errorf("failed creating TLS config: %w", err)
	}

	processID := fmt.Sprintf("api-%s-%s", util.GetHostname(), uuid.New().String())
	provider, err := queues.NewRedisProvider(ctx, log, processID, cfg.KV.Hostname, cfg.KV.Port, cfg.KV.Password, queues.DefaultRetryConfig())
	if err != nil {
		return fmt.Errorf("failed connecting to Redis queue: %w", err)
	}

	kvStore, err := kvstore.NewKVStore(ctx, log, cfg.KV.Hostname, cfg.KV.Port, cfg.KV.Password)
	if err != nil {
		return fmt.Errorf("creating kvstore: %w", err)
	}
	if err = rendered.Bus.Initialize(ctx, kvStore, provider, time.Duration(cfg.Service.RenderedWaitTimeout), log); err != nil {
		return fmt.Errorf("creating rendered version manager: %w", err)
	}
	if err = rendered.Bus.Instance().Start(ctx); err != nil {
		return fmt.Errorf("starting rendered version manager: %w", err)
	}

	// create the agent service listener as tcp (combined HTTP+gRPC)
	agentListener, err := net.Listen("tcp", cfg.Service.AgentEndpointAddress)
	if err != nil {
		return fmt.Errorf("creating listener: %w", err)
	}

	orgCache := cache.NewOrganizationTTL(cache.DefaultTTL)
	go orgCache.Start()
	defer orgCache.Stop()

	buildResolverOpts := resolvers.BuildResolverOptions{
		Config: cfg,
		Store:  store.Organization(),
		Log:    log,
		Cache:  orgCache,
	}

	if cfg.Auth != nil && cfg.Auth.AAP != nil {
		membershipCache := cache.NewMembershipTTL(cache.DefaultTTL)
		go membershipCache.Start()
		defer membershipCache.Stop()
		buildResolverOpts.MembershipCache = membershipCache
	}

	orgResolver, err := resolvers.BuildResolver(buildResolverOpts)
	if err != nil {
		return fmt.Errorf("failed to build organization resolver: %w", err)
	}

	agentServer, err := agentserver.New(ctx, log, cfg, store, ca, agentListener, provider, agentTlsConfig, orgResolver)
	if err != nil {
		return fmt.Errorf("initializing agent server: %w", err)
	}

	listener, err := middleware.NewTLSListener(cfg.Service.Address, tlsConfig)
	if err != nil {
		return fmt.Errorf("creating TLS listener: %w", err)
	}
	defer listener.Close()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		server := apiserver.New(log, cfg, store, ca, listener, provider, agentServer.GetGRPCServer(), orgResolver)
		if err := server.Run(ctx); err != nil {
			log.Errorf("Failed to run API server: %v", err)
			cancel()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := agentServer.Run(ctx); err != nil {
			log.Errorf("Failed to run agent server: %v", err)
			cancel()
		}
	}()

	if cfg.Metrics != nil && cfg.Metrics.Enabled {
		var collectors []metrics.NamedCollector
		if cfg.Metrics.DeviceCollector != nil && cfg.Metrics.DeviceCollector.Enabled {
			collectors = append(collectors, domain.NewDeviceCollector(ctx, store, log, cfg))
		}
		if cfg.Metrics.FleetCollector != nil && cfg.Metrics.FleetCollector.Enabled {
			collectors = append(collectors, domain.NewFleetCollector(ctx, store, log, cfg))
		}
		if cfg.Metrics.RepositoryCollector != nil && cfg.Metrics.RepositoryCollector.Enabled {
			collectors = append(collectors, domain.NewRepositoryCollector(ctx, store, log, cfg))
		}
		if cfg.Metrics.ResourceSyncCollector != nil && cfg.Metrics.ResourceSyncCollector.Enabled {
			collectors = append(collectors, domain.NewResourceSyncCollector(ctx, store, log, cfg))
		}
		if cfg.Metrics.SystemCollector != nil && cfg.Metrics.SystemCollector.Enabled {
			if systemMetricsCollector := metrics.NewSystemCollector(ctx, cfg); systemMetricsCollector != nil {
				collectors = append(collectors, systemMetricsCollector)
				defer func() {
					if err := systemMetricsCollector.Shutdown(); err != nil {
						log.Errorf("Failed to shutdown system metrics collector: %v", err)
					}
				}()
			}
		}
		if cfg.Metrics.HttpCollector != nil && cfg.Metrics.HttpCollector.Enabled {
			if httpMetricsCollector := metrics.NewHTTPMetricsCollector(ctx, cfg, "flightctl-api", log); httpMetricsCollector != nil {
				collectors = append(collectors, httpMetricsCollector)
				defer func() {
					if err := httpMetricsCollector.Shutdown(); err != nil {
						log.Errorf("Failed to shutdown HTTP metrics collector: %v", err)
					}
				}()
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			metricsServer := metrics.NewMetricsServer(log, cfg, collectors...)
			if err := metricsServer.Run(ctx); err != nil {
				log.Errorf("Failed to run metrics server: %v", err)
				cancel()
			}
		}()
	}

	wg.Wait()

	return nil
}
