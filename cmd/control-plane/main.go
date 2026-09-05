// Command control-plane uruchamia API, gateway agentow i endpoint enrollmentu.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/ultherego/flotestro/internal/adminapi"
	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/database"
	"github.com/ultherego/flotestro/internal/enrollment"
	"github.com/ultherego/flotestro/internal/events"
	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/gateway"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/identity"
	"github.com/ultherego/flotestro/internal/integrations"
	alertyIntegracji "github.com/ultherego/flotestro/internal/integrations/alerts"
	metrykiIntegracji "github.com/ultherego/flotestro/internal/integrations/metrics"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/oidc"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relays"
	"github.com/ultherego/flotestro/internal/remediation"
	"github.com/ultherego/flotestro/internal/scheduler"
	"github.com/ultherego/flotestro/internal/secrets"
	"github.com/ultherego/flotestro/internal/vuln"
	debianzrodlo "github.com/ultherego/flotestro/internal/vuln/sources/debian"
)

const staleCheckInterval = 30 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("control plane zakonczony bledem", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.ControlPlane{}
	flag.StringVar(&cfg.DatabaseURL, "database-url",
		config.Env("FLOTESTRO_DATABASE_URL", ""), "DSN PostgreSQL")
	flag.StringVar(&cfg.StateDir, "state-dir",
		config.Env("FLOTESTRO_STATE_DIR", "/var/lib/flotestro"), "katalog stanu (CA)")
	flag.StringVar(&cfg.GatewayAddr, "gateway-addr",
		config.Env("FLOTESTRO_GATEWAY_ADDR", ":8443"), "adres gatewaya agentow (mTLS)")
	flag.StringVar(&cfg.EnrollmentAddr, "enrollment-addr",
		config.Env("FLOTESTRO_ENROLLMENT_ADDR", ":8444"), "adres endpointu enrollmentu (TLS)")
	flag.StringVar(&cfg.AdminAddr, "admin-addr",
		config.Env("FLOTESTRO_ADMIN_ADDR", "127.0.0.1:8080"), "adres REST API")
	advertised := flag.String("advertise",
		config.Env("FLOTESTRO_ADVERTISE", "127.0.0.1"),
		"adresy i nazwy, pod ktorymi agenci widza control plane (po przecinku)")
	flag.IntVar(&cfg.HeartbeatSeconds, "heartbeat-seconds",
		config.EnvInt("FLOTESTRO_HEARTBEAT_SECONDS", 60), "bazowy odstep heartbeatu")
	flag.IntVar(&cfg.HeartbeatJitter, "heartbeat-jitter",
		config.EnvInt("FLOTESTRO_HEARTBEAT_JITTER", 30), "losowy rozrzut heartbeatu")
	issuerURL := flag.String("oidc-issuer",
		config.Env("FLOTESTRO_OIDC_ISSUER", ""),
		"adres wystawcy OIDC, np. https://ipa:8081/realms/flotestro")
	clientID := flag.String("oidc-client-id",
		config.Env("FLOTESTRO_OIDC_CLIENT_ID", "flotestro-panel"), "identyfikator klienta OIDC")
	clientSecret := flag.String("oidc-client-secret",
		config.Env("FLOTESTRO_OIDC_CLIENT_SECRET", ""), "sekret klienta OIDC")
	directoryWrite := flag.Bool("directory-write",
		config.Env("FLOTESTRO_DIRECTORY_WRITE", "") == "true",
		"wlacza zmiany w katalogu tozsamosci; domyslnie panel tylko czyta katalog")
	agentCertTTL := flag.Duration("agent-cert-ttl",
		config.EnvDuration("FLOTESTRO_AGENT_CERT_TTL", pki.AgentCertTTL),
		"czas zycia certyfikatu agenta; agent odnawia go po uplywie dwoch trzecich")
	stepUpMaxAge := flag.Duration("stepup-max-age",
		config.EnvDuration("FLOTESTRO_STEPUP_MAX_AGE", 5*time.Minute),
		"dopuszczalny wiek uwierzytelnienia przy operacjach o najwiekszym wplywie")
	stepUpACR := flag.String("stepup-acr",
		config.Env("FLOTESTRO_STEPUP_ACR", ""),
		"wymagany poziom uwierzytelnienia (acr) przy operacjach o najwiekszym wplywie")
	// Klucz magazynu lezy w katalogu stanu, obok klucza CA: to jedyne miejsce,
	// do ktorego usluga ma prawo zapisu, i jedyne, ktorego prawa sa na tyle
	// waskie, zeby trzymac tam material kryptograficzny.
	secretsKeyFile := flag.String("secrets-key-file",
		config.Env("FLOTESTRO_SECRETS_KEY_FILE", ""),
		"plik z kluczem magazynu sekretow; bez jego kopii sekretow nie da sie odzyskac")
	webRoot := flag.String("web-root",
		config.Env("FLOTESTRO_WEB_ROOT", ""), "katalog ze zbudowanym panelem")
	publicURL := flag.String("public-url",
		config.Env("FLOTESTRO_PUBLIC_URL", ""), "adres panelu widoczny dla przegladarki")
	groupsClaim := flag.String("oidc-groups-claim",
		config.Env("FLOTESTRO_OIDC_GROUPS_CLAIM", "groups"), "pole tokenu z lista grup")
	// Nazwa zmiennej musi zgadzac sie z plikiem konfiguracyjnym, ktory
	// instalacja dostaje w pakiecie: rozjazd oznaczal, ze wypelniony
	// FLOTESTRO_IPA_URL nie wlaczal niczego, a panel milczal o powodzie.
	ipaServer := flag.String("ipa-server",
		config.Env("FLOTESTRO_IPA_URL", config.Env("FLOTESTRO_IPA_SERVER", "")),
		"adres serwera FreeIPA, np. https://ipa.example.org")
	ipaPrincipal := flag.String("ipa-principal",
		config.Env("FLOTESTRO_IPA_PRINCIPAL", ""), "service principal connectora katalogu")
	ipaKeytab := flag.String("ipa-keytab",
		config.Env("FLOTESTRO_IPA_KEYTAB", "/etc/flotestro/ipa.keytab"), "keytab connectora")
	ipaCACert := flag.String("ipa-ca-cert",
		config.Env("FLOTESTRO_IPA_CA_CERT", "/etc/flotestro/ipa-ca.crt"), "certyfikat CA katalogu")
	ipaRealm := flag.String("ipa-realm",
		config.Env("FLOTESTRO_IPA_REALM", ""), "realm Kerberos katalogu")
	monitoring := config.Monitoring{}
	flag.StringVar(&monitoring.PrometheusURL, "prometheus-url",
		config.Env("FLOTESTRO_PROMETHEUS_URL", ""),
		"adres zrodla metryk (Prometheus API); pusty wylacza wykresy")
	flag.StringVar(&monitoring.AlertmanagerURL, "alertmanager-url",
		config.Env("FLOTESTRO_ALERTMANAGER_URL", ""),
		"adres zrodla alertow (Alertmanager API); pusty wylacza alerty i wyciszenia")
	flag.DurationVar(&monitoring.Timeout, "monitoring-timeout",
		config.EnvDuration("FLOTESTRO_MONITORING_TIMEOUT", integrations.DomyslnyLimitCzasu),
		"limit czasu pojedynczego pytania do monitoringu")
	flag.StringVar(&monitoring.HostLabel, "monitoring-host-label",
		config.Env("FLOTESTRO_MONITORING_HOST_LABEL", "instance"),
		"etykieta, po ktorej monitoring rozpoznaje host")
	flag.StringVar(&monitoring.HostValue, "monitoring-host-value",
		config.Env("FLOTESTRO_MONITORING_HOST_VALUE", "{hostname}:9100"),
		"szablon wartosci etykiety hosta, np. {hostname}:9100")
	flag.StringVar(&monitoring.SiteLabel, "monitoring-site-label",
		config.Env("FLOTESTRO_MONITORING_SITE_LABEL", "site"), "etykieta lokalizacji")
	flag.StringVar(&monitoring.EnvironmentLabel, "monitoring-environment-label",
		config.Env("FLOTESTRO_MONITORING_ENVIRONMENT_LABEL", "environment"), "etykieta srodowiska")
	flag.StringVar(&monitoring.DashboardURL, "monitoring-dashboard-url",
		config.Env("FLOTESTRO_MONITORING_DASHBOARD_URL", ""),
		"szablon odnosnika do dashboardu hosta")
	flag.StringVar(&monitoring.LogsURL, "monitoring-logs-url",
		config.Env("FLOTESTRO_MONITORING_LOGS_URL", ""),
		"szablon odnosnika do logow hosta")
	flag.DurationVar(&monitoring.Window, "monitoring-window",
		config.EnvDuration("FLOTESTRO_MONITORING_WINDOW", 3*time.Hour),
		"domyslny zakres czasu wykresow")
	podatnosci := config.Podatnosci{}
	flag.BoolVar(&podatnosci.Enabled, "vulnerability-correlator",
		config.Env("FLOTESTRO_VULN_ENABLED", "true") == "true",
		"wlacza korelator podatnosci oparty na trackerach dystrybucji")
	flag.DurationVar(&podatnosci.SyncInterval, "vulnerability-sync-interval",
		config.EnvDuration("FLOTESTRO_VULN_SYNC_INTERVAL", 30*time.Minute),
		"jak czesto panel pyta trackery o zmiany")
	flag.DurationVar(&podatnosci.MaxSnapshotAge, "vulnerability-max-snapshot-age",
		config.EnvDuration("FLOTESTRO_VULN_MAX_SNAPSHOT_AGE", 6*time.Hour),
		"wiek, powyzej ktorego dane feedu sa opisywane jako nieswieze")
	flag.StringVar(&podatnosci.DebianURL, "vulnerability-debian-url",
		config.Env("FLOTESTRO_VULN_DEBIAN_URL", debianzrodlo.AdresDomyslny),
		"zrzut trackera bezpieczenstwa Debiana; pusty wylacza to zrodlo")
	productionList := flag.String("production-environments",
		config.Env("FLOTESTRO_PRODUCTION_ENVIRONMENTS", "prod,production"),
		"srodowiska, w ktorych zmiane musi zatwierdzic druga osoba")
	flag.Parse()

	productionEnvironments := splitList(*productionList)

	cfg.GatewayID = config.Env("FLOTESTRO_GATEWAY_ID", defaultGatewayID())
	cfg.StaleAfter = time.Duration(cfg.HeartbeatSeconds+cfg.HeartbeatJitter) * 3 * time.Second
	if err := cfg.Validate(); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := database.Migrate(ctx, pool); err != nil {
		return err
	}
	log.Info("schemat bazy aktualny")

	trust, err := pki.EnsureTrust(cfg.StateDir)
	if err != nil {
		return err
	}
	ca := trust.Active()
	ca.AgentTTL = *agentCertTTL
	log.Info("CA gotowe", "subject", ca.Certificate.Subject.CommonName,
		"not_after", ca.Certificate.NotAfter.Format(time.RFC3339),
		"agent_cert_ttl", ca.AgentTTL.String(),
		"uznawanych_ca", len(trust.Authorities()))

	// Certyfikaty sprzed wprowadzenia wymiany CA nie maja zapisanego wystawcy.
	// Uzupelniamy go tylko wtedy, gdy istnieje dokladnie jedno CA: przy
	// wiekszej liczbie wystawcy nie da sie ustalic inaczej niz zgadujac.
	if len(trust.Authorities()) == 1 {
		uzupelnione, err := hosts.NewStore(pool).AdoptCertificateIssuer(ctx,
			ca.Certificate.Subject.CommonName, ca.Certificate.SerialNumber.String())
		if err != nil {
			return fmt.Errorf("uzupelnienie wystawcy certyfikatow: %w", err)
		}
		if uzupelnione > 0 {
			log.Info("uzupelniono wystawce certyfikatow agentow", "wierszy", uzupelnione)
		}
	}

	// Panel dostepny wylacznie pod localhost nie obsluzy zadnej floty:
	// certyfikat bramy nie bedzie pasowal do adresu, pod ktorym agent laczy
	// sie z panelem. Milczenie w tym miejscu kosztuje instalacje, w ktorej
	// wszystko wyglada na uruchomione, a zaden host sie nie rejestruje.
	if *advertised == "127.0.0.1" {
		log.Warn("panel przedstawia sie agentom jako 127.0.0.1; " +
			"ustaw FLOTESTRO_ADVERTISE na adres widoczny dla hostow floty")
	}
	dnsNames, ips := splitAdvertised(*advertised)
	serverCertPEM, serverKeyPEM, err := ca.IssueServerCert(dnsNames, ips)
	if err != nil {
		return err
	}
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return err
	}

	// Zbior zaufania zmienia sie przy wymianie CA, wiec weryfikacja klienta
	// czyta go przy kazdym uscisku zamiast trzymac kopie z chwili startu.
	clientTrust := func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    trust.Pool(),
			MinVersion:   tls.VersionTLS13,
			// Konfiguracja zwrocona tutaj zastepuje ta z serwera w calosci,
			// wiec musi sama zadeklarowac HTTP/2. Bez tego negocjacja konczy
			// sie na HTTP/1.1 i strumien dwukierunkowy nie ma jak dzialac.
			NextProtos: []string{"h2"},
		}, nil
	}

	hostStore := hosts.NewStore(pool)
	inventoryStore := inventory.NewStore(pool)
	jobStore := jobs.NewStore(pool)
	campaignStore := campaigns.NewStore(pool)
	tokenStore := enrollment.NewTokenStore(pool)
	relayStore := relays.NewStore(pool)
	authzStore := authz.NewStore(pool)
	recorder := audit.NewRecorder(pool, log)
	registry := gateway.NewRegistry()

	// Gateway agentow: mTLS obowiazkowe, tozsamosc wylacznie z certyfikatu.
	if err := bootstrapAdmin(ctx, authzStore, cfg.StateDir, log); err != nil {
		return err
	}

	// Dostawca tozsamosci jest opcjonalny: bez niego dzialaja wylacznie tokeny
	// API, co wystarcza automatyzacji, ale nie spelnia wymogu logowania z MFA.
	var identityProvider *oidc.Provider
	if *issuerURL != "" {
		identityProvider, err = oidc.Discover(ctx, oidc.Config{
			IssuerURL:    *issuerURL,
			ClientID:     *clientID,
			ClientSecret: *clientSecret,
			RedirectURL:  strings.TrimSuffix(*publicURL, "/") + "/auth/callback",
			GroupsClaim:  *groupsClaim,
		})
		if err != nil {
			return fmt.Errorf("dostawca tozsamosci: %w", err)
		}
		log.Info("dostawca tozsamosci gotowy", "issuer", identityProvider.Issuer())
	} else {
		log.Warn("brak dostawcy tozsamosci; logowanie operatorow dziala tylko na tokenach API")
	}

	// Connector katalogu jest opcjonalny. Jego brak oznacza panel bez widoku
	// tozsamosci, a nie panel niedzialajacy.
	var directory *freeipa.Client
	if *ipaServer != "" && *ipaPrincipal != "" {
		directory, err = freeipa.New(freeipa.Config{
			ServerURL:  *ipaServer,
			Realm:      *ipaRealm,
			Principal:  *ipaPrincipal,
			KeytabPath: *ipaKeytab,
			CACertPath: *ipaCACert,
			CacheTTL:   30 * time.Second,
		})
		if err != nil {
			return fmt.Errorf("connector katalogu: %w", err)
		}
		log.Info("connector katalogu gotowy", "principal", directory.Principal(), "serwer", *ipaServer)
	} else {
		log.Info("connector katalogu nie jest skonfigurowany")
	}

	changeStore := identity.NewStore(pool)
	if directory != nil && *directoryWrite {
		// Wykonawca zmian katalogu dziala obok schedulera zadan hostowych:
		// zmiana w katalogu nie jest operacja na hoscie.
		go identity.NewExecutor(changeStore, directory, authzStore, recorder,
			log, 3*time.Second).Run(ctx)
	}

	agentService := gateway.NewAgentService(pool, hostStore, inventoryStore, jobStore, recorder,
		registry, trust, relayStore, log, cfg.GatewayID, cfg.HeartbeatSeconds, cfg.HeartbeatJitter)
	// Wpisy sesji po padzie procesu zostaja otwarte i zawyzaja kazdy pomiar
	// liczacy polaczenia z bazy.
	go agentService.ReapOrphanSessions(ctx, time.Minute)

	gatewayMux := http.NewServeMux()
	gatewayMux.Handle(agentv1connect.NewAgentServiceHandler(agentService))
	gatewayServer := &http.Server{
		Addr:    cfg.GatewayAddr,
		Handler: gateway.WithClientCertificate(gatewayMux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			// Zbior zaufania czytany przy kazdym uscisku: po wymianie CA
			// nowe certyfikaty agentow musza byc uznane bez restartu panelu.
			GetConfigForClient: clientTrust,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2"},
		},
		ReadHeaderTimeout: 15 * time.Second,
	}

	// Enrollment: TLS bez certyfikatu klienta, bo host nie ma jeszcze tozsamosci.
	enrollmentService := gateway.NewEnrollmentService(trust, hostStore, relayStore, tokenStore, recorder, log)
	enrollmentMux := http.NewServeMux()
	enrollmentMux.Handle(agentv1connect.NewEnrollmentServiceHandler(enrollmentService))
	enrollmentServer := &http.Server{
		Addr:    cfg.EnrollmentAddr,
		Handler: enrollmentMux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		},
		ReadHeaderTimeout: 15 * time.Second,
	}

	// Magistrala zdarzen budzi otwarte ekrany, gdy zmienia sie stan operacji
	// i gdy trwajaca operacja melduje postep. Bez niej panel dziala jak
	// dotad - postep widac po odswiezeniu strony.
	eventBus := events.NewBus(pool)
	go eventBus.Run(ctx, log)
	agentService.SetEvents(eventBus)

	panelServer := adminapi.NewServer(pool, hostStore, inventoryStore, jobStore, campaignStore,
		tokenStore, authzStore, recorder, registry, identityProvider, directory,
		changeStore, log,
		adminapi.Options{
			ProductionEnvironments: productionEnvironments,
			SessionIdle:            8 * time.Hour,
			SessionAbsolute:        24 * time.Hour,
			PublicURL:              *publicURL,
			WebRoot:                *webRoot,
			DirectoryWrite:         *directoryWrite,
			StepUpMaxAge:           *stepUpMaxAge,
			StepUpACR:              *stepUpACR,
			// Metryka waznosci CA ma pokazywac CA podpisujace,
			// takze po wymianie, wiec czyta caly zbior zaufania.
			Metrics: metrics.NewCollector(pool, registry, trust, cfg.GatewayID).
				WithAuthorities(trust.Authorities),
			Trust: trust,
		})
	panelServer.SetEvents(eventBus)

	// Monitoring: panel czyta cudze metryki i cudze alerty. Puste adresy
	// oznaczaja instalacje bez monitoringu - wtedy zakladka mowi wprost, ze
	// zrodel nie wskazano, zamiast rysowac puste wykresy.
	panelServer.SetMonitoring(adminapi.Monitoring{
		Metryki: metrykiIntegracji.NowyPrometheus(monitoring.PrometheusURL, monitoring.Timeout, nil),
		Alerty:  alertyIntegracji.NowyAlertmanager(monitoring.AlertmanagerURL, monitoring.Timeout),
		Mapowanie: integrations.Mapowanie{
			HostLabel:        monitoring.HostLabel,
			HostValue:        monitoring.HostValue,
			SiteLabel:        monitoring.SiteLabel,
			EnvironmentLabel: monitoring.EnvironmentLabel,
			DashboardURL:     monitoring.DashboardURL,
			LogsURL:          monitoring.LogsURL,
			Okno:             monitoring.Window,
		},
	})
	if monitoring.PrometheusURL != "" || monitoring.AlertmanagerURL != "" {
		log.Info("integracje monitoringowe podlaczone",
			"metryki", monitoring.PrometheusURL, "alerty", monitoring.AlertmanagerURL,
			"etykieta_hosta", monitoring.HostLabel)
	}

	// Plany naprawy: panel je zaklada, runner prowadzi krok po kroku.
	remediationStore := remediation.NewStore(pool)
	panelServer.SetRemediation(remediationStore)

	// Korelator podatnosci trzyma snapshoty feedow, ustalenia producentow
	// i liste pakietow hostow.
	vulnStore := vuln.NewStore(pool)
	packageStore := vuln.NowyMagazynPakietow(pool)
	panelServer.SetPodatnosci(vulnStore, packageStore, podatnosci.MaxSnapshotAge)

	// Magazyn sekretow. Klucz lezy w pliku poza baza: kopia bazy bez niego
	// nie wystarcza, zeby odczytac cokolwiek.
	sciezkaKlucza := *secretsKeyFile
	if sciezkaKlucza == "" {
		sciezkaKlucza = filepath.Join(cfg.StateDir, "secrets.key")
	}
	szyfr, utworzony, err := secrets.OtworzSzyfr(sciezkaKlucza)
	if err != nil {
		return fmt.Errorf("magazyn sekretow: %w", err)
	}
	if utworzony {
		log.Warn("wygenerowano klucz magazynu sekretow; bez kopii tego pliku "+
			"sekretow nie da sie odzyskac", "sciezka", sciezkaKlucza)
	}
	secretStore := secrets.NewStore(pool, szyfr)
	panelServer.SetSecrets(secretStore)
	agentService.SetSecrets(secretStore)
	agentService.SetSecretLeases(secretStore)

	adminServer := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           h2c.NewHandler(panelServer.Routes(), &http2.Server{}),
		ReadHeaderTimeout: 15 * time.Second,
	}

	errCh := make(chan error, 3)
	go serveTLS(gatewayServer, "gateway agentow", log, errCh)
	go serveTLS(enrollmentServer, "enrollment", log, errCh)
	go func() {
		log.Info("REST API nasluchuje", "addr", adminServer.Addr)
		if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("REST API: %w", err)
		}
	}()

	go markStaleHosts(ctx, pool, cfg.StaleAfter, log)

	// Scheduler dostarcza zatwierdzone zadania hostom polaczonym z tym gatewayem
	// i pilnuje lease oraz TTL.
	dyspozytor := scheduler.New(jobStore, registry, recorder, directory, log, scheduler.Options{
		GatewayID:     cfg.GatewayID,
		LeaseDuration: 5 * time.Minute,
	})
	// Dzierzawy sekretow powstaja w chwili dostarczenia zadania: krotkie okno
	// zaczyna sie wtedy, gdy host zaczyna prace.
	dyspozytor.SetSecrets(secretStore)
	go dyspozytor.Run(ctx)

	// Orkiestrator prowadzi kampanie przez canary i fale, tworzac zadania,
	// ktore dostarcza scheduler.
	go campaigns.NewOrchestrator(campaignStore, jobStore, hostStore, recorder,
		log, 5*time.Second).Run(ctx)

	// Runner prowadzi plany naprawy krok po kroku: kazdy krok jest zwyklym
	// zadaniem modulu, a nastepny rusza dopiero, gdy poprzedni sie udal.
	go remediation.NewRunner(remediationStore, jobStore, hostStore, recorder,
		log, 5*time.Second).Run(ctx)

	// Korelator podatnosci: trackery producentow dystrybucji rozstrzygaja,
	// czy zainstalowana wersja jest podatna. Panel niczego nie zgaduje - host
	// bez feedu albo bez listy pakietow dostaje stan nieustalony z powodem,
	// a nie zero znalezisk.
	if podatnosci.Enabled {
		var zrodla []vuln.Zrodlo
		if podatnosci.DebianURL != "" {
			zrodla = append(zrodla, debianzrodlo.Nowe(podatnosci.DebianURL, 10*time.Minute))
		}
		if len(zrodla) == 0 {
			log.Warn("korelator podatnosci wlaczony, ale nie ma zadnego zrodla")
		} else {
			nazwy := make([]string, 0, len(zrodla))
			for _, zrodlo := range zrodla {
				nazwy = append(nazwy, zrodlo.Nazwa())
			}
			log.Info("korelator podatnosci uruchomiony", "zrodla", nazwy,
				"odstep", podatnosci.SyncInterval, "maksymalny_wiek", podatnosci.MaxSnapshotAge)
			go vuln.NowyHarmonogram(vulnStore, packageStore, hostStore, inventoryStore,
				jobStore, zrodla, vuln.Ustawienia{
					Interval:       podatnosci.SyncInterval,
					MaxSnapshotAge: podatnosci.MaxSnapshotAge,
				}, log).Run(ctx)
		}
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("zamykanie control plane")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = gatewayServer.Shutdown(shutdownCtx)
	_ = enrollmentServer.Shutdown(shutdownCtx)
	_ = adminServer.Shutdown(shutdownCtx)
	return nil
}

func serveTLS(server *http.Server, name string, log *slog.Logger, errCh chan<- error) {
	log.Info(name+" nasluchuje", "addr", server.Addr)
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- fmt.Errorf("%s: %w", name, err)
	}
}

// markStaleHosts oznacza hosty, ktore przestaly sie odzywac. Sesja moze zniknac
// bez zamkniecia streamu, wiec stan online nie moze opierac sie tylko na nim.
func markStaleHosts(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(staleCheckInterval)
	defer ticker.Stop()
	const query = `
		update hosts set connection_state = 'stale', updated_at = now()
		where connection_state = 'online'
		  and (last_seen_at is null or last_seen_at < now() - $1::interval)`
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			interval := fmt.Sprintf("%d seconds", int(staleAfter.Seconds()))
			if _, err := pool.Exec(ctx, query, interval); err != nil && ctx.Err() == nil {
				log.Error("nie oznaczono hostow jako stale", "err", err)
			}
		}
	}
}

// bootstrapAdmin tworzy pierwsza tozsamosc, gdy system jest pusty. Bez tego
// nie da sie wykonac zadnej operacji, bo kazdy endpoint wymaga uprawnien.
// Token jest pokazany raz, w logu, i nie da sie go odczytac pozniej.
func bootstrapAdmin(ctx context.Context, store *authz.Store, stateDir string, log *slog.Logger) error {
	count, err := store.CountPrincipals(ctx)
	if err != nil {
		return fmt.Errorf("sprawdzenie tozsamosci: %w", err)
	}
	if count > 0 {
		return nil
	}

	tx, err := store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	principalID, err := store.EnsurePrincipal(ctx, tx, "bootstrap-admin", "Bootstrap administrator", "user")
	if err != nil {
		return err
	}
	if err := store.GrantRole(ctx, tx, principalID, authz.RolePlatformAdmin,
		authz.GlobalScope, "system"); err != nil {
		return err
	}
	token, err := store.IssueToken(ctx, tx, principalID, "token bootstrapowy", 0, "system")
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Token trafia takze do pliku w katalogu stanu, zeby dalo sie go odczytac
	// po rotacji dziennika. Plik nalezy usunac po utworzeniu wlasciwych
	// tozsamosci - dopoki istnieje, jest sekretem lezacym na dysku.
	tokenPath := filepath.Join(stateDir, "bootstrap-token")
	if err := os.WriteFile(tokenPath, []byte(token.Value+"\n"), 0o600); err != nil {
		log.Error("nie zapisano tokenu bootstrapowego", "path", tokenPath, "err", err)
	}

	log.Warn("utworzono tozsamosc bootstrapowa; usun plik tokenu po utworzeniu wlasciwych kont",
		"subject", "bootstrap-admin", "token_file", tokenPath)
	return nil
}

func splitList(value string) []string {
	var items []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

func splitAdvertised(value string) ([]string, []net.IP) {
	var (
		dnsNames []string
		ips      = []net.IP{net.ParseIP("127.0.0.1")}
	)
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, part)
	}
	dnsNames = append(dnsNames, "localhost")
	return dnsNames, ips
}

func defaultGatewayID() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "gateway-1"
	}
	return name
}
