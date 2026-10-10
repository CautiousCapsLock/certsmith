// Some Fortinet appliances (FortiManager, FortiAnalyzer) ship a factory certificate whose serial
// number is negative, which RFC 5280 forbids and Go refuses to parse by default. That failure comes
// during the TLS handshake, before any request is made, so those devices could not be reached at all.
// This lets Go parse such certificates. It does not weaken verification: whether a certificate is
// trusted is still decided by the chain or by the fingerprint you confirmed.
//
//go:debug x509negativeserial=1

// Command certsmith is a certificate automation daemon with a web UI.
//
//	certsmith [flags]                  run the daemon
//	certsmith reset-admin -data DIR [-user NAME]
//	                                   give a user a new random password (stop the service first)
//	certsmith reset-admin -data DIR -wipe
//	                                   remove all users so the setup wizard runs again
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
	"syscall"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/engine"
	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
	"github.com/CautiousCapsLock/certsmith/internal/secret"
	"github.com/CautiousCapsLock/certsmith/internal/store"
	"github.com/CautiousCapsLock/certsmith/internal/uitls"
	"github.com/CautiousCapsLock/certsmith/internal/update"
	"github.com/CautiousCapsLock/certsmith/internal/web"

	_ "github.com/CautiousCapsLock/certsmith/internal/dns"
	_ "github.com/CautiousCapsLock/certsmith/internal/targets"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "reset-admin" {
		resetAdmin(os.Args[2:])
		return
	}

	data := flag.String("data", "./data", "data directory (database, keys, certificates)")
	listen := flag.String("listen", "127.0.0.1:8443", "web UI listen address")
	tlsDir := flag.String("tls-dir", "", "directory holding the UI's fullchain.pem and key.pem (default <data>/ui-tls; a self-signed pair is created if empty)")
	noTLS := flag.Bool("no-tls", false, "serve the UI over plain HTTP (only behind a TLS-terminating proxy on the same host)")
	redirect := flag.String("http-redirect", "", "also listen for plain HTTP on this address (for example :80) and redirect every request to the HTTPS page; ignored with -no-tls")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	dir := *tlsDir
	if dir == "" {
		dir = filepath.Join(*data, "ui-tls")
	}
	if err := run(log, *data, *listen, dir, *noTLS, *redirect); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func resetAdmin(args []string) {
	fs := flag.NewFlagSet("reset-admin", flag.ExitOnError)
	data := fs.String("data", "./data", "data directory")
	user := fs.String("user", "", "user to reset (optional when there is only one)")
	wipe := fs.Bool("wipe", false, "remove all users instead, so the setup wizard runs again")
	_ = fs.Parse(args)
	if *wipe {
		if err := web.WipeUsers(*data); err != nil {
			fmt.Fprintln(os.Stderr, "reset-admin:", err)
			os.Exit(1)
		}
		fmt.Println("all users removed: the next visit to the web UI runs the setup wizard")
		return
	}
	name, pw, err := web.ResetPassword(*data, *user)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reset-admin:", err)
		os.Exit(1)
	}
	fmt.Printf("new password for %s: %s\n(sign in and change it under Settings)\n", name, pw)
}

func run(log *slog.Logger, data, listen, tlsDir string, noTLS bool, redirect string) error {
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	box, err := secret.Open(data)
	if err != nil {
		return err
	}
	st, err := store.Open(data)
	if err != nil {
		return err
	}
	opts := plugin.Options{AllowCommands: os.Getenv("CERTSMITH_ALLOW_COMMANDS") == "1", UIListen: listen}
	if !noTLS {
		opts.UITLSDir = tlsDir
	}
	plugin.SetOptions(opts)

	if err := web.SeedAdmin(st, os.Getenv("CERTSMITH_ADMIN_USER"), os.Getenv("CERTSMITH_ADMIN_PASSWORD")); err != nil {
		return err
	}
	var needSetup bool
	st.View(func(db *model.DB) { needSetup = len(db.Users) == 0 })
	if needSetup {
		log.Warn("no users yet: open the web UI to run the setup wizard (it works once)")
	}

	eng := engine.New(st, box, data, log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go eng.Run(ctx)

	ws, err := web.New(st, box, eng, data, log)
	if err != nil {
		return err
	}
	// Looks for newer releases once a day (and on request from the web interface). It only reads.
	checker := update.New(os.Getenv("CERTSMITH_REPO"), version)
	if api := os.Getenv("CERTSMITH_UPDATE_API"); api != "" { // a test hook
		checker.APIBase = api
	}
	ws.SetUpdates(version, checker)
	go ws.AutoCheckUpdates(ctx)
	// Request contexts derive from baseCtx, which is cancelled when shutdown starts, so a
	// long request (a DNS test) stops at once and cleans up instead of being cut off.
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	srv := &http.Server{
		Addr:              listen,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
		Handler:           ws.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		log.Info("stopping: ending running work and letting it clean up its DNS records")
		cancelBase()
		sctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		eng.Drain(sctx)        // issuances and deployments finish or abort, removing challenge records
		_ = srv.Shutdown(sctx) // then in-flight requests (such as a DNS test) finish their cleanup
	}()

	if redirect != "" {
		startRedirect(ctx, log, redirect, listen, noTLS)
	}

	if noTLS {
		log.Warn("serving plain HTTP: the administrator password is not encrypted in transit", "listen", listen)
		err = srv.ListenAndServe()
	} else {
		ldr, lerr := uitls.New(tlsDir)
		if lerr != nil {
			return lerr
		}
		srv.TLSConfig = &tls.Config{GetCertificate: ldr.GetCertificate, MinVersion: tls.VersionTLS12}
		log.Info("starting", "version", version, "listen", listen, "tls", "on", "cert_dir", tlsDir, "cert_sha256", ldr.Fingerprint())
		err = srv.ListenAndServeTLS("", "")
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// startRedirect runs the optional plain-HTTP listener that sends browsers to the HTTPS
// page. Failing to bind (port 80 taken, no permission) is reported but is not fatal: the
// page itself still works on its own address.
func startRedirect(ctx context.Context, log *slog.Logger, addr, listen string, noTLS bool) {
	if noTLS {
		log.Warn("-http-redirect ignored: the page is already served as plain HTTP", "redirect", addr)
		return
	}
	_, httpsPort, err := net.SplitHostPort(listen)
	if err != nil {
		log.Warn("-http-redirect ignored: cannot read the HTTPS port from -listen", "listen", listen, "err", err)
		return
	}
	rs := newRedirectServer(addr, httpsPort)
	go func() {
		log.Info("redirecting plain HTTP to HTTPS", "listen", addr, "https_port", httpsPort)
		if err := rs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("HTTP redirect is not running", "listen", addr, "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rs.Shutdown(sctx)
	}()
}
