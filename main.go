package main

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"io/ioutil"

	"code.google.com/p/go.net/websocket"
	flags "github.com/jessevdk/go-flags"
	"github.com/mozilla-services/FindMyDevice/util"
	"github.com/mozilla-services/FindMyDevice/wmf"

	// Only add the following for devel.
	//	_ "net/http/pprof"

	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
)

var opts struct {
	ConfigFile string `short:"c" long:"config" description:"Configuration file"`
	Profile    string `long:"profile"`
	MemProfile string `long:"memprofile"`
	LogLevel   int    `short:"l" long:"loglevel"`
	LogFile    string `short:"o" long:"logfile"`

	Ddlcreate    string `long:"ddlcreate" description:"Create a new version"`
	Ddldowngrade string `long:"ddldowngrade" description:"Downgrade to a specific version"`
	Ddlupgrade   bool   `long:"ddlupgrade" description:"Upgrade database to latest"`
	Ddllog       bool   `long:"ddllog" description:"Show a revision history of the database"`
}

const (
	// VERSION is the version number for system.
	VERSION = "1.4.6"
	SERVER  = "FindMyDevice"
)

// get the latest version from the file, "GITREF"
func getCodeVersionFromFile() string {
	vers, err := ioutil.ReadFile("GITREF")
	if err != nil {
		log.Print(err)
		return ""
	}
	return strings.TrimSpace(string(vers))
}

// get the latest version from git.
// If this isn't a git install, report "Unknown"
func getCodeVersion() string {
	if vers := getCodeVersionFromFile(); vers != "" {
		return vers
	}
	var buffer = new(bytes.Buffer)
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Stdout = buffer
	err := cmd.Run()
	if err != nil {
		log.Printf("Could not get Git Version: %s", err.Error())
		return "Unknown"
	}
	return strings.TrimSpace(buffer.String())
}

func main() {
	if _, err := flags.ParseArgs(&opts, os.Args); err != nil {
		log.Fatalf(err.Error())
		return
	}

	// Configuration
	// TODO: switch to regular go flag package
	// defaults don't appear to work.
	if opts.ConfigFile == "" {
		opts.ConfigFile = "config.ini"
	}

	config, err := util.ReadMzConfig(opts.ConfigFile)
	if err != nil {
		log.Fatalf("Could not read config file %s: %s", opts.ConfigFile, err.Error())
		return
	}

	fullVers := fmt.Sprintf("%s-%s", config.Get("VERSION", VERSION),
		getCodeVersion())
	config.Override("VERSION", fullVers)
	config.Override("SERVER", SERVER)
	config.Override("ddl.create", opts.Ddlcreate)
	config.Override("ddl.downgrade", opts.Ddldowngrade)
	if opts.LogFile != "" {
		config.Override("logger.output", opts.LogFile)
	}
	if opts.Ddlupgrade {
		config.SetDefaultFlag("ddl.upgrade", true)
	}
	if opts.Ddllog {
		config.SetDefaultFlag("ddl.log", true)
	}
	sock_secret, _ := util.GenUUID4()
	config.SetDefault("ws.socket_secret", sock_secret)

	// Rest Config
	errChan := make(chan error)
	host := config.Get("host", "localhost")
	port := config.Get("port", "8080")

	if config.GetFlag("aws.get_hostname") {
		if hostname, err := util.GetAWSPublicHostname(); err == nil {
			config.SetDefault("ws_hostname", hostname)
		}
		if port != "80" {
			config.SetDefault("ws_hostname", config.Get("ws_hostname", "")+":"+port)
		}
	}

	// Partner cert pool contains the various self-signed certs that
	// partners may require to access their servers (for Proprietary
	// wake mechanisms like UDP)
	// This would be where you collect the certs and store them into
	// the config map as something like:
	// config["partnerCertPool"] = self.loadCerts()

	if opts.Profile != "" {
		log.Printf("Creating profile %s...\n", opts.Profile)
		f, err := os.Create(opts.Profile)
		if err != nil {
			log.Fatal(fmt.Sprintf("Profile creation failed:\n%s\n",
				err.Error()))
			return
		}
		defer func() {
			log.Printf("Writing app profile...\n")
			pprof.StopCPUProfile()
		}()
		pprof.StartCPUProfile(f)
	}
	if opts.MemProfile != "" {
		defer func() {
			profFile, err := os.Create(opts.MemProfile)
			if err != nil {
				log.Fatal(fmt.Sprintf("Memory Profile creation failed:\n%s\n", err.Error()))
				return
			}
			log.Printf("Writing memory profile...\n")
			pprof.WriteHeapProfile(profFile)
			profFile.Close()
		}()
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	logger := util.NewLogger(config)
	metrics := util.NewMetrics(config.Get(
		"metrics.prefix",
		"wmf"), logger, config)
	if err != nil {
		logger.Error("main", "Unable to connect to database. Have you configured it yet?", nil)
		return
	}
	if hawkCount := config.Get("hawk.nonce_cache", "1000"); hawkCount != "1000" {
		count, err := strconv.ParseInt(hawkCount, 10, 32)
		if err != nil {
			log.Printf("Could not read hawk.nonce_cache, defaulting to 1000")
		} else {
			wmf.InitHawkNonces(count)
		}
	}
	handlers := wmf.NewHandler(config, logger, metrics)
	if handlers == nil {
		log.Fatalf("Could not start server. Please check config.ini")
	}

	// Signal handler
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1)

	var RESTMux = http.DefaultServeMux
	var WSMux = http.DefaultServeMux
	var verRoot = strings.SplitN(VERSION, ".", 2)[0]

	// REST calls

	RESTMux.HandleFunc(fmt.Sprintf("/%s/register/", verRoot),
		handlers.Register)
	RESTMux.HandleFunc(fmt.Sprintf("/%s/cmd/", verRoot),
		handlers.Cmd)
	// Web UI calls
	RESTMux.HandleFunc(fmt.Sprintf("/%s/queue/", verRoot),
		handlers.RestQueue)
	RESTMux.HandleFunc(fmt.Sprintf("/%s/state/", verRoot),
		handlers.State)
	RESTMux.HandleFunc(fmt.Sprintf("/%s/l10n/client.json", verRoot),
		handlers.Language)
	// Static files (served by nginx in production)
	if config.GetFlag("use_insecure_static") {
		RESTMux.HandleFunc("/bower_components/",
			handlers.Static)
		RESTMux.HandleFunc("/images/",
			handlers.Static)
		RESTMux.HandleFunc("/scripts/",
			handlers.Static)
		RESTMux.HandleFunc("/styles/",
			handlers.Static)
	}
	// Metrics
	RESTMux.HandleFunc("/metrics/",
		handlers.Metrics)
	// Operations call
	RESTMux.HandleFunc("/status/",
		handlers.Status)
	//Signin
	// set state nonce & check if valid at signin
	RESTMux.HandleFunc("/signin/",
		handlers.Signin)
	//Signout
	RESTMux.HandleFunc("/signout/",
		handlers.Signout)
	// Config option because there are other teams involved.
	auth := config.Get("fxa.redir_uri", "/oauth/")
	RESTMux.HandleFunc(auth, handlers.OAuthCallback)

	WSMux.Handle(fmt.Sprintf("/%s/ws/", verRoot),
		websocket.Handler(handlers.WSSocketHandler))
	// Handle root calls as webUI
	// Get a list of registered devices for the currently logged in user
	RESTMux.HandleFunc(fmt.Sprintf("/%s/devices/", verRoot),
		handlers.UserDevices)
	// Get an object describing the data for a user's device
	// e.g. http://host/0/data/0123deviceid
	RESTMux.HandleFunc(fmt.Sprintf("/%s/data/", verRoot),
		handlers.InitDataJson)
	RESTMux.HandleFunc(fmt.Sprintf("/%s/validate/", verRoot),
		handlers.Validate)
	RESTMux.HandleFunc("/",
		handlers.Index)

	logger.Info("main", "startup...",
		util.Fields{"host": host, "port": port, "version": fullVers})

	go func() {
		errChan <- http.ListenAndServe(host+":"+port, nil)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			log.Fatalf("ListenAndServe: " + err.Error())
		}
	case <-sigChan:
		logger.Info("main", "Shutting down...", nil)
	}
}
