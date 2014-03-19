package main

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"code.google.com/p/go.net/websocket"
	flags "github.com/jessevdk/go-flags"
	"mozilla.org/util"
	"mozilla.org/wmf"
	"mozilla.org/wmf/storage"
	// Only add the following for devel.
	//	_ "net/http/pprof"

	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
)

var opts struct {
	ConfigFile string `short:"c" long:"config" optional:true description:"Configuration file"`
	Profile    string `long:"profile" optional:true`
	MemProfile string `long:"memprofile" optional:true`
	LogLevel   int    `short:"l" long:"loglevel" optional:true`
}

var (
	logger  *util.HekaLogger
	store   *storage.Storage
	metrics *util.Metrics
)

const (
	// VERSION is the version number for system.
	VERSION = "0.1"
)

func main() {
	flags.ParseArgs(&opts, os.Args)

	// Configuration
	// defaults don't appear to work.
	if opts.ConfigFile == "" {
		opts.ConfigFile = "config.ini"
	}
	config := util.MzGetConfig(opts.ConfigFile)
	config["VERSION"] = VERSION

	// Rest Config
	errChan := make(chan error)
	host := util.MzGet(config, "host", "localhost")
	port := util.MzGet(config, "port", "8080")

	if util.MzGetFlag(config, "aws.get_hostname") {
		if hostname, err := util.GetAWSPublicHostname(); err == nil {
			config["ws_hostname"] = hostname
		}
		if port != "80" {
			config["ws_hostname"] = config["ws_hostname"].(string) + ":" + port
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
			log.Printf("Closing profile...\n")
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
			pprof.WriteHeapProfile(profFile)
			profFile.Close()
		}()
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	logger := util.NewHekaLogger(config)
	metrics := util.NewMetrics(util.MzGet(config,
		"metrics.prefix",
		"wmf"), logger, config)
	store, err := storage.Open(config, logger, metrics)
	if err != nil {
		logger.Error("main", "Unable to connect to database. Have you configured it yet?", nil)
		return
	}
	handlers := wmf.NewHandler(config, logger, store, metrics)

	// Signal handler
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1)

	var RESTMux = http.DefaultServeMux
	var WSMux = http.DefaultServeMux
	var verRoot = strings.SplitN(VERSION, ".", 2)[0]

	// REST calls
	// Device calls.
	RESTMux.HandleFunc(fmt.Sprintf("/%s/register/", verRoot),
		handlers.Register)
	RESTMux.HandleFunc(fmt.Sprintf("/%s/cmd/", verRoot),
		handlers.Cmd)
	// Web UI calls
	RESTMux.HandleFunc(fmt.Sprintf("/%s/queue/", verRoot),
		handlers.RestQueue)
	RESTMux.HandleFunc(fmt.Sprintf("/%s/state/", verRoot),
		handlers.State)
	RESTMux.HandleFunc("/static/",
		handlers.Static)
	RESTMux.HandleFunc("/metrics/",
		handlers.Metrics)
	// Operations call
	RESTMux.HandleFunc("/status/",
		handlers.Status)
	WSMux.Handle(fmt.Sprintf("/%s/ws/", verRoot),
		websocket.Handler(handlers.WSSocketHandler))
	// Handle root calls as webUI
	RESTMux.HandleFunc("/",
		handlers.Index)

	logger.Info("main", "startup...",
		util.Fields{"host": host, "port": port})

	go func() {
		errChan <- http.ListenAndServe(host+":"+port, nil)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			panic("ListenAndServe: " + err.Error())
		}
	case <-sigChan:
		logger.Info("main", "Shutting down...", nil)
	}

}
