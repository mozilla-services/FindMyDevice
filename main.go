package main

import (
	flags "github.com/jessevdk/go-flags"
	"mozilla.org/util"
	"mozilla.org/wmf"
	"mozilla.org/wmf/storage"

	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
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
	logger *util.HekaLogger
	store  *storage.Storage
)

const (
	VERSION = "0.1"
	SIGUSR1 = syscall.SIGUSR1
)

func main() {
	flags.ParseArgs(&opts, os.Args)

	// Configuration
	fmt.Printf("Opts: %v", opts)
	// defaults don't appear to work.
	if opts.ConfigFile == "" {
		opts.ConfigFile = "config.ini"
	}
	config := util.MzGetConfig(opts.ConfigFile)
	config["VERSION"] = VERSION
	runtime.GOMAXPROCS(runtime.NumCPU())
	logger := util.NewHekaLogger(config)
	store, err := storage.Open(config, logger)
	if err != nil {
		logger.Error("main", "FAIL", nil)
		return
	}
	handlers := wmf.NewHandler(config, logger, store)

	// Signal handler
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGHUP, SIGUSR1)

	// Rest Config
	errChan := make(chan error)
	host := util.MzGet(config, "host", "localhost")
	port := util.MzGet(config, "port", "8080")

	var RESTMux *http.ServeMux = http.DefaultServeMux
	var verRoot = strings.SplitN(VERSION, ".", 2)[0]

	// REST calls
	// Device calls.
	RESTMux.HandleFunc(fmt.Sprintf("/%s/register/", verRoot),
		handlers.Register)
	RESTMux.HandleFunc(fmt.Sprintf("/%s/cmd/", verRoot),
		handlers.Cmd)
	// Web UI calls
	RESTMux.HandleFunc(fmt.Sprintf("/%s/queue/", verRoot),
		handlers.Queue)
	RESTMux.HandleFunc(fmt.Sprintf("/%s/state/", verRoot),
		handlers.State)
	RESTMux.HandleFunc("/static/",
		handlers.Static)
	RESTMux.HandleFunc("/metrics/",
		handlers.Metrics)
	// Operations call
	RESTMux.HandleFunc("/status/",
		handlers.Status)
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
