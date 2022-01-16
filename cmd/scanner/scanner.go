package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ricoberger/harbor-snyk-scanner/pkg/log"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/metrics"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/scanner"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/snyk"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/version"

	flag "github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logFormat   string
	logLevel    string
	showVersion bool
)

// init is used to define all flags for the harbor-snyk-scanner. If a specific package needs some additional flags, they
// must be defined in the init method of the package. See the pkg/metrics/metrics.go file, which defines an additional
// metrics.address flag for the metrics server. All package specific flags should be prefixed with the name of the
// package.
func init() {
	defaultLogFormat := "console"
	if os.Getenv("LOG_FORMAT") != "" {
		defaultLogFormat = os.Getenv("LOG_FORMAT")
	}

	defaultLogLevel := "info"
	if os.Getenv("LOG_LEVEL") != "" {
		defaultLogLevel = os.Getenv("LOG_LEVEL")
	}

	flag.StringVar(&logFormat, "log.format", defaultLogFormat, "Set the output format of the logs. Must be \"console\" or \"json\".")
	flag.StringVar(&logLevel, "log.level", defaultLogLevel, "Set the log level. Must be \"debug\", \"info\", \"warn\", \"error\", \"fatal\" or \"panic\".")
	flag.BoolVar(&showVersion, "version", false, "Print version information.")
}

func main() {
	flag.Parse()

	// Configure our logging library. The logs can be written in console format (the console format is compatible with
	// logfmt) or in json format. The default is console, because it is better to read during development. In a
	// production environment you should consider to use json, so that the logs can be parsed by a logging system like
	// Elasticsearch.
	// Next to the log format it is also possible to configure the log leven. The accepted values are "debug", "info",
	// "warn", "error", "fatal" and "panic". The default log level is "info".
	zapEncoderCfg := zap.NewProductionEncoderConfig()
	zapEncoderCfg.TimeKey = "timestamp"
	zapEncoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	zapConfig := zap.Config{
		Level:            log.ParseLevel(logLevel),
		Development:      false,
		Encoding:         logFormat,
		EncoderConfig:    zapEncoderCfg,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
	}

	logger, err := zapConfig.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	zap.ReplaceGlobals(logger)

	// When the version value is set to "true" (--version) we will print the version information. After we printed the
	// version information the application is stopped.
	// The short form of the version information is also printed in two lines, when the version option is set to
	// "false".
	if showVersion {
		v, err := version.Print("Harbor Snyk Scanner")
		if err != nil {
			log.Fatal(nil, "Failed to print version information", zap.Error(err))
		}

		fmt.Fprintln(os.Stdout, v)
		return
	}

	log.Info(nil, "Version information", version.Info()...)
	log.Info(nil, "Build context", version.BuildContext()...)

	// Initialize each component and start it in it's own goroutine, so that the main goroutine is only used as listener
	// for terminal signals, to initialize the graceful shutdown of the components.
	snykClient := snyk.NewClient()

	scannerServer := scanner.New(snykClient)
	go scannerServer.Start()

	metricsServer := metrics.New()
	go metricsServer.Start()

	// All components should be terminated gracefully. For that we are listen for the SIGINT and SIGTERM signals and try
	// to gracefully shutdown the started components. This ensures that established connections or tasks are not
	// interrupted.
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	log.Debug(nil, "Start listining for SIGINT and SIGTERM signal")
	<-done
	log.Info(nil, "Shutdown...")

	metricsServer.Stop()
	scannerServer.Stop()

	log.Info(nil, "Shutdown is done")
}
