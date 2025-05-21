package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Himanshu-216/ssh-exporter/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
)

var (
	listenAddress = flag.String("web.listen-address", "0.0.0.0:9898", "Address and port to expose metrics on")
	showVersion   = flag.Bool("version", false, "Print version information and exit")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Println("ssh-exporter")
		fmt.Println("  Version:", version.Info())
		fmt.Println("  Build:  ", version.BuildContext())
		os.Exit(0)
	}

	metrics.RegisterMetrics()

	go func() {
		err := metrics.MonitorAuthLog("/var/log/auth.log")
		if err != nil {
			fmt.Printf("error in MonitorAuthLog: %v\n", err)
		}
	}()

	// Update derived metrics periodically
	go func() {
		for {
			metrics.UpdateLoginsToday()
			metrics.UpdateLastLoginTimes()
			metrics.LoginsmonitorwithIP()
			time.Sleep(5 * time.Second)
		}
	}()

	fmt.Printf("Starting SSH Exporter on %s\n", *listenAddress)
	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start server: %v\n", err)
		os.Exit(1)
	}
}
