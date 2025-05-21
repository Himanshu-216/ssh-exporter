package metrics

import (
	// "fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// LoginsmonitorwithIP updates Prometheus metrics for successful and failed SSH logins by IP.
func LoginsmonitorwithIP() {
	// Use space-padded day to match `last` and `lastb` output (e.g., "May  4")
	today := time.Now().Format("Jan _2")
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	// ---- Failed logins from `lastb` ----
	failedOut, err := exec.Command("lastb").Output()
	if err != nil {
		return
	}
	failedLines := strings.Split(string(failedOut), "\n")
	failedLoginIPCount := make(map[string]int)
	for _, line := range failedLines {
		if strings.Contains(line, today) {
			ip := ipRegex.FindString(line)
			if ip != "" {
				failedLoginIPCount[ip]++
			}
		}
	}

	SSHFailedLoginsByIP.Reset()
	for ip, count := range failedLoginIPCount {
		SSHFailedLoginsByIP.WithLabelValues(ip).Set(float64(count))
	}

	// ---- Successful logins from `last` ----
	successOut, err := exec.Command("last").Output()
	if err != nil {
		return
	}
	successLines := strings.Split(string(successOut), "\n")
	successfulLoginIPCount := make(map[string]int)

	for _, line := range successLines {
		if strings.Contains(line, today) && strings.Contains(line, "pts/") {
			ip := ipRegex.FindString(line)
			if ip != "" {
				successfulLoginIPCount[ip]++
			}
		}
	}

	SSHSuccessfulLoginsByIP.Reset()
	for ip, count := range successfulLoginIPCount {
		SSHSuccessfulLoginsByIP.WithLabelValues(ip).Set(float64(count))
	}

}
