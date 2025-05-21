package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// Metric for tracking the number of active SSH sessions
	SSHSessionActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssh_session_active",
			Help: "Indicates if an SSH session is active (1 = active, 0 = inactive)",
		},
		[]string{"session_id", "user", "fingerprint"},
	)

	// Metric for tracking the number of SSH logins today
	SSHLoginsToday = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssh_logins_today",
		Help: "Number of SSH logins today",
	})

	// Metric for tracking the last login time per user
	LastLoginTime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssh_user_last_login",
			Help: "Last login time per user (Unix timestamp)",
		},
		[]string{"user"},
	)

	// Metric for tracking failed SSH login attempts by IP address
	SSHFailedLoginsByIP = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssh_failed_logins_by_ip",
			Help: "Number of failed SSH login attempts by IP address",
		},
		[]string{"ip"},
	)

	// Metric for tracking successful SSH login attempts by IP address
	SSHSuccessfulLoginsByIP = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssh_total_successful_logins_by_ip",
			Help: "Number of successful SSH login attempts by IP address",
		},
		[]string{"ip"},
	)

	// Metric for tracking the total duration of SSH sessions
	SSHSessionDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssh_session_duration_seconds",
			Help: "Duration of SSH sessions in seconds",
		},
		[]string{"session_id", "user", "fingerprint", "login_time"},
	)
	
	ActiveSSHCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssh_sessions_active_count",
		Help: "The number of active SSH sessions",
	})
)

// Register all metrics with Prometheus
func RegisterMetrics() {
	prometheus.MustRegister(ActiveSSHCount)
	prometheus.MustRegister(SSHLoginsToday)
	prometheus.MustRegister(LastLoginTime)
	prometheus.MustRegister(SSHFailedLoginsByIP)
	prometheus.MustRegister(SSHSuccessfulLoginsByIP)
	prometheus.MustRegister(SSHSessionDuration)
	prometheus.MustRegister(SSHSessionActive)
}
