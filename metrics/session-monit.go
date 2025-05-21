package metrics

import (
	"fmt"
	"regexp"
	"time"

	"github.com/hpcloud/tail"
)

type Session struct {
	LoginTime   time.Time
	User        string
	Fingerprint string
	SystemdID   string
}

var (
	sessions     = make(map[string]*Session) // key: systemd session ID
	tempSessions = make(map[string]*Session) // key: username before session ID is known

	loginRegex        = regexp.MustCompile(`sshd\[\d+\]: Accepted publickey for (\w+) from .* ssh2: RSA (\S+)`)
	sessionStartRegex = regexp.MustCompile(`systemd-logind\[\d+\]: New session (\d+) of user (\w+)`)
	sessionEndRegex   = regexp.MustCompile(`systemd-logind\[\d+\]: Removed session (\d+)`)
	timeRegex         = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`)
)

func MonitorAuthLog(logFilePath string) error {
	t, err := tail.TailFile(logFilePath, tail.Config{
		Follow: true,
		ReOpen: true,
		Poll:   true,
	})
	if err != nil {
		return fmt.Errorf("failed to tail file: %v", err)
	}

	for line := range t.Lines {
		timestampStr := timeRegex.FindStringSubmatch(line.Text)
		if timestampStr == nil {
			continue
		}
		entryTime, err := time.Parse("2006-01-02T15:04:05", timestampStr[1])
		if err != nil {
			fmt.Printf("[WARN] Could not parse time: %v\n", err)
			continue
		}

		if loginMatch := loginRegex.FindStringSubmatch(line.Text); loginMatch != nil {
			user := loginMatch[1]
			fingerprint := loginMatch[2]

			tempSessions[user] = &Session{
				LoginTime:   entryTime,
				User:        user,
				Fingerprint: fingerprint,
			}
			continue
		}

		if startMatch := sessionStartRegex.FindStringSubmatch(line.Text); startMatch != nil {
			sessionID := startMatch[1]
			user := startMatch[2]

			if s, ok := tempSessions[user]; ok {
				s.SystemdID = sessionID
				sessions[sessionID] = s
				delete(tempSessions, user)

				SSHSessionActive.WithLabelValues(sessionID, user, s.Fingerprint).Set(1)
			} else {
				fmt.Printf("[WARN] No temp session for user %s\n", user)
			}
			continue
		}

		if endMatch := sessionEndRegex.FindStringSubmatch(line.Text); endMatch != nil {
			sessionID := endMatch[1]

			if s, ok := sessions[sessionID]; ok {
				endTime := entryTime
				duration := endTime.Sub(s.LoginTime).Seconds()
				loginTimeStr := s.LoginTime.Format(time.RFC3339)

				SSHSessionDuration.WithLabelValues(sessionID, s.User, s.Fingerprint, loginTimeStr).Set(duration)

				// Only delete active metric
				SSHSessionActive.DeleteLabelValues(sessionID, s.User, s.Fingerprint)

				delete(sessions, sessionID)
			} else {
				fmt.Printf("[WARN] No session found for SessionID=%s\n", sessionID)
			}
			continue
		}
	}

	return nil
}
