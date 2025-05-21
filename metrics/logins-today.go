package metrics

import (
	"os/exec"
	"strings"
	"time"
)

// UpdateLoginsToday sets SSHLoginsToday based on unique SSH sessions today
func UpdateLoginsToday() {
	out, err := exec.Command("last").Output()
	if err != nil {
		return
	}
	lines := strings.Split(string(out), "\n")

	today := time.Now()
	month := today.Format("Jan")
	day := today.Format("2") // no underscore padding
	uniqueSessions := make(map[string]bool)

	for _, line := range lines {
		if !strings.Contains(line, "pts/") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Find index of month and day
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == month && fields[i+1] == day {
				// Use user + pts + IP + date part as session key
				sessionKey := strings.Join(fields[0:i+4], " ")
				uniqueSessions[sessionKey] = true
				break
			}
		}
	}

	SSHLoginsToday.Set(float64(len(uniqueSessions)))
}
