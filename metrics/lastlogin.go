package metrics

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func UpdateLastLoginTimes() {
	out, err := exec.Command("lastlog").Output()
	if err != nil {
		return
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) <= 1 {
		return
	}

	space := regexp.MustCompile(`\s+`)

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := space.Split(line, -1)
		if len(fields) < 6 {
			continue
		}

		user := fields[0]
		dateFields := fields[len(fields)-6:] // last 6 fields = full date
		dateStr := strings.Join(dateFields, " ")

		t, err := time.Parse("Mon Jan 2 15:04:05 -0700 2006", dateStr)
		if err == nil {
			LastLoginTime.WithLabelValues(user).Set(float64(t.Unix()))
		} else {
			fmt.Println("Failed to parse date for user", user, ":", dateStr)
		}
	}
}
