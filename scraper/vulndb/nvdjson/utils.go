package nvdjson

import (
	"errors"
	"strings"
)

// parseCPE23 parses CPE 2.3 string.
func parseCPE23(cpe23str string) (parts []string, err error) {
	parts = strings.Split(cpe23str, ":")
	if len(parts) != 13 {
		return nil, errors.New("Invalid cpe23")
	}
	if parts[0] != "cpe" && parts[1] != "2.3" {
		return nil, errors.New("invalid cpe23")
	}

	return parts, nil
}
