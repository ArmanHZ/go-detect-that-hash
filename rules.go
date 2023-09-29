package gdth

import (
	"regexp"
)

type HashInfo struct {
	name     string
	hashcat  int
	john     string
	extended bool
}

type Prototype struct {
	regexp *regexp.Regexp
	mode   []HashInfo
}

var (
	prototypes []Prototype = []Prototype{
		{
			regexp: regexp.MustCompile(`^[a-f0-9]{4}$`),
			mode: []HashInfo{
				{"CRC-16", -1, "", false},
				{"CRC-16-CCITT", -1, "", false},
				{"FCS-16", -1, "", false},
			},
		},
		{ // List incomplete. Only sha-256 for testing
			regexp: regexp.MustCompile(`^[aA-fF0-9]{64}(:.+)?$`),
			mode: []HashInfo{
				{"SHA-256", 1400, "raw-sha256", false},
			},
		},
	}
)
