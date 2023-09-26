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
	}
)

// returns a slice of possible hashes
func Detect(hash string) []HashInfo {
	for _, proto := range prototypes {
		if proto.regexp.MatchString(hash) {
			return proto.mode
		}
	}
	return nil
}
