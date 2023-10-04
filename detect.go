package gdth

import (
	"fmt"
	"text/tabwriter"
)

// TODO prettier formatting for the table
// TODO color coded
// TODO some hashcat, john and extended info seems to be mission
func PrintHash(tabWritter *tabwriter.Writer, hashInfo HashInfo) {
	fmt.Fprintf(tabWritter, "%s\t%d\t%s\t%t\n", hashInfo.Name, hashInfo.Hashcat, hashInfo.John, hashInfo.Extended)
}

// returns a slice of possible hashes
func Detect(hash string) []HashInfo {
	var hashes []HashInfo

	for _, proto := range prototypes {
		if proto.match(hash) {
			hashes = append(hashes, proto.mode...)
		}
	}

	return hashes
}
