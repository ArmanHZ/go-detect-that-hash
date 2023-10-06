package gdth

import (
	"fmt"
	"text/tabwriter"
)

// TODO prettier formatting for the table
// TODO color coded
// TODO some hashcat, john and extended info seems to be missing
func PrintHash(tabWritter *tabwriter.Writer, hashInfo HashInfo) {
	fmt.Fprintf(tabWritter, "%s\t", hashInfo.Name)
	if hashInfo.Hashcat != -1 {
		fmt.Fprintf(tabWritter, "%d\t", hashInfo.Hashcat)
	} else {
		fmt.Fprintf(tabWritter, "\t")
	}

	fmt.Fprintf(tabWritter, "%12s\t%t\n", hashInfo.John, hashInfo.Extended)
}

func PrintHashes(tabWritter *tabwriter.Writer, hashInfo []HashInfo) {
	fmt.Fprintln(tabWritter, "Name\tHashCat\tJohn\tIs extended\t")
	fmt.Fprintln(tabWritter, "-----\t-----\t-----\t-----\t")
	for _, hash := range hashInfo {
		PrintHash(tabWritter, hash)
	}
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
