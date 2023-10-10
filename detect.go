package gdth

import (
	"fmt"
	"text/tabwriter"
)

// Idk, I'll look at a way of doing Enum or Struct. This looks ugly lol
const (
	Color_reset = "\033[0m"
	Color_cyan  = "\033[36m"
	Color_red   = "\033[31m"
	Color_green = "\033[32m"
)

// TODO prettier formatting for the table
// TODO maybe we should create a print table file or have functions to do so
func PrintHash(tabWritter *tabwriter.Writer, hashInfo HashInfo) {
	fmt.Fprintf(tabWritter, Color_green+"%s\t"+Color_reset, hashInfo.Name)
	if hashInfo.Hashcat != -1 {
		fmt.Fprintf(tabWritter, Color_green+"%d\t"+Color_reset, hashInfo.Hashcat)
	} else {
		fmt.Fprintf(tabWritter, Color_red+"N/A\t"+Color_reset)
	}
	if hashInfo.John == "" {
		fmt.Fprintf(tabWritter, Color_red+"N/A\t"+Color_reset)
	} else {
		fmt.Fprintf(tabWritter, Color_green+"%s\t"+Color_reset, hashInfo.John)
	}
	fmt.Fprintf(tabWritter, Color_green+"%t\n"+Color_reset, hashInfo.Extended)
}

func PrintHashes(tabWritter *tabwriter.Writer, hashInfo []HashInfo) {
	fmt.Fprintln(tabWritter, Color_cyan+"Name\tHashCat\tJohn\tIs extended"+Color_reset)
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
