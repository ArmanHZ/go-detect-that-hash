package gdth

import (
	"fmt"
)

// TODO prettier printing. Similar to a table with word length checks
// TODO color coded
// TODO some hashcat, john and extended info seems to be mission
// For now, we only print the name
func PrintHash(hashInfo HashInfo) {
	// fmt.Printf("%s\t%d\t%s\t%t\n", hashInfo.Name, hashInfo.Hashcat, hashInfo.John, hashInfo.Extended)
	fmt.Printf("%s\n", hashInfo.Name)
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
