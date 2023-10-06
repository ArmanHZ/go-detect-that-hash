package main

import (
	"os"
	"text/tabwriter"

	gdth "github.com/ArmanHZ/go-detect-that-hash"
)

func main() {
	// TODO input to lowercase. Must research if there are any case sensitive hashes first tho.
	// For testing. Extra checks later.
	inputHash := os.Args[1]
	results := gdth.Detect(inputHash)

	tabWritter := tabwriter.NewWriter(os.Stdout, 0, 10, 1, ' ', 0)
	defer tabWritter.Flush()

	gdth.PrintHashes(tabWritter, results)
}
