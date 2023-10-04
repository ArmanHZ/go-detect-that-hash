package main

import (
	"fmt"
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
	fmt.Fprintln(tabWritter, "Name\tHashCat ID\tJohn ID\tIs extended")
	fmt.Fprintln(tabWritter, "-----\t-----\t-----\t-----")

	for _, result := range results {
		gdth.PrintHash(tabWritter, result)
	}
	tabWritter.Flush()
}
