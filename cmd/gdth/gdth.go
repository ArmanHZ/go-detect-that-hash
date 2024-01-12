package main

import (
	"os"

	gdth "github.com/ArmanHZ/go-detect-that-hash"
)

func main() {
	// TODO input to lowercase. Must research if there are any case sensitive hashes first tho.
	// For testing. Extra checks later.
	inputHash := os.Args[1]
	results := gdth.Detect(inputHash)

	gdth.PrintTable(results, []string{"Name", "HashCat", "John", "Extended?"}, 40, 10, 20, 12)
}
