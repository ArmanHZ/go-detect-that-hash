package main

import (
	"fmt"
	"os"

	gdth "github.com/ArmanHZ/go-detect-that-hash"
)

func main() {
	// TODO input to lowercase. Must research if there are any case sensitive hashes first tho.
	// For testing. Extra checks later.
	inputHash := os.Args[1]
	results := gdth.Detect(inputHash)

	fmt.Println("Name\t\tHashCat ID\t\tJohn ID\t\tIs extended")
	fmt.Println("-------------------------------------------------------------------")
	for _, result := range results {
		gdth.PrintHash(result)
	}
}
