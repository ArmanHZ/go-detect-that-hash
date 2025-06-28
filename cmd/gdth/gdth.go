package main

import (
	"flag"

	gdth "github.com/ArmanHZ/go-detect-that-hash"
)

func main() {
	// TODO input to lowercase. Must research if there are any case sensitive hashes first tho.
	// For testing. Extra checks later.
	outputMode := flag.String("format", "table", "Output mode. Options: table, csv")
	flag.Parse()

	     if flag.NArg() < 1{
     	flag.Usage()
     	os.Exit(1)
     }
	
	inputHash := flag.Arg(0)
	results := gdth.Detect(inputHash)

	switch *outputMode {
	case "csv":
		gdth.PrintCSV(results)
	default:
		gdth.PrintTable(results, []string{"Name", "HashCat", "John", "Extended?"}, 40, 10, 20, 12)
	}
}
