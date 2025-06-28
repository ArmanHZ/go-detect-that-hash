package main

import (
	"flag"
	"os"
	"strings"

	gdth "github.com/ArmanHZ/go-detect-that-hash"
)

func main() {
	// TODO input to lowercase. Must research if there are any case sensitive hashes first tho.
	// For testing. Extra checks later.
	outputMode := flag.String("format", "table", "Output mode. Options: table, csv")
    columns := flag.String("column", "Name, HashCat, John, Extended", "May offer help later")
	flag.Parse()

     if flag.NArg() < 1{
     	flag.Usage()
     	os.Exit(1)
     }


	inputHash := flag.Arg(0)
	results := gdth.Detect(inputHash)
		selectedColumns := strings.Split(*columns, ",")


//this is to get the individual padding of each column 
paddings := make ([]int, len(selectedColumns))
for i, _ := range selectedColumns{
	switch strings.ToLower(selectedColumns[i]){
		case "name":
		paddings[i] = 40

		case "hashcat":
		paddings[i] = 10

		case "john":
		paddings[i] = 30

		case "extended":
		paddings[i] = 12

		default:
		paddings[i] = 10
	}
}

	switch *outputMode {
	case "csv":
		gdth.PrintCSV(results)
	default:
	gdth.PrintTable(results, selectedColumns, paddings...)
	}
}
