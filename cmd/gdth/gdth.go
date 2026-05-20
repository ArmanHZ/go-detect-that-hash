package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"

	gdth "github.com/ArmanHZ/go-detect-that-hash"
)

func readHashesFromFile(fileName string) []string {
	var hashes []string

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Failed to open file: %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		hashes = append(hashes, line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %s", err)
	}

	return hashes
}

func main() {
	// TODO input to lowercase. Must research if there are any case sensitive hashes first tho.
	// For testing. Extra checks later.
	outputMode := flag.String("format", "table", "Output mode. Options: table, csv")
	var fileName string
	flag.StringVar(&fileName, "file", "", "Read hashes from a file")

	flag.Parse()

	// FIXME: Code repetition here looks ugly. The fix would be to have another
	// detect function that takes a list of hashes, but that requires the print
	// functions to change as well.
	if fileName != "" {
		fileHashes := readHashesFromFile(fileName)
		for _, hash := range fileHashes {
			results := gdth.Detect(hash)

			switch *outputMode {
			case "csv":
				fmt.Printf("\nHash: %s\n", hash)
				gdth.PrintCSV(results)
			default:
				fmt.Printf("\nHash: %s\n", hash)
				gdth.PrintTable(results, []string{"Name", "HashCat", "John", "Extended?"}, 40, 10, 20, 12)
			}
		}
	} else {
		inputHash := flag.Arg(0)
		results := gdth.Detect(inputHash)

		switch *outputMode {
		case "csv":
			gdth.PrintCSV(results)
		default:
			gdth.PrintTable(results, []string{"Name", "HashCat", "John", "Extended?"}, 40, 10, 20, 12)
		}
	}

}
