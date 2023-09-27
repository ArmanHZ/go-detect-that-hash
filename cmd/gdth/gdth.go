package main

import (
	"fmt"
	"os"

	gdth "github.com/ArmanHZ/go-detect-that-hash"
)

func main() {
	// For testing. Extra checks later.
	inputHash := os.Args[1]
	fmt.Println(gdth.Detect(inputHash))
}
