package main

/*
This program generates the tests for the detect function using scraped hashes from https://hashcat.net/wiki/doku.php?id=example_hashes

Usage (from the root of the project):
go run ./testgen > test/detect_test.go
*/

import (
	"bytes"
	_ "embed"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	gdth "github.com/ArmanHZ/go-detect-that-hash"
)

var (
	//go:embed hashes
	hashes string

	testNames map[string]bool
)

const (
	prologue = `package gdth_test

import (
	"testing"
	gdth "github.com/ArmanHZ/go-detect-that-hash"
)

func checkIncludedHashID(hashes []gdth.HashInfo, hashcatID int) bool {
	for _, h := range hashes {
		if h.Hashcat == hashcatID {
			return true
		}
	}
	return false
}
`
)

// replace all non-alphanumeric characters with an underscore
func sanitizeName(name string) string {
	result := ""
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			result += string(c)
		} else {
			result += "_"
		}
	}
	return strings.ToUpper(result)
}

func downloadRemoteHash(url string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	buffer := bytes.Buffer{}
	_, err = buffer.ReadFrom(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(buffer.String()), nil
}

func main() {
	testNames = make(map[string]bool)

	hashTypes := strings.Split(hashes, "\n")

	fmt.Println(prologue)
	for _, hashType := range hashTypes {
		if hashType == "" {
			continue
		}

		data := strings.Split(hashType, "\t")
		hashcatID := data[0]
		name := data[1]
		hash := data[2]

		// check if the hashcatID is currently supported
		id, _ := strconv.Atoi(hashcatID)
		if !gdth.IsSupported(id) {
			continue
		}

		// pass duplicate tests
		testName := sanitizeName(name)
		if testNames[testName] {
			continue
		}
		testNames[testName] = true

		// check if the hash is remote
		if strings.HasPrefix(hash, "http") {
			var err error
			if hash, err = downloadRemoteHash(hash); err != nil {
				fmt.Printf("// Failed to download hash %s: %s\n", name, err)
				continue
			}
		}

		// build test function
		fmt.Printf("func Test%s(t *testing.T) {\n", testName)
		fmt.Printf("\tif hashes := gdth.Detect(\"%s\"); !checkIncludedHashID(hashes, %s) {\n", hash, hashcatID)
		fmt.Printf("\t\tt.Errorf(\"Expected %s, got %%v\", hashes)\n", name)
		fmt.Printf("\t}\n")
		fmt.Printf("}\n\n")
	}
}
