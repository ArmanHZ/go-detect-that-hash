package gdth

import (
	"fmt"
	"strconv"
	"strings"
)

// Idk, I'll look at a way of doing Enum or Struct. This looks ugly lol
const (
	Color_reset = "\033[0m"
	Color_cyan  = "\033[36m"
	Color_red   = "\033[31m"
	Color_green = "\033[32m"
)

func printTableLine(paddings ...int) string {
	sum := 0
	for _, v := range paddings {
		sum += v
	}
	result := strings.Repeat("-", sum)
	if sum%2 == 0 {
		result += strings.Repeat("-", 8)
	} else {
		result += strings.Repeat("-", 7)
	}
	return result + "+"
}

// Text will be in the middle
func prepareTableItem(item string, padding int) string {
	paddingToApply := (padding - len(item))
	result := ""
	if paddingToApply%2 != 0 {
		result += " "
	}
	result += strings.Repeat(" ", paddingToApply/2) + item + strings.Repeat(" ", paddingToApply/2) + " |"
	return result
}

func getGreatestLength(header string, words []string) int {
	maxLen := len(header)
		for _, word := range words {
			if len(word) > maxLen {
				maxLen = len(word)
			}
		}
		return maxLen+2
}


func sortDetectSlice(results []HashInfo) ([]string, []string, []string, []string) {
	//return all as slice of strings so that GetMaxLength will be readable and maintainable
	var name, john, hashcat, extended []string
	for _, v := range results {
		strHC := strconv.Itoa(v.Hashcat)
		strExtd := strconv.FormatBool(v.Extended)
		name = append(name, v.Name)
		hashcat = append(hashcat, strHC)
		john = append(john, v.John)
		extended = append(extended, strExtd)
	}
	return name, hashcat, john, extended
}
// Column width should be generated programatically, get padding from value with greatest length
// Static column width (provided by dev) is prone to panic "panic: strings: negative Repeat count" when length of an item
// is greater than provided static length. Forcing dev to give a higher upper limit column length, where mostly that much
//space is not needed

func PrintTable(hashes []HashInfo, headers []string) {
	nameSlice, hcSlice, johnSlice, extendedSlice := sortDetectSlice(hashes)
	nameLen := getGreatestLength(headers[0], nameSlice)
	hashcatLen := getGreatestLength(headers[1], hcSlice)
	johnLen := getGreatestLength(headers[2], johnSlice)
	extendedLen := getGreatestLength(headers[3], extendedSlice)
	tableLine := printTableLine(nameLen+hashcatLen+johnLen+extendedLen)

	// fmt.Println(printTableLine(paddings...))
	fmt.Println(tableLine)

	fmt.Print(prepareTableItem(headers[0], nameLen))
	fmt.Print(prepareTableItem(headers[1], hashcatLen))
	fmt.Print(prepareTableItem(headers[2], johnLen))
	fmt.Println(prepareTableItem(headers[3], extendedLen))

	//fmt.Println(printTableLine(paddings...))
	fmt.Println(tableLine)

	for _, v := range hashes {
		fmt.Print(prepareTableItem(v.Name, nameLen))
		if v.Hashcat == -1 {
			fmt.Print(prepareTableItem("N/A", hashcatLen))
		} else {
			fmt.Print(prepareTableItem(strconv.Itoa(v.Hashcat), hashcatLen))
		}
		if v.John == "" {
			fmt.Print(prepareTableItem("N/A", johnLen))
		} else {
			fmt.Print(prepareTableItem(v.John, johnLen))
		}
		if v.Extended {
			fmt.Print(prepareTableItem("True", extendedLen))
		} else {
			fmt.Print(prepareTableItem("False", extendedLen))
		}
		fmt.Println()
	}
	fmt.Println(tableLine)
}

func PrintCSV(hashes []HashInfo) {
	fmt.Println("Name,HashCat,John,Extended")
	for _, v := range hashes {
		fmt.Print(v.Name + ",")

		if v.Hashcat == -1 {
			fmt.Print("N/A,")
		} else {
			fmt.Print(strconv.Itoa(v.Hashcat) + ",")
		}

		if v.John == "" {
			fmt.Print("N/A,")
		} else {
			fmt.Print(v.John + ",")
		}

		if v.Extended {
			fmt.Println("True")
		} else {
			fmt.Println("False")
		}
	}
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

func IsSupported(hashcatID int) bool {
	for _, proto := range prototypes {
		for _, mode := range proto.mode {
			if mode.Hashcat == hashcatID {
				return true
			}
		}
	}
	return false
}
