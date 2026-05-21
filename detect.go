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

func getColumnSizesWithPaddings(hashes []HashInfo) []int {
	// Default sizes in case of empty output.
	// These are the sizes of the column title text + 2 for padding.
	sizes := []int{6, 9, 6, 11}

	// We only need to get max sizes of Name and John fields.
	// The hashcat field is a number only field and goes up to a 7 digit number at max.
	// The Extended field is a boolean field, so we use the size of the column.
	for _, v := range hashes {
		if len(v.Name) > sizes[0] {
			sizes[0] = len(v.Name)
		}
		if len(v.John) > sizes[2] {
			sizes[2] = len(v.John)
		}
	}

	// Adding 2 for left and right padding.
	sizes[0] += 2
	sizes[2] += 2

	return sizes
}

func PrintTable(hashes []HashInfo, headers []string) {
	coulmnSizes := getColumnSizesWithPaddings(hashes)
	tableLine := printTableLine(coulmnSizes...)

	fmt.Println(tableLine)

	fmt.Print(prepareTableItem(headers[0], coulmnSizes[0]))
	fmt.Print(prepareTableItem(headers[1], coulmnSizes[1]))
	fmt.Print(prepareTableItem(headers[2], coulmnSizes[2]))
	fmt.Println(prepareTableItem(headers[3], coulmnSizes[3]))

	fmt.Println(tableLine)

	for _, v := range hashes {
		fmt.Print(prepareTableItem(v.Name, coulmnSizes[0]))
		if v.Hashcat == -1 {
			fmt.Print(prepareTableItem("N/A", coulmnSizes[1]))
		} else {
			fmt.Print(prepareTableItem(strconv.Itoa(v.Hashcat), coulmnSizes[1]))
		}
		if v.John == "" {
			fmt.Print(prepareTableItem("N/A", coulmnSizes[2]))
		} else {
			fmt.Print(prepareTableItem(v.John, coulmnSizes[2]))
		}
		if v.Extended {
			fmt.Print(prepareTableItem("True", coulmnSizes[3]))
		} else {
			fmt.Print(prepareTableItem("False", coulmnSizes[3]))
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
