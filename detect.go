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

func PrintTable(hashes []HashInfo, headers []string, paddings ... int) {
	fmt.Println(printTableLine(paddings...))


	for numHead, _ := range headers{
		fmt.Print(prepareTableItem(headers[numHead], paddings[numHead]))
	}

	fmt.Println(printTableLine(paddings...))

 
	for _, v := range hashes {
	for numHead, head := range headers {
    head := strings.ToLower(head) 
	switch head{
		case "name":
		fmt.Print(prepareTableItem(v.Name, paddings[numHead]))

		case "hashcat":
		if v.Hashcat == -1 {
			fmt.Print(prepareTableItem("N/A", paddings[numHead]))
		} else {
			fmt.Print(prepareTableItem(strconv.Itoa(v.Hashcat), paddings[numHead]))
			}

	   case "john":
	   if v.John == "" {
	   	fmt.Print(prepareTableItem("N/A", paddings[numHead]))
	   } else {
	   	fmt.Print(prepareTableItem(v.John, paddings[numHead]))
	   }

	   case "extended":
	   if v.Extended {
	   			fmt.Print(prepareTableItem("True", paddings[numHead]))
	   		} else {
	   			fmt.Print(prepareTableItem("False", paddings[numHead]))
	   		}

	   default:
	   fmt.Print(prepareTableItem("", paddings[numHead]))

	}
    }
	fmt.Println()
	}
	fmt.Println(printTableLine(paddings...))
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
