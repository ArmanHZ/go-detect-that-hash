package gdth

// TODO add something like to string or beautify the []HashInfo

// returns a slice of possible hashes
func Detect(hash string) []HashInfo {
	var hashes []HashInfo

	for _, proto := range prototypes {
		if proto.regexp.MatchString(hash) {
			hashes = append(hashes, proto.mode...)
		}
	}

	return hashes
}
