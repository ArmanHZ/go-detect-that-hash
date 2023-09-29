package gdth

// returns a slice of possible hashes
func Detect(hash string) []HashInfo {
	for _, proto := range prototypes {
		if proto.regexp.MatchString(hash) {
			return proto.mode
		}
	}
	return nil
}
