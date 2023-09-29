package gdth

import (
	"testing"
)

func checkIncludedHash(hashes []HashInfo, hash string) bool {
	for _, h := range hashes {
		if h.name == hash {
			return true
		}
	}
	return false
}

func TestSha256(t *testing.T) {
	if hashes := Detect("127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"); !checkIncludedHash(hashes, "SHA-256") {
		t.Errorf("Expected SHA-256, got %v", hashes)
	}
}
