package gdth

import (
	"testing"
)

func checkIncludedHashName(hashes []HashInfo, hash string) bool {
	for _, h := range hashes {
		if h.Name == hash {
			return true
		}
	}
	return false
}

func checkIncludedHashID(hashes []HashInfo, hashcatID int) bool {
	for _, h := range hashes {
		if h.Hashcat == hashcatID {
			return true
		}
	}
	return false
}

// most hashes have been taken from https://hashcat.net/wiki/doku.php?id=example_hashes

func TestSha256(t *testing.T) {
	if hashes := Detect("127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"); !checkIncludedHashName(hashes, "SHA-256") {
		t.Errorf("Expected SHA-256, got %v", hashes)
	}
}

func TestGRUB2(t *testing.T) {
	if hashes := Detect("grub.pbkdf2.sha512.10000.7d391ef48645f626b427b1fae06a7219b5b54f4f02b2621f86b5e36e83ae492bd1db60871e45bc07925cecb46ff8ba3db31c723c0c6acbd4f06f60c5b246ecbf.26d59c52b50df90d043f070bd9cbcd92a74424da42b3666fdeb08f1a54b8f1d2f4f56cf436f9382419c26798dc2c209a86003982b1e5a9fcef905f4dfaa4c524"); !checkIncludedHashName(hashes, "GRUB 2") {
		t.Errorf("Expected GRUB2, got %v", hashes)
	}
}

// TODO: i really can't find an example hash for this, maybe someone else can?
// func TestMSTSC(t *testing.T) {
// 	if hashes := Detect(""); !checkIncludedHash(hashes, "MSTSC") {
// 		t.Errorf("Expected MSTSC, got %v", hashes)
// 	}
// }