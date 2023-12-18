package gdth

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type HashInfo struct {
	Name     string
	Hashcat  int
	John     string
	Extended bool
}

type Prototype struct {
	// regexp *regexp.Regexp
	match func(input string) bool
	mode  []HashInfo
}

var (
	regexPool = sync.Map{}
)

// does some simple regex pooling and checks if the input string matches the provided regex.
// will add the regex to the regex pool if it doesn't exist yet.
func checkRegex(regex, input string) bool {
	// we don't want to compile the regex for every comparison, so lazily compile it and store it in a map
	var rexp *regexp.Regexp
	val, ok := regexPool.Load(regex)
	if !ok {
		// we also set the case-insensitive flag here
		rexp = regexp.MustCompile("(?i)" + regex)
		regexPool.Store(regex, rexp)
	} else {
		rexp = val.(*regexp.Regexp)
	}

	return rexp.MatchString(input)
}

// checks input string for lowercase alphanumeric characters
func checkAlphaNumericLower(input string) bool {
	for _, char := range input {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}

	return true
}

// TODO: the commented out rules need to be manually converted from a simple regex to a handspun match function

var (
	prototypes []Prototype = []Prototype{
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{4}$`, input)
			},
			mode: []HashInfo{
				{"CRC-16", -1, "", false},
				{"CRC-16-CCITT", -1, "", false},
				{"FCS-16", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{8}$`, input)
			},
			mode: []HashInfo{
				{"Adler-32", -1, "", false},
				{"CRC-32B", -1, "", false},
				{"FCS-32", -1, "", false},
				{"GHash-32-3", -1, "", false},
				{"GHash-32-5", -1, "", false},
				{"FNV-132", -1, "", false},
				{"Fletcher-32", -1, "", false},
				{"Joaat", -1, "", false},
				{"ELF-32", -1, "", false},
				{"XOR-32", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{6}$`, input)
			},
			mode: []HashInfo{
				{"CRC-24", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$`, input)
			},
			mode: []HashInfo{
				{"CRC-32", -1, "crc32", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\+[a-z0-9\/.]{12}$`, input)
			},
			mode: []HashInfo{
				{"Eggdrop IRC Bot", -1, "bfegg", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9\/.]{13}$`, input)
			},
			mode: []HashInfo{
				{"DES(Unix)", 1500, "descrypt", false},
				{"Traditional DES", 1500, "descrypt", false},
				{"DEScrypt", 1500, "descrypt", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{16}$`, input)
			},
			mode: []HashInfo{
				{"MySQL323", 200, "mysql", false},
				{"DES(Oracle)", 3100, "", false},
				{"Half MD5", 5100, "", false},
				{"Oracle 7-10g", 3100, "", false},
				{"FNV-164", -1, "", false},
				{"CRC-64", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9\/.]{16}$`, input)
			},
			mode: []HashInfo{
				{"Cisco-PIX(MD5)", 2400, "pix-md5", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\([a-z0-9\/+]{20}\)$`, input)
			},
			mode: []HashInfo{
				{"Lotus Notes/Domino 6", 8700, "dominosec", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^_[a-z0-9\/.]{19}$`, input)
			},
			mode: []HashInfo{
				{"BSDi Crypt", -1, "bsdicrypt", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{24}$`, input)
			},
			mode: []HashInfo{
				{"CRC-96(ZIP)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9\/.]{24}$`, input)
			},
			mode: []HashInfo{
				{"Crypt16", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$md2\$)?[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"MD2", -1, "md2", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{32}(:.+)?$`, input)
			},
			mode: []HashInfo{
				{"MD5", 0, "raw-md5", false},
				{"MD4", 900, "raw-md4", false},
				{"Double MD5", 2600, "", false},
				{"LM", 3000, "lm", false},
				{"RIPEMD-128", -1, "ripemd-128", false},
				{"Haval-128", -1, "haval-128-4", false},
				{"Tiger-128", -1, "", false},
				{"Skein-256(128)", -1, "", false},
				{"Skein-512(128)", -1, "", false},
				{"Lotus Notes/Domino 5", 8600, "lotus5", false},
				{"Skype", 23, "", false},
				{"ZipMonster", -1, "", true},
				{"PrestaShop", 11000, "", true},
				{"md5(md5(md5($pass)))", 3500, "", true},
				{"md5(strtoupper(md5($pass)))", 4300, "", true},
				{"md5(sha1($pass))", 4400, "", true},
				{"md5($pass.$salt)", 10, "", true},
				{"md5($salt.$pass)", 20, "", true},
				{"md5(unicode($pass).$salt)", 30, "", true},
				{"md5($salt.unicode($pass))", 40, "", true},
				{"HMAC-MD5 (key = $pass)", 50, "hmac-md5", true},
				{"HMAC-MD5 (key = $salt)", 60, "hmac-md5", true},
				{"md5(md5($salt).$pass)", 3610, "", true},
				{"md5($salt.md5($pass))", 3710, "", true},
				{"md5($pass.md5($salt))", 3720, "", true},
				{"md5($salt.$pass.$salt)", 3810, "", true},
				{"md5(md5($pass).md5($salt))", 3910, "", true},
				{"md5($salt.md5($salt.$pass))", 4010, "", true},
				{"md5($salt.md5($pass.$salt))", 4110, "", true},
				{"md5($username.0.$pass)", 4210, "", true},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{16}(:.+)?$`, input)
			},
			mode: []HashInfo{
				{"LM", 3000, "lm", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$snefru\$)?[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"Snefru-128", -1, "snefru-128", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$NT\$)?[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"NTLM", 1000, "nt", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$`, input)
			},
			mode: []HashInfo{
				{"Domain Cached Credentials", 1100, "mscach", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"Domain Cached Credentials 2", 2100, "mscach2", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^{SHA}[a-z0-9\/+]{27}=$`, input)
			},
			mode: []HashInfo{
				{"SHA-1(Base64)", 101, "nsldap", false},
				{"Netscape LDAP SHA", 101, "nsldap", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$`, input)
			},
			mode: []HashInfo{
				{"MD5 Crypt", 500, "md5crypt", false},
				{"Cisco-IOS(MD5)", 500, "md5crypt", false},
				{"FreeBSD MD5", 500, "md5crypt", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^0x[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"Lineage II C4", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$H\$[a-z0-9]{30}\.$`, input)
			},
			mode: []HashInfo{
				{"phpBB v3.x", 400, "phpass", false},
				{"Wordpress v2.6.0/2.6.1", 400, "phpass", false},
				{"PHPass' Portable Hash", 400, "phpass", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$P\$[a-z0-9]{30}\.$`, input)
			},
			mode: []HashInfo{
				{"Wordpress ≥ v2.6.2", 400, "phpass", false},
				{"Joomla ≥ v2.5.18", 400, "phpass", false},
				{"PHPass' Portable Hash", 400, "phpass", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{32}:[a-z0-9]{2}$`, input)
			},
			mode: []HashInfo{
				{"osCommerce", 21, "", false},
				{"xt:Commerce", 21, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$`, input)
			},
			mode: []HashInfo{
				{"MD5(APR)", 1600, "", false},
				{"Apache MD5", 1600, "", false},
				{"md5apr1", 1600, "", true},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^{smd5}[a-z0-9$\/.]{31}$`, input)
			},
			mode: []HashInfo{
				{"AIX(smd5)", 6300, "aix-smd5", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{32}:[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"WebEdition CMS", 3721, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{32}:.{5}$`, input)
			},
			mode: []HashInfo{
				{"IP.Board ≥ v2+", 2811, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{32}:.{8}$`, input)
			},
			mode: []HashInfo{
				{"MyBB ≥ v1.2+", 2811, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9]{34}$`, input)
			},
			mode: []HashInfo{
				{"CryptoCurrency(Adress)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{40}(:.+)?$`, input)
			},
			mode: []HashInfo{
				{"SHA-1", 100, "raw-sha1", false},
				{"Double SHA-1", 4500, "", false},
				{"RIPEMD-160", 6000, "ripemd-160", false},
				{"Haval-160", -1, "", false},
				{"Tiger-160", -1, "", false},
				{"HAS-160", -1, "", false},
				{"LinkedIn", 190, "raw-sha1-linkedin", false},
				{"Skein-256(160)", -1, "", false},
				{"Skein-512(160)", -1, "", false},
				{"MangosWeb Enhanced CMS", -1, "", true},
				{"sha1(sha1(sha1($pass)))", 4600, "", true},
				{"sha1(md5($pass))", 4700, "", true},
				{"sha1($pass.$salt)", 110, "", true},
				{"sha1($salt.$pass)", 120, "", true},
				{"sha1(unicode($pass).$salt)", 130, "", true},
				{"sha1($salt.unicode($pass))", 140, "", true},
				{"HMAC-SHA1 (key = $pass)", 150, "hmac-sha1", true},
				{"HMAC-SHA1 (key = $salt)", 160, "hmac-sha1", true},
				{"sha1($salt.$pass.$salt)", 4710, "", true},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"MySQL5.x", 300, "mysql-sha1", false},
				{"MySQL4.1", 300, "mysql-sha1", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9]{43}$`, input)
			},
			mode: []HashInfo{
				{"Cisco-IOS(SHA-256)", 5700, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^{SSHA}[a-z0-9\/+]{38}==$`, input)
			},
			mode: []HashInfo{
				{"SSHA-1(Base64)", 111, "nsldaps", false},
				{"Netscape LDAP SSHA", 111, "nsldaps", false},
				{"nsldaps", 111, "nsldaps", true},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9=]{47}$`, input)
			},
			mode: []HashInfo{
				{"Fortigate(FortiOS)", 7000, "fortigate", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{48}$`, input)
			},
			mode: []HashInfo{
				{"Haval-192", -1, "", false},
				{"Tiger-192", -1, "tiger", false},
				{"SHA-1(Oracle)", -1, "", false},
				{"OSX v10.4", 122, "xsha", false},
				{"OSX v10.5", 122, "xsha", false},
				{"OSX v10.6", 122, "xsha", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{51}$`, input)
			},
			mode: []HashInfo{
				{"Palshop CMS", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9]{51}$`, input)
			},
			mode: []HashInfo{
				{"CryptoCurrency(PrivateKey)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$`, input)
			},
			mode: []HashInfo{
				{"AIX(ssha1)", 6700, "aix-ssha1", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^0x0100[a-f0-9]{48}$`, input)
			},
			mode: []HashInfo{
				{"MSSQL(2005)", 132, "mssql05", false},
				{"MSSQL(2008)", 132, "mssql05", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$`, input)
			},
			mode: []HashInfo{
				{"Sun MD5 Crypt", 3300, "sunmd5", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{56}$`, input)
			},
			mode: []HashInfo{
				{"SHA-224", -1, "raw-sha224", false},
				{"Haval-224", -1, "", false},
				{"SHA3-224", -1, "", false},
				{"Skein-256(224)", -1, "", false},
				{"Skein-512(224)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$`, input)
			},
			mode: []HashInfo{
				{"Blowfish(OpenBSD)", 3200, "bcrypt", false},
				{"Woltlab Burning Board 4.x", -1, "", false},
				{"bcrypt", 3200, "bcrypt", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{40}:[a-f0-9]{16}$`, input)
			},
			mode: []HashInfo{
				{"Android PIN", 5800, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$`, input)
			},
			mode: []HashInfo{
				{"Oracle 11g/12c", 112, "oracle11", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$`, input)
			},
			mode: []HashInfo{
				{"bcrypt(SHA-256)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{32}:.{3}$`, input)
			},
			mode: []HashInfo{
				{"vBulletin < v3.8.5", 2611, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{32}:.{30}$`, input)
			},
			mode: []HashInfo{
				{"vBulletin ≥ v3.8.5", 2711, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$snefru\$)?[a-f0-9]{64}$`, input)
			},
			mode: []HashInfo{
				{"Snefru-256", -1, "snefru-256", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{64}(:.+)?$`, input)
			},
			mode: []HashInfo{
				{"SHA-256", 1400, "raw-sha256", false},
				{"RIPEMD-256", -1, "", false},
				{"Haval-256", -1, "haval-256-3", false},
				{"GOST R 34.11-94", 6900, "gost", false},
				{"GOST CryptoPro S-Box", -1, "", false},
				{"SHA3-256", 5000, "raw-keccak-256", false},
				{"Skein-256", -1, "skein-256", false},
				{"Skein-512(256)", -1, "", false},
				{"Ventrilo", -1, "", true},
				{"sha256($pass.$salt)", 1410, "", true},
				{"sha256($salt.$pass)", 1420, "", true},
				{"sha256(unicode($pass).$salt)", 1430, "", true},
				{"sha256($salt.unicode($pass))", 1440, "", true},
				{"HMAC-SHA256 (key = $pass)", 1450, "hmac-sha256", true},
				{"HMAC-SHA256 (key = $salt)", 1460, "hmac-sha256", true},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{32}:[a-z0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"Joomla < v2.5.18", 11, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f-0-9]{32}:[a-f-0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"SAM(LM_Hash:NT_Hash)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$`, input)
			},
			mode: []HashInfo{
				{"MD5(Chap)", 4800, "chap", false},
				{"iSCSI CHAP Authentication", 4800, "chap", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$`, input)
			},
			mode: []HashInfo{
				{"EPiServer 6.x < v4", 141, "episerver", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$`, input)
			},
			mode: []HashInfo{
				{"AIX(ssha256)", 6400, "aix-ssha256", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{80}$`, input)
			},
			mode: []HashInfo{
				{"RIPEMD-320", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$`, input)
			},
			mode: []HashInfo{
				{"EPiServer 6.x ≥ v4", 1441, "episerver", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^0x0100[a-f0-9]{88}$`, input)
			},
			mode: []HashInfo{
				{"MSSQL(2000)", 131, "mssql", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{96}$`, input)
			},
			mode: []HashInfo{
				{"SHA-384", 10800, "raw-sha384", false},
				{"SHA3-384", -1, "", false},
				{"Skein-512(384)", -1, "", false},
				{"Skein-1024(384)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^{SSHA512}[a-z0-9\/+]{96}$`, input)
			},
			mode: []HashInfo{
				{"SSHA-512(Base64)", 1711, "ssha512", false},
				{"LDAP(SSHA-512)", 1711, "ssha512", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$`, input)
			},
			mode: []HashInfo{
				{"AIX(ssha512)", 6500, "aix-ssha512", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{128}(:.+)?$`, input)
			},
			mode: []HashInfo{
				{"SHA-512", 1700, "raw-sha512", false},
				{"Whirlpool", 6100, "whirlpool", false},
				{"Salsa10", -1, "", false},
				{"Salsa20", -1, "", false},
				{"SHA3-512", -1, "raw-keccak", false},
				{"Skein-512", -1, "skein-512", false},
				{"Skein-1024(512)", -1, "", false},
				{"sha512($pass.$salt)", 1710, "", true},
				{"sha512($salt.$pass)", 1720, "", true},
				{"sha512(unicode($pass).$salt)", 1730, "", true},
				{"sha512($salt.unicode($pass))", 1740, "", true},
				{"HMAC-SHA512 (key = $pass)", 1750, "hmac-sha512", true},
				{"HMAC-SHA512 (key = $salt)", 1760, "hmac-sha512", true},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{136}$`, input)
			},
			mode: []HashInfo{
				{"OSX v10.7", 1722, "xsha512", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^0x0200[a-f0-9]{136}$`, input)
			},
			mode: []HashInfo{
				{"MSSQL(2012)", 1731, "msql12", false},
				{"MSSQL(2014)", 1731, "msql12", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$`, input)
			},
			mode: []HashInfo{
				{"OSX v10.8", 7100, "pbkdf2-hmac-sha512", false},
				{"OSX v10.9", 7100, "pbkdf2-hmac-sha512", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{256}$`, input)
			},
			mode: []HashInfo{
				{"Skein-1024", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				parts := strings.Split(input, ".")
				if len(parts) != 6 {
					return false
				}

				if parts[0] != "grub" || parts[1] != "pbkdf2" || parts[2] != "sha512" {
					return false
				}

				numPart := parts[3]
				if _, err := strconv.Atoi(numPart); err != nil {
					return false
				}

				saltPart := parts[4]
				if len(saltPart) != 128 && len(saltPart) != 2048 {
					return false
				}

				if !checkAlphaNumericLower(saltPart) {
					return false
				}

				hashPart := parts[5]
				if len(hashPart) != 128 {
					return false
				}

				if !checkAlphaNumericLower(hashPart) {
					return false
				}

				return true
			},
			mode: []HashInfo{
				{"GRUB 2", 7200, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^sha1\$[a-z0-9]+\$[a-f0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"Django(SHA-1)", 124, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{49}$`, input)
			},
			mode: []HashInfo{
				{"Citrix Netscaler", 8100, "citrix_ns10", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$S\$[a-z0-9\/.]{52}$`, input)
			},
			mode: []HashInfo{
				{"Drupal > v7.x", 7900, "drupal7", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$`, input)
			},
			mode: []HashInfo{
				{"SHA-256 Crypt", 7400, "sha256crypt", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$`, input)
			},
			mode: []HashInfo{
				{"Sybase ASE", 8000, "sybasease", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$`, input)
			},
			mode: []HashInfo{
				{"SHA-512 Crypt", 1800, "sha512crypt", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$`, input)
			},
			mode: []HashInfo{
				{"Minecraft(AuthMe Reloaded)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^sha256\$[a-z0-9]+\$[a-f0-9]{64}$`, input)
			},
			mode: []HashInfo{
				{"Django(SHA-256)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^sha384\$[a-z0-9]+\$[a-f0-9]{96}$`, input)
			},
			mode: []HashInfo{
				{"Django(SHA-384)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$`, input)
			},
			mode: []HashInfo{
				{"Clavister Secure Gateway", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{112}$`, input)
			},
			mode: []HashInfo{
				{"Cisco VPN Client(PCF-File)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				if len(input) != 1329 {
					return false
				}

				return checkAlphaNumericLower(input)
			},
			mode: []HashInfo{
				{"Microsoft MSTSC(RDP-File)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$`, input)
			},
			mode: []HashInfo{
				{"NetNTLMv1-VANILLA / NetNTLMv1+ESS", 5500, "netntlm", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$`, input)
			},
			mode: []HashInfo{
				{"NetNTLMv2", 5600, "netntlmv2", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$`, input)
			},
			mode: []HashInfo{
				{"Kerberos 5 AS-REQ Pre-Auth", 7500, "krb5pa-md5", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$`, input)
			},
			mode: []HashInfo{
				{"SCRAM Hash", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{40}:[a-f0-9]{0,32}$`, input)
			},
			mode: []HashInfo{
				{"Redmine Project Management Web App", 7600, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(.+)?\$[a-f0-9]{16}$`, input)
			},
			mode: []HashInfo{
				{"SAP CODVN B (BCODE)", 7700, "sapb", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(.+)?\$[a-f0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"SAP CODVN F/G (PASSCODE)", 7800, "sapg", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$`, input)
			},
			mode: []HashInfo{
				{"Juniper Netscreen/SSG(ScreenOS)", 22, "md5ns", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"EPi", 123, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{40}:[^*]{1,25}$`, input)
			},
			mode: []HashInfo{
				{"SMF ≥ v1.1", 121, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"Woltlab Burning Board 3.x", 8400, "wbb3", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{130}(:[a-f0-9]{40})?$`, input)
			},
			mode: []HashInfo{
				{"IPMI2 RAKP HMAC-SHA1", 7300, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$`, input)
			},
			mode: []HashInfo{
				{"Lastpass", 6800, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9\/.]{16}([:$].{1,})?$`, input)
			},
			mode: []HashInfo{
				{"Cisco-ASA(MD5)", 2410, "asa-md5", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"VNC", -1, "vnc", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$`, input)
			},
			mode: []HashInfo{
				{"DNSSEC(NSEC3)", 8300, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$`, input)
			},
			mode: []HashInfo{
				{"RACF", 8500, "racf", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$3\$\$[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"NTHash(FreeBSD Variant)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$`, input)
			},
			mode: []HashInfo{
				{"SHA-1 Crypt", -1, "sha1crypt", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{70}$`, input)
			},
			mode: []HashInfo{
				{"hMailServer", 1421, "hmailserver", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"MediaWiki", 3711, "mediawiki", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{140}$`, input)
			},
			mode: []HashInfo{
				{"Minecraft(xAuth)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$`, input)
			},
			mode: []HashInfo{
				{"PBKDF2-SHA1(Generic)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$`, input)
			},
			mode: []HashInfo{
				{"PBKDF2-SHA256(Generic)", -1, "pbkdf2-hmac-sha256", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$`, input)
			},
			mode: []HashInfo{
				{"PBKDF2-SHA512(Generic)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$`, input)
			},
			mode: []HashInfo{
				{"PBKDF2(Cryptacular)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$`, input)
			},
			mode: []HashInfo{
				{"PBKDF2(Dwayne Litzenberger)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$`, input)
			},
			mode: []HashInfo{
				{"Fairly Secure Hashed Password", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$PHPS\$.+\$[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"PHPS", 2612, "phps", false},
			},
		},
		// {
		// 	match: func(input string) bool {
		// regex :=regexp.MustCompile(`^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$`)
		// return regex.MatchString(input)
		// },
		// 	mode: []HashInfo{
		// 		{"1Password(Agile Keychain)", 6600, "", false},
		// 	},
		// },
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$`, input)
			},
			mode: []HashInfo{
				{"1Password(Cloud Keychain)", 8200, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"IKE-PSK MD5", 5300, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"IKE-PSK SHA1", 5400, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9\/+]{27}=$`, input)
			},
			mode: []HashInfo{
				{"PeopleSoft", 133, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$`, input)
			},
			mode: []HashInfo{
				{"Django(DES Crypt Wrapper)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$`, input)
			},
			mode: []HashInfo{
				{"Django(PBKDF2-HMAC-SHA256)", 10000, "django", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$`, input)
			},
			mode: []HashInfo{
				{"Django(PBKDF2-HMAC-SHA1)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$`, input)
			},
			mode: []HashInfo{
				{"Django(bcrypt)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^md5\$[a-f0-9]+\$[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"Django(MD5)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\{PKCS5S2\}[a-z0-9\/+]{64}$`, input)
			},
			mode: []HashInfo{
				{"PBKDF2(Atlassian)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^md5[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"PostgreSQL MD5", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\([a-z0-9\/+]{49}\)$`, input)
			},
			mode: []HashInfo{
				{"Lotus Notes/Domino 8", 9100, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$`, input)
			},
			mode: []HashInfo{
				{"scrypt", 8900, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$`, input)
			},
			mode: []HashInfo{
				{"Cisco Type 8", 9200, "cisco8", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$`, input)
			},
			mode: []HashInfo{
				{"Cisco Type 9", 9300, "cisco9", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"Microsoft Office 2007", 9400, "office", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$`, input)
			},
			mode: []HashInfo{
				{"Microsoft Office 2010", 9500, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$`, input)
			},
			mode: []HashInfo{
				{"Microsoft Office 2013", 9600, "", false},
			},
		},
		// {
		// 	match: func(input string) bool {
		// regex :=regexp.MustCompile(`^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$`)
		// return regex.MatchString(input)
		// },
		// 	mode: []HashInfo{
		// 		{"Android FDE ≤ 4.3", 8800, "fde", false},
		// 	},
		// },
		{
			match: func(input string) bool {
				return checkRegex(`^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"Microsoft Office ≤ 2003 (MD5+RC4)", 9700, "oldoffice", false},
				{"Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1", 9710, "oldoffice", false},
				{"Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #2", 9720, "oldoffice", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"Microsoft Office ≤ 2003 (SHA1+RC4)", 9800, "", false},
				{"Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1", 9810, "", false},
				{"Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #2", 9820, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$radmin2\$)?[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"RAdmin v2.x", 9900, "radmin", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$`, input)
			},
			mode: []HashInfo{
				{"SAP CODVN H (PWDSALTEDHASH) iSSHA-1", 10300, "saph", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$`, input)
			},
			mode: []HashInfo{
				{"CRAM-MD5", 10200, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{16}:2:4:[a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"SipHash", 10100, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-f0-9]{4,}$`, input)
			},
			mode: []HashInfo{
				{"Cisco Type 7", -1, "", true},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^[a-z0-9\/.]{13,}$`, input)
			},
			mode: []HashInfo{
				{"BigCrypt", -1, "bigcrypt", true},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$cisco4\$)?[a-z0-9\/.]{43}$`, input)
			},
			mode: []HashInfo{
				{"Cisco Type 4", -1, "cisco4", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$`, input)
			},
			mode: []HashInfo{
				{"Django(bcrypt-SHA256)", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$`, input)
			},
			mode: []HashInfo{
				{"PostgreSQL Challenge-Response Authentication (MD5)", 11100, "postgres", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"Siemens-S7", -1, "siemens-s7", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$pst\$)?[a-f0-9]{8}$`, input)
			},
			mode: []HashInfo{
				{"Microsoft Outlook PST", -1, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}$`, input)
			},
			mode: []HashInfo{
				{"PBKDF2-HMAC-SHA256(PHP)", 10900, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^(\$dahua\$)?[a-z0-9]{8}$`, input)
			},
			mode: []HashInfo{
				{"Dahua", -1, "dahua", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$`, input)
			},
			mode: []HashInfo{
				{"MySQL Challenge-Response Authentication (SHA1)", 11200, "", false},
			},
		},
		{
			match: func(input string) bool {
				return checkRegex(`^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$`, input)
			},
			mode: []HashInfo{
				{"PDF 1.4 - 1.6 (Acrobat 5 - 8)", 10500, "pdf", false},
			},
		},
	}
)
