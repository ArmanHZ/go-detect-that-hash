package gdth_test

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

func TestMD5(t *testing.T) {
	if hashes := gdth.Detect("8743b52063cd84097a65d1633f5c74f5"); !checkIncludedHashID(hashes, 0) {
		t.Errorf("Expected MD5, got %v", hashes)
	}
}

func TestMD5__PASS__SALT_(t *testing.T) {
	if hashes := gdth.Detect("01dfae6e5d4d90d9892622325959afbe:7050461"); !checkIncludedHashID(hashes, 10) {
		t.Errorf("Expected MD5($PASS.$SALT), got %v", hashes)
	}
}

func TestMD5__SALT__PASS_(t *testing.T) {
	if hashes := gdth.Detect("f0fda58630310a6dd91a7d8f0a4ceda2:4225637426"); !checkIncludedHashID(hashes, 20) {
		t.Errorf("Expected MD5($SALT.$PASS), got %v", hashes)
	}
}

func TestMD5_UTF16LE__PASS___SALT_(t *testing.T) {
	if hashes := gdth.Detect("b31d032cfdcf47a399990a71e43c5d2a:144816"); !checkIncludedHashID(hashes, 30) {
		t.Errorf("Expected MD5(UTF16LE($PASS).$SALT), got %v", hashes)
	}
}

func TestMD5__SALT_UTF16LE__PASS__(t *testing.T) {
	if hashes := gdth.Detect("d63d0e21fdc05f618d55ef306c54af82:13288442151473"); !checkIncludedHashID(hashes, 40) {
		t.Errorf("Expected MD5($SALT.UTF16LE($PASS)), got %v", hashes)
	}
}

func TestHMAC_MD5__KEY____PASS_(t *testing.T) {
	if hashes := gdth.Detect("fc741db0a2968c39d9c2a5cc75b05370:1234"); !checkIncludedHashID(hashes, 50) {
		t.Errorf("Expected HMAC-MD5 (KEY = $PASS), got %v", hashes)
	}
}

func TestHMAC_MD5__KEY____SALT_(t *testing.T) {
	if hashes := gdth.Detect("bfd280436f45fa38eaacac3b00518f29:1234"); !checkIncludedHashID(hashes, 60) {
		t.Errorf("Expected HMAC-MD5 (KEY = $SALT), got %v", hashes)
	}
}

func TestSHA1(t *testing.T) {
	if hashes := gdth.Detect("b89eaac7e61417341b710b727768294d0e6a277b"); !checkIncludedHashID(hashes, 100) {
		t.Errorf("Expected SHA1, got %v", hashes)
	}
}

func TestSHA1__PASS__SALT_(t *testing.T) {
	if hashes := gdth.Detect("2fc5a684737ce1bf7b3b239df432416e0dd07357:2014"); !checkIncludedHashID(hashes, 110) {
		t.Errorf("Expected SHA1($PASS.$SALT), got %v", hashes)
	}
}

func TestSHA1__SALT__PASS_(t *testing.T) {
	if hashes := gdth.Detect("cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024"); !checkIncludedHashID(hashes, 120) {
		t.Errorf("Expected SHA1($SALT.$PASS), got %v", hashes)
	}
}

func TestSHA1_UTF16LE__PASS___SALT_(t *testing.T) {
	if hashes := gdth.Detect("c57f6ac1b71f45a07dbd91a59fa47c23abcd87c2:631225"); !checkIncludedHashID(hashes, 130) {
		t.Errorf("Expected SHA1(UTF16LE($PASS).$SALT), got %v", hashes)
	}
}

func TestSHA1__SALT_UTF16LE__PASS__(t *testing.T) {
	if hashes := gdth.Detect("5db61e4cd8776c7969cfd62456da639a4c87683a:8763434884872"); !checkIncludedHashID(hashes, 140) {
		t.Errorf("Expected SHA1($SALT.UTF16LE($PASS)), got %v", hashes)
	}
}

func TestHMAC_SHA1__KEY____PASS_(t *testing.T) {
	if hashes := gdth.Detect("c898896f3f70f61bc3fb19bef222aa860e5ea717:1234"); !checkIncludedHashID(hashes, 150) {
		t.Errorf("Expected HMAC-SHA1 (KEY = $PASS), got %v", hashes)
	}
}

func TestHMAC_SHA1__KEY____SALT_(t *testing.T) {
	if hashes := gdth.Detect("d89c92b4400b15c39e462a8caa939ab40c3aeeea:1234"); !checkIncludedHashID(hashes, 160) {
		t.Errorf("Expected HMAC-SHA1 (KEY = $SALT), got %v", hashes)
	}
}

func TestMYSQL323(t *testing.T) {
	if hashes := gdth.Detect("7196759210defdc0"); !checkIncludedHashID(hashes, 200) {
		t.Errorf("Expected MYSQL323, got %v", hashes)
	}
}

func TestMYSQL4_1_MYSQL5(t *testing.T) {
	if hashes := gdth.Detect("fcf7c1b8749cf99d88e5f34271d636178fb5d130"); !checkIncludedHashID(hashes, 300) {
		t.Errorf("Expected MYSQL4.1/MYSQL5, got %v", hashes)
	}
}

func TestPHPASS__WORDPRESS__MD5__JOOMLA__MD5_(t *testing.T) {
	if hashes := gdth.Detect("$P$984478476IagS59wHZvyQMArzfx58u."); !checkIncludedHashID(hashes, 400) {
		t.Errorf("Expected PHPASS, WORDPRESS (MD5),JOOMLA (MD5), got %v", hashes)
	}
}

func TestPHPASS__PHPBB3__MD5_(t *testing.T) {
	if hashes := gdth.Detect("$H$984478476IagS59wHZvyQMArzfx58u."); !checkIncludedHashID(hashes, 400) {
		t.Errorf("Expected PHPASS, PHPBB3 (MD5), got %v", hashes)
	}
}

func TestMD5CRYPT__MD5__UNIX___CISCO_IOS__1___MD5__2(t *testing.T) {
	if hashes := gdth.Detect("$1$28772684$iEwNOgGugqO9.bIz5sk8k/"); !checkIncludedHashID(hashes, 500) {
		t.Errorf("Expected MD5CRYPT, MD5 (UNIX), CISCO-IOS $1$ (MD5) 2, got %v", hashes)
	}
}

func TestMD4(t *testing.T) {
	if hashes := gdth.Detect("afe04867ec7a3845145579a95f72eca7"); !checkIncludedHashID(hashes, 900) {
		t.Errorf("Expected MD4, got %v", hashes)
	}
}

func TestNTLM(t *testing.T) {
	if hashes := gdth.Detect("b4b9b02e6f09a9bd760f388b67351e2b"); !checkIncludedHashID(hashes, 1000) {
		t.Errorf("Expected NTLM, got %v", hashes)
	}
}

func TestDOMAIN_CACHED_CREDENTIALS__DCC___MS_CACHE(t *testing.T) {
	if hashes := gdth.Detect("4dd8965d1d476fa0d026722989a6b772:3060147285011"); !checkIncludedHashID(hashes, 1100) {
		t.Errorf("Expected DOMAIN CACHED CREDENTIALS (DCC), MS CACHE, got %v", hashes)
	}
}

func TestSHA2_256(t *testing.T) {
	if hashes := gdth.Detect("127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"); !checkIncludedHashID(hashes, 1400) {
		t.Errorf("Expected SHA2-256, got %v", hashes)
	}
}

func TestSHA256__PASS__SALT_(t *testing.T) {
	if hashes := gdth.Detect("c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528"); !checkIncludedHashID(hashes, 1410) {
		t.Errorf("Expected SHA256($PASS.$SALT), got %v", hashes)
	}
}

func TestSHA256__SALT__PASS_(t *testing.T) {
	if hashes := gdth.Detect("eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617"); !checkIncludedHashID(hashes, 1420) {
		t.Errorf("Expected SHA256($SALT.$PASS), got %v", hashes)
	}
}

func TestSHA256_UTF16LE__PASS___SALT_(t *testing.T) {
	if hashes := gdth.Detect("4cc8eb60476c33edac52b5a7548c2c50ef0f9e31ce656c6f4b213f901bc87421:890128"); !checkIncludedHashID(hashes, 1430) {
		t.Errorf("Expected SHA256(UTF16LE($PASS).$SALT), got %v", hashes)
	}
}

func TestSHA256__SALT_UTF16LE__PASS__(t *testing.T) {
	if hashes := gdth.Detect("a4bd99e1e0aba51814e81388badb23ecc560312c4324b2018ea76393ea1caca9:12345678"); !checkIncludedHashID(hashes, 1440) {
		t.Errorf("Expected SHA256($SALT.UTF16LE($PASS)), got %v", hashes)
	}
}

func TestHMAC_SHA256__KEY____PASS_(t *testing.T) {
	if hashes := gdth.Detect("abaf88d66bf2334a4a8b207cc61a96fb46c3e38e882e6f6f886742f688b8588c:1234"); !checkIncludedHashID(hashes, 1450) {
		t.Errorf("Expected HMAC-SHA256 (KEY = $PASS), got %v", hashes)
	}
}

func TestHMAC_SHA256__KEY____SALT_(t *testing.T) {
	if hashes := gdth.Detect("8efbef4cec28f228fa948daaf4893ac3638fbae81358ff9020be1d7a9a509fc6:1234"); !checkIncludedHashID(hashes, 1460) {
		t.Errorf("Expected HMAC-SHA256 (KEY = $SALT), got %v", hashes)
	}
}

func TestDESCRYPT__DES__UNIX___TRADITIONAL_DES(t *testing.T) {
	if hashes := gdth.Detect("48c/R8JAv757A"); !checkIncludedHashID(hashes, 1500) {
		t.Errorf("Expected DESCRYPT, DES (UNIX), TRADITIONAL DES, got %v", hashes)
	}
}

func TestAPACHE__APR1__MD5__MD5APR1__MD5__APR__2(t *testing.T) {
	if hashes := gdth.Detect("$apr1$71850310$gh9m4xcAn3MGxogwX/ztb."); !checkIncludedHashID(hashes, 1600) {
		t.Errorf("Expected APACHE $APR1$ MD5, MD5APR1, MD5 (APR) 2, got %v", hashes)
	}
}

func TestSHA2_512(t *testing.T) {
	if hashes := gdth.Detect("82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"); !checkIncludedHashID(hashes, 1700) {
		t.Errorf("Expected SHA2-512, got %v", hashes)
	}
}

func TestSHA512__PASS__SALT_(t *testing.T) {
	if hashes := gdth.Detect("e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd:6352283260"); !checkIncludedHashID(hashes, 1710) {
		t.Errorf("Expected SHA512($PASS.$SALT), got %v", hashes)
	}
}

func TestSHA512__SALT__PASS_(t *testing.T) {
	if hashes := gdth.Detect("976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127"); !checkIncludedHashID(hashes, 1720) {
		t.Errorf("Expected SHA512($SALT.$PASS), got %v", hashes)
	}
}

func TestSHA512_UTF16LE__PASS___SALT_(t *testing.T) {
	if hashes := gdth.Detect("13070359002b6fbb3d28e50fba55efcf3d7cc115fe6e3f6c98bf0e3210f1c6923427a1e1a3b214c1de92c467683f6466727ba3a51684022be5cc2ffcb78457d2:341351589"); !checkIncludedHashID(hashes, 1730) {
		t.Errorf("Expected SHA512(UTF16LE($PASS).$SALT), got %v", hashes)
	}
}

func TestSHA512__SALT_UTF16LE__PASS__(t *testing.T) {
	if hashes := gdth.Detect("bae3a3358b3459c761a3ed40d34022f0609a02d90a0d7274610b16147e58ece00cd849a0bd5cf6a92ee5eb5687075b4e754324dfa70deca6993a85b2ca865bc8:1237015423"); !checkIncludedHashID(hashes, 1740) {
		t.Errorf("Expected SHA512($SALT.UTF16LE($PASS)), got %v", hashes)
	}
}

func TestHMAC_SHA512__KEY____PASS_(t *testing.T) {
	if hashes := gdth.Detect("94cb9e31137913665dbea7b058e10be5f050cc356062a2c9679ed0ad6119648e7be620e9d4e1199220cd02b9efb2b1c78234fa1000c728f82bf9f14ed82c1976:1234"); !checkIncludedHashID(hashes, 1750) {
		t.Errorf("Expected HMAC-SHA512 (KEY = $PASS), got %v", hashes)
	}
}

func TestHMAC_SHA512__KEY____SALT_(t *testing.T) {
	if hashes := gdth.Detect("7cce966f5503e292a51381f238d071971ad5442488f340f98e379b3aeae2f33778e3e732fcc2f7bdc04f3d460eebf6f8cb77da32df25500c09160dd3bf7d2a6b:1234"); !checkIncludedHashID(hashes, 1760) {
		t.Errorf("Expected HMAC-SHA512 (KEY = $SALT), got %v", hashes)
	}
}

func TestSHA512CRYPT__6___SHA512__UNIX__2(t *testing.T) {
	if hashes := gdth.Detect("$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/"); !checkIncludedHashID(hashes, 1800) {
		t.Errorf("Expected SHA512CRYPT $6$, SHA512 (UNIX) 2, got %v", hashes)
	}
}

func TestDOMAIN_CACHED_CREDENTIALS_2__DCC2___MS_CACHE_2(t *testing.T) {
	if hashes := gdth.Detect("$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f"); !checkIncludedHashID(hashes, 2100) {
		t.Errorf("Expected DOMAIN CACHED CREDENTIALS 2 (DCC2), MS CACHE 2, got %v", hashes)
	}
}

func TestCISCO_PIX_MD5(t *testing.T) {
	if hashes := gdth.Detect("dRRVnUmUHXOTt9nk"); !checkIncludedHashID(hashes, 2400) {
		t.Errorf("Expected CISCO-PIX MD5, got %v", hashes)
	}
}

func TestCISCO_ASA_MD5(t *testing.T) {
	if hashes := gdth.Detect("02dMBMYkTdC5Ziyp:36"); !checkIncludedHashID(hashes, 2410) {
		t.Errorf("Expected CISCO-ASA MD5, got %v", hashes)
	}
}

func TestMD5_MD5__PASS__(t *testing.T) {
	if hashes := gdth.Detect("a936af92b0ae20b1ff6c3347a72e5fbe"); !checkIncludedHashID(hashes, 2600) {
		t.Errorf("Expected MD5(MD5($PASS)), got %v", hashes)
	}
}

func TestLM(t *testing.T) {
	if hashes := gdth.Detect("299bd128c1101fd6"); !checkIncludedHashID(hashes, 3000) {
		t.Errorf("Expected LM, got %v", hashes)
	}
}

func TestORACLE_H__TYPE__ORACLE_7__(t *testing.T) {
	if hashes := gdth.Detect("7A963A529D2E3229:3682427524"); !checkIncludedHashID(hashes, 3100) {
		t.Errorf("Expected ORACLE H: TYPE (ORACLE 7+), got %v", hashes)
	}
}

func TestBCRYPT__2____BLOWFISH__UNIX_(t *testing.T) {
	if hashes := gdth.Detect("$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"); !checkIncludedHashID(hashes, 3200) {
		t.Errorf("Expected BCRYPT $2*$, BLOWFISH (UNIX), got %v", hashes)
	}
}

func TestMD5_MD5_MD5__PASS___(t *testing.T) {
	if hashes := gdth.Detect("9882d0778518b095917eb589f6998441"); !checkIncludedHashID(hashes, 3500) {
		t.Errorf("Expected MD5(MD5(MD5($PASS))), got %v", hashes)
	}
}

func TestMD5__SALT_MD5__PASS__(t *testing.T) {
	if hashes := gdth.Detect("95248989ec91f6d0439dbde2bd0140be:1234"); !checkIncludedHashID(hashes, 3710) {
		t.Errorf("Expected MD5($SALT.MD5($PASS)), got %v", hashes)
	}
}

func TestMD5_MD5__PASS__MD5__SALT__(t *testing.T) {
	if hashes := gdth.Detect("250920b3a5e31318806a032a4674df7e:1234"); !checkIncludedHashID(hashes, 3910) {
		t.Errorf("Expected MD5(MD5($PASS).MD5($SALT)), got %v", hashes)
	}
}

func TestMD5__SALT_MD5__SALT__PASS__(t *testing.T) {
	if hashes := gdth.Detect("30d0cf4a5d7ed831084c5b8b0ba75b46:1234"); !checkIncludedHashID(hashes, 4010) {
		t.Errorf("Expected MD5($SALT.MD5($SALT.$PASS)), got %v", hashes)
	}
}

func TestMD5__SALT_MD5__PASS__SALT__(t *testing.T) {
	if hashes := gdth.Detect("b4cb5c551a30f6c25d648560408df68a:1234"); !checkIncludedHashID(hashes, 4110) {
		t.Errorf("Expected MD5($SALT.MD5($PASS.$SALT)), got %v", hashes)
	}
}

func TestMD5_STRTOUPPER_MD5__PASS___(t *testing.T) {
	if hashes := gdth.Detect("b8c385461bb9f9d733d3af832cf60b27"); !checkIncludedHashID(hashes, 4300) {
		t.Errorf("Expected MD5(STRTOUPPER(MD5($PASS))), got %v", hashes)
	}
}

func TestMD5_SHA1__PASS__(t *testing.T) {
	if hashes := gdth.Detect("288496df99b33f8f75a7ce4837d1b480"); !checkIncludedHashID(hashes, 4400) {
		t.Errorf("Expected MD5(SHA1($PASS)), got %v", hashes)
	}
}

func TestSHA1_SHA1__PASS__(t *testing.T) {
	if hashes := gdth.Detect("3db9184f5da4e463832b086211af8d2314919951"); !checkIncludedHashID(hashes, 4500) {
		t.Errorf("Expected SHA1(SHA1($PASS)), got %v", hashes)
	}
}

func TestSHA1_MD5__PASS__(t *testing.T) {
	if hashes := gdth.Detect("92d85978d884eb1d99a51652b1139c8279fa8663"); !checkIncludedHashID(hashes, 4700) {
		t.Errorf("Expected SHA1(MD5($PASS)), got %v", hashes)
	}
}

func TestSHA1_MD5__PASS___SALT_(t *testing.T) {
	if hashes := gdth.Detect("53c724b7f34f09787ed3f1b316215fc35c789504:hashcat1"); !checkIncludedHashID(hashes, 4710) {
		t.Errorf("Expected SHA1(MD5($PASS).$SALT), got %v", hashes)
	}
}

func TestISCSI_CHAP_AUTHENTICATION__MD5_CHAP__7(t *testing.T) {
	if hashes := gdth.Detect("afd09efdd6f8ca9f18ec77c5869788c3:01020304050607080910111213141516:01"); !checkIncludedHashID(hashes, 4800) {
		t.Errorf("Expected ISCSI CHAP AUTHENTICATION, MD5(CHAP) 7, got %v", hashes)
	}
}

func TestSHA1_SHA1__SALT__PASS__SALT__(t *testing.T) {
	if hashes := gdth.Detect("05ac0c544060af48f993f9c3cdf2fc03937ea35b:232725102020"); !checkIncludedHashID(hashes, 5000) {
		t.Errorf("Expected SHA1(SHA1($SALT.$PASS.$SALT)), got %v", hashes)
	}
}

func TestHALF_MD5(t *testing.T) {
	if hashes := gdth.Detect("8743b52063cd8409"); !checkIncludedHashID(hashes, 5100) {
		t.Errorf("Expected HALF MD5, got %v", hashes)
	}
}

func TestIKE_PSK_MD5(t *testing.T) {
	if hashes := gdth.Detect("e957a6a0f53ce06a56e4d82e96bc925ffa3cf7b79f6500b667edad5a1d7bad4619efa734f75cca9c4222fbb169f71d4240aced349eb7126f35cf94772b4af373ddf9b3f1ab3a9ff8cd2705417dca7e36dd9026bd0d472459cea7ad245ce57e4bf7d36efdea2a782978c6161eae98f01eac1ee05578f8e524a0d7748c5a1ec2de:647c051436ee84b39a514fd5f2da24fd3bdbb245ef3ed05cb362c58916bbb2cb93a93e3ec33da27404b82125cfd354c0114a3d10dfca26fab139f91046f2ad996f6091ac7a729305272696ac1769991b81a30826e24cee586f3f383b5e035820e17d9715db433ac75f204f20153a12cf7ee4fa7d11b2823e424c26cb513eb26b:fb3678377967e4db:708993a01df48348:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:01110000c0a83965:19004c6aa04dba354599f0d6afbc866970d751e4:6074841c25c83a0c1abfa348fee2d133399595f2:19a3428d90eb5045363a58dc33f51941"); !checkIncludedHashID(hashes, 5300) {
		t.Errorf("Expected IKE-PSK MD5, got %v", hashes)
	}
}

func TestIKE_PSK_SHA1(t *testing.T) {
	if hashes := gdth.Detect("7a1115b74a1b9d63de62627bdd029aa7a50df83ddbaba88c47d3e51833d21984fb463a2604ba0c82611a11edee7406e1826b2c70410d2797487d1220a4f716d7532fcd73e82b2fd6304f9af5dd1bc0a5dc1eb58bee978f95ffc8b6dc4401d4d2720978f4b0e69ae4dd96e61a1f23a347123aa242f893b33ac74fa234366dc56c:7e599b0168b56608f8a512b68bc7ea47726072ca8e66ecb8792a607f926afc2c3584850773d91644a3186da80414c5c336e07d95b891736f1e88eb05662bf17659781036fa03b869cb554d04689b53b401034e5ea061112066a89dcf8cbe3946e497feb8c5476152c2f8bc0bef4c2a05da51344370682ffb17ec664f8bc07855:419011bd5632fe07:169168a1ac421e4d:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:01110000c0a83965:ee4e517ba0f721798209d04dfcaf965758c4857e:48aada032ae2523815f4ec86758144fa98ad533c:e65f040dad4a628df43f3d1253f821110797a106"); !checkIncludedHashID(hashes, 5400) {
		t.Errorf("Expected IKE-PSK SHA1, got %v", hashes)
	}
}

func TestNETNTLMV1___NETNTLMV1_ESS(t *testing.T) {
	if hashes := gdth.Detect("u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c"); !checkIncludedHashID(hashes, 5500) {
		t.Errorf("Expected NETNTLMV1 / NETNTLMV1+ESS, got %v", hashes)
	}
}

func TestNETNTLMV2(t *testing.T) {
	if hashes := gdth.Detect("admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030"); !checkIncludedHashID(hashes, 5600) {
		t.Errorf("Expected NETNTLMV2, got %v", hashes)
	}
}

func TestCISCO_IOS_TYPE_4__SHA256_(t *testing.T) {
	if hashes := gdth.Detect("2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI"); !checkIncludedHashID(hashes, 5700) {
		t.Errorf("Expected CISCO-IOS TYPE 4 (SHA256), got %v", hashes)
	}
}

func TestSAMSUNG_ANDROID_PASSWORD_PIN(t *testing.T) {
	if hashes := gdth.Detect("0223b799d526b596fe4ba5628b9e65068227e68e:f6d45822728ddb2c"); !checkIncludedHashID(hashes, 5800) {
		t.Errorf("Expected SAMSUNG ANDROID PASSWORD/PIN, got %v", hashes)
	}
}

func TestRIPEMD_160(t *testing.T) {
	if hashes := gdth.Detect("012cb9b334ec1aeb71a9c8ce85586082467f7eb6"); !checkIncludedHashID(hashes, 6000) {
		t.Errorf("Expected RIPEMD-160, got %v", hashes)
	}
}

func TestWHIRLPOOL(t *testing.T) {
	if hashes := gdth.Detect("7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258"); !checkIncludedHashID(hashes, 6100) {
		t.Errorf("Expected WHIRLPOOL, got %v", hashes)
	}
}

func TestAIX__SMD5_(t *testing.T) {
	if hashes := gdth.Detect("{smd5}a5/yTL/u$VfvgyHx1xUlXZYBocQpQY0"); !checkIncludedHashID(hashes, 6300) {
		t.Errorf("Expected AIX {SMD5}, got %v", hashes)
	}
}

func TestAIX__SSHA256_(t *testing.T) {
	if hashes := gdth.Detect("{ssha256}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX.nZZLEz.g2"); !checkIncludedHashID(hashes, 6400) {
		t.Errorf("Expected AIX {SSHA256}, got %v", hashes)
	}
}

func TestAIX__SSHA512_(t *testing.T) {
	if hashes := gdth.Detect("{ssha512}06$bJbkFGJAB30L2e23$bXiXjyH5YGIyoWWmEVwq67nCU5t7GLy9HkCzrodRCQCx3r9VvG98o7O3V0r9cVrX3LPPGuHqT5LLn0oGCuI1.."); !checkIncludedHashID(hashes, 6500) {
		t.Errorf("Expected AIX {SSHA512}, got %v", hashes)
	}
}

func TestAIX__SSHA1_(t *testing.T) {
	if hashes := gdth.Detect("{ssha1}06$bJbkFGJAB30L2e23$dCESGOsP7jaIIAJ1QAcmaGeG.kr"); !checkIncludedHashID(hashes, 6700) {
		t.Errorf("Expected AIX {SSHA1}, got %v", hashes)
	}
}

func TestLASTPASS___LASTPASS_SNIFFED4(t *testing.T) {
	if hashes := gdth.Detect("a2d1f7b7a1862d0d4a52644e72d59df5:500:lp@trash-mail.com"); !checkIncludedHashID(hashes, 6800) {
		t.Errorf("Expected LASTPASS + LASTPASS SNIFFED4, got %v", hashes)
	}
}

func TestGOST_R_34_11_94(t *testing.T) {
	if hashes := gdth.Detect("df226c2c6dcb1d995c0299a33a084b201544293c31fc3d279530121d36bbcea9"); !checkIncludedHashID(hashes, 6900) {
		t.Errorf("Expected GOST R 34.11-94, got %v", hashes)
	}
}

func TestFORTIGATE__FORTIOS_(t *testing.T) {
	if hashes := gdth.Detect("AK1AAECAwQFBgcICRARNGqgeC3is8gv2xWWRony9NJnDgE="); !checkIncludedHashID(hashes, 7000) {
		t.Errorf("Expected FORTIGATE (FORTIOS), got %v", hashes)
	}
}

func TestGRUB_2(t *testing.T) {
	if hashes := gdth.Detect("grub.pbkdf2.sha512.10000.7d391ef48645f626b427b1fae06a7219b5b54f4f02b2621f86b5e36e83ae492bd1db60871e45bc07925cecb46ff8ba3db31c723c0c6acbd4f06f60c5b246ecbf.26d59c52b50df90d043f070bd9cbcd92a74424da42b3666fdeb08f1a54b8f1d2f4f56cf436f9382419c26798dc2c209a86003982b1e5a9fcef905f4dfaa4c524"); !checkIncludedHashID(hashes, 7200) {
		t.Errorf("Expected GRUB 2, got %v", hashes)
	}
}

func TestIPMI2_RAKP_HMAC_SHA1(t *testing.T) {
	if hashes := gdth.Detect("b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174:472bdabe2d5d4bffd6add7b3ba79a291d104a9ef"); !checkIncludedHashID(hashes, 7300) {
		t.Errorf("Expected IPMI2 RAKP HMAC-SHA1, got %v", hashes)
	}
}

func TestSHA256CRYPT__5___SHA256__UNIX__2(t *testing.T) {
	if hashes := gdth.Detect("$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD"); !checkIncludedHashID(hashes, 7400) {
		t.Errorf("Expected SHA256CRYPT $5$, SHA256 (UNIX) 2, got %v", hashes)
	}
}

func TestKERBEROS_5__ETYPE_23__AS_REQ_PRE_AUTH(t *testing.T) {
	if hashes := gdth.Detect("$krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835"); !checkIncludedHashID(hashes, 7500) {
		t.Errorf("Expected KERBEROS 5, ETYPE 23, AS-REQ PRE-AUTH, got %v", hashes)
	}
}

func TestSAP_CODVN_B__BCODE_(t *testing.T) {
	if hashes := gdth.Detect("USER$C8B48F26B87B7EA7"); !checkIncludedHashID(hashes, 7700) {
		t.Errorf("Expected SAP CODVN B (BCODE), got %v", hashes)
	}
}

func TestSAP_CODVN_F_G__PASSCODE_(t *testing.T) {
	if hashes := gdth.Detect("USER$ABCAD719B17E7F794DF7E686E563E9E2D24DE1D0"); !checkIncludedHashID(hashes, 7800) {
		t.Errorf("Expected SAP CODVN F/G (PASSCODE), got %v", hashes)
	}
}

func TestDRUPAL7(t *testing.T) {
	if hashes := gdth.Detect("$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf"); !checkIncludedHashID(hashes, 7900) {
		t.Errorf("Expected DRUPAL7, got %v", hashes)
	}
}

func TestSYBASE_ASE(t *testing.T) {
	if hashes := gdth.Detect("0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2"); !checkIncludedHashID(hashes, 8000) {
		t.Errorf("Expected SYBASE ASE, got %v", hashes)
	}
}

func TestCITRIX_NETSCALER__SHA1_(t *testing.T) {
	if hashes := gdth.Detect("1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea"); !checkIncludedHashID(hashes, 8100) {
		t.Errorf("Expected CITRIX NETSCALER (SHA1), got %v", hashes)
	}
}

func Test1PASSWORD__CLOUDKEYCHAIN(t *testing.T) {
	if hashes := gdth.Detect("92407e964bb9a368e86bcd52273e3f6b86181ab1204a9ed709bbe97667e7f67c:c1b981dd8e36340daf420badbfe38ca9:40000:991a0942a91889409a70b6622caf779a00ba472617477883394141bd6e23e38d8e2f5a69f5b30aa9dc28ebf6ecedcb679224e29af1123889a947576806536b831cc1d159a6d9135194671719adf86324ce6c6cbc64069c4210e748dde5400f7da738016a6b3c35c843f740008b0282581b52ea91d46a9600bfa8b79270d1ce8e4326f9fc9afa97082096eaf0ce1270eb030f53e98e3654d6fd38a313777b182051d95d582f67675628202dab60f120d4146250fa9ade4d0112aa873b5eb56425380e7b1220f6284ed1fa7d913a595aedfc0159ba2c95719d3c33646372098dc49037018885ed5d79e3479fee47fbe69076ea94852672f04f10e63fe3f53366fd61f7afd41831150cf24a49e837d72d656a1906943117252ab1f3889261ce09c3d832a4d583cfc82a049cee99cf62d4ec"); !checkIncludedHashID(hashes, 8200) {
		t.Errorf("Expected 1PASSWORD, CLOUDKEYCHAIN, got %v", hashes)
	}
}

func TestDNSSEC__NSEC3_(t *testing.T) {
	if hashes := gdth.Detect("7b5n74kq8r441blc2c5qbbat19baj79r:.lvdsiqfj.net:33164473:1"); !checkIncludedHashID(hashes, 8300) {
		t.Errorf("Expected DNSSEC (NSEC3), got %v", hashes)
	}
}

func TestWBB3__WOLTLAB_BURNING_BOARD_(t *testing.T) {
	if hashes := gdth.Detect("8084df19a6dc81e2597d051c3d8b400787e2d5a9:6755045315424852185115352765375338838643"); !checkIncludedHashID(hashes, 8400) {
		t.Errorf("Expected WBB3 (WOLTLAB BURNING BOARD), got %v", hashes)
	}
}

func TestRACF(t *testing.T) {
	if hashes := gdth.Detect("$racf$*USER*FC2577C6EBE6265B"); !checkIncludedHashID(hashes, 8500) {
		t.Errorf("Expected RACF, got %v", hashes)
	}
}

func TestLOTUS_NOTES_DOMINO_5(t *testing.T) {
	if hashes := gdth.Detect("3dd2e1e5ac03e230243d58b8c5ada076"); !checkIncludedHashID(hashes, 8600) {
		t.Errorf("Expected LOTUS NOTES/DOMINO 5, got %v", hashes)
	}
}

func TestLOTUS_NOTES_DOMINO_6(t *testing.T) {
	if hashes := gdth.Detect("(GDpOtD35gGlyDksQRxEU)"); !checkIncludedHashID(hashes, 8700) {
		t.Errorf("Expected LOTUS NOTES/DOMINO 6, got %v", hashes)
	}
}

func TestSCRYPT(t *testing.T) {
	if hashes := gdth.Detect("SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo="); !checkIncludedHashID(hashes, 8900) {
		t.Errorf("Expected SCRYPT, got %v", hashes)
	}
}

func TestLOTUS_NOTES_DOMINO_8(t *testing.T) {
	if hashes := gdth.Detect("(HsjFebq0Kh9kH7aAZYc7kY30mC30mC3KmC30mCluagXrvWKj1)"); !checkIncludedHashID(hashes, 9100) {
		t.Errorf("Expected LOTUS NOTES/DOMINO 8, got %v", hashes)
	}
}

func TestCISCO_IOS__8___PBKDF2_SHA256_(t *testing.T) {
	if hashes := gdth.Detect("$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk"); !checkIncludedHashID(hashes, 9200) {
		t.Errorf("Expected CISCO-IOS $8$ (PBKDF2-SHA256), got %v", hashes)
	}
}

func TestCISCO_IOS__9___SCRYPT_(t *testing.T) {
	if hashes := gdth.Detect("$9$2MJBozw/9R3UsU$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6"); !checkIncludedHashID(hashes, 9300) {
		t.Errorf("Expected CISCO-IOS $9$ (SCRYPT), got %v", hashes)
	}
}

func TestMS_OFFICE_2007(t *testing.T) {
	if hashes := gdth.Detect("$office$*2007*20*128*16*411a51284e0d0200b131a8949aaaa5cc*117d532441c63968bee7647d9b7df7d6*df1d601ccf905b375575108f42ef838fb88e1cde"); !checkIncludedHashID(hashes, 9400) {
		t.Errorf("Expected MS OFFICE 2007, got %v", hashes)
	}
}

func TestMS_OFFICE_2010(t *testing.T) {
	if hashes := gdth.Detect("$office$*2010*100000*128*16*77233201017277788267221014757262*b2d0ca4854ba19cf95a2647d5eee906c*e30cbbb189575cafb6f142a90c2622fa9e78d293c5b0c001517b3f5b82993557"); !checkIncludedHashID(hashes, 9500) {
		t.Errorf("Expected MS OFFICE 2010, got %v", hashes)
	}
}

func TestMS_OFFICE_2013(t *testing.T) {
	if hashes := gdth.Detect("$office$*2013*100000*256*16*7dd611d7eb4c899f74816d1dec817b3b*948dc0b2c2c6c32f14b5995a543ad037*0b7ee0e48e935f937192a59de48a7d561ef2691d5c8a3ba87ec2d04402a94895"); !checkIncludedHashID(hashes, 9600) {
		t.Errorf("Expected MS OFFICE 2013, got %v", hashes)
	}
}

func TestMS_OFFICE___2003_MD5___RC4__OLDOFFICE_0__OLDOFFICE_1(t *testing.T) {
	if hashes := gdth.Detect("$oldoffice$1*04477077758555626246182730342136*b1b72ff351e41a7c68f6b45c4e938bd6*0d95331895e99f73ef8b6fbc4a78ac1a"); !checkIncludedHashID(hashes, 9700) {
		t.Errorf("Expected MS OFFICE ⇐ 2003 MD5 + RC4, OLDOFFICE$0, OLDOFFICE$1, got %v", hashes)
	}
}

func TestMS_OFFICE___2003__0__1__MD5___RC4__COLLIDER__1_23(t *testing.T) {
	if hashes := gdth.Detect("$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2"); !checkIncludedHashID(hashes, 9710) {
		t.Errorf("Expected MS OFFICE ⇐ 2003 $0/$1, MD5 + RC4, COLLIDER #1 23, got %v", hashes)
	}
}

func TestMS_OFFICE___2003__0__1__MD5___RC4__COLLIDER__2(t *testing.T) {
	if hashes := gdth.Detect("$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2:91b2e062b9"); !checkIncludedHashID(hashes, 9720) {
		t.Errorf("Expected MS OFFICE ⇐ 2003 $0/$1, MD5 + RC4, COLLIDER #2, got %v", hashes)
	}
}

func TestMS_OFFICE___2003_SHA1___RC4__OLDOFFICE_3__OLDOFFICE_4(t *testing.T) {
	if hashes := gdth.Detect("$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd"); !checkIncludedHashID(hashes, 9800) {
		t.Errorf("Expected MS OFFICE ⇐ 2003 SHA1 + RC4, OLDOFFICE$3, OLDOFFICE$4, got %v", hashes)
	}
}

func TestMS_OFFICE___2003__3__SHA1___RC4__COLLIDER__1_24(t *testing.T) {
	if hashes := gdth.Detect("$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd"); !checkIncludedHashID(hashes, 9810) {
		t.Errorf("Expected MS OFFICE ⇐ 2003 $3, SHA1 + RC4, COLLIDER #1 24, got %v", hashes)
	}
}

func TestMS_OFFICE___2003__3__SHA1___RC4__COLLIDER__2(t *testing.T) {
	if hashes := gdth.Detect("$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd:b8f63619ca"); !checkIncludedHashID(hashes, 9820) {
		t.Errorf("Expected MS OFFICE ⇐ 2003 $3, SHA1 + RC4, COLLIDER #2, got %v", hashes)
	}
}

func TestRADMIN2(t *testing.T) {
	if hashes := gdth.Detect("22527bee5c29ce95373c4e0f359f079b"); !checkIncludedHashID(hashes, 9900) {
		t.Errorf("Expected RADMIN2, got %v", hashes)
	}
}

func TestDJANGO__PBKDF2_SHA256_(t *testing.T) {
	if hashes := gdth.Detect("pbkdf2_sha256$20000$H0dPx8NeajVu$GiC4k5kqbbR9qWBlsRgDywNqC2vd9kqfk7zdorEnNas="); !checkIncludedHashID(hashes, 10000) {
		t.Errorf("Expected DJANGO (PBKDF2-SHA256), got %v", hashes)
	}
}

func TestSIPHASH(t *testing.T) {
	if hashes := gdth.Detect("ad61d78c06037cd9:2:4:81533218127174468417660201434054"); !checkIncludedHashID(hashes, 10100) {
		t.Errorf("Expected SIPHASH, got %v", hashes)
	}
}

func TestCRAM_MD5(t *testing.T) {
	if hashes := gdth.Detect("$cram_md5$PG5vLXJlcGx5QGhhc2hjYXQubmV0Pg==$dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ=="); !checkIncludedHashID(hashes, 10200) {
		t.Errorf("Expected CRAM-MD5, got %v", hashes)
	}
}

func TestSAP_CODVN_H__PWDSALTEDHASH__ISSHA_1(t *testing.T) {
	if hashes := gdth.Detect("{x-issha, 1024}C0624EvGSdAMCtuWnBBYBGA0chvqAflKY74oEpw/rpY="); !checkIncludedHashID(hashes, 10300) {
		t.Errorf("Expected SAP CODVN H (PWDSALTEDHASH) ISSHA-1, got %v", hashes)
	}
}

func TestPDF_1_4___1_6__ACROBAT_5___8_(t *testing.T) {
	if hashes := gdth.Detect("$pdf$2*3*128*-1028*1*16*da42ee15d4b3e08fe5b9ecea0e02ad0f*32*c9b59d72c7c670c42eeb4fca1d2ca15000000000000000000000000000000000*32*c4ff3e868dc87604626c2b8c259297a14d58c6309c70b00afdfb1fbba10ee571"); !checkIncludedHashID(hashes, 10500) {
		t.Errorf("Expected PDF 1.4 - 1.6 (ACROBAT 5 - 8), got %v", hashes)
	}
}

func TestSHA2_384(t *testing.T) {
	if hashes := gdth.Detect("07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42"); !checkIncludedHashID(hashes, 10800) {
		t.Errorf("Expected SHA2-384, got %v", hashes)
	}
}

func TestPBKDF2_HMAC_SHA256(t *testing.T) {
	if hashes := gdth.Detect("sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt"); !checkIncludedHashID(hashes, 10900) {
		t.Errorf("Expected PBKDF2-HMAC-SHA256, got %v", hashes)
	}
}

func TestPRESTASHOP(t *testing.T) {
	if hashes := gdth.Detect("810e3d12f0f10777a679d9ca1ad7a8d9:M2uZ122bSHJ4Mi54tXGY0lqcv1r28mUluSkyw37ou5oia4i239ujqw0l"); !checkIncludedHashID(hashes, 11000) {
		t.Errorf("Expected PRESTASHOP, got %v", hashes)
	}
}

func TestPOSTGRESQL_CRAM__MD5_(t *testing.T) {
	if hashes := gdth.Detect("$postgres$postgres*f0784ea5*2091bb7d4725d1ca85e8de6ec349baf6"); !checkIncludedHashID(hashes, 11100) {
		t.Errorf("Expected POSTGRESQL CRAM (MD5), got %v", hashes)
	}
}

func TestMYSQL_CRAM__SHA1_(t *testing.T) {
	if hashes := gdth.Detect("$mysqlna$1c24ab8d0ee94d70ab1f2e814d8f0948a14d10b9*437e93572f18ae44d9e779160c2505271f85821d"); !checkIncludedHashID(hashes, 11200) {
		t.Errorf("Expected MYSQL CRAM (SHA1), got %v", hashes)
	}
}

func TestJOOMLA___2_5_18(t *testing.T) {
	if hashes := gdth.Detect("19e0e8d91c722e7091ca7a6a6fb0f4fa:54718031842521651757785603028777"); !checkIncludedHashID(hashes, 11) {
		t.Errorf("Expected JOOMLA < 2.5.18, got %v", hashes)
	}
}

func TestOSCOMMERCE__XT_COMMERCE(t *testing.T) {
	if hashes := gdth.Detect("374996a5e8a5e57fd97d893f7df79824:36"); !checkIncludedHashID(hashes, 21) {
		t.Errorf("Expected OSCOMMERCE, XT:COMMERCE, got %v", hashes)
	}
}

func TestJUNIPER_NETSCREEN_SSG__SCREENOS_(t *testing.T) {
	if hashes := gdth.Detect("nNxKL2rOEkbBc9BFLsVGG6OtOUO/8n:user"); !checkIncludedHashID(hashes, 22) {
		t.Errorf("Expected JUNIPER NETSCREEN/SSG (SCREENOS), got %v", hashes)
	}
}

func TestSKYPE(t *testing.T) {
	if hashes := gdth.Detect("3af0389f093b181ae26452015f4ae728:user"); !checkIncludedHashID(hashes, 23) {
		t.Errorf("Expected SKYPE, got %v", hashes)
	}
}

func TestNSLDAP__SHA_1_BASE64___NETSCAPE_LDAP_SHA(t *testing.T) {
	if hashes := gdth.Detect("{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s="); !checkIncludedHashID(hashes, 101) {
		t.Errorf("Expected NSLDAP, SHA-1(BASE64), NETSCAPE LDAP SHA, got %v", hashes)
	}
}

func TestNSLDAPS__SSHA_1_BASE64___NETSCAPE_LDAP_SSHA(t *testing.T) {
	if hashes := gdth.Detect("{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng=="); !checkIncludedHashID(hashes, 111) {
		t.Errorf("Expected NSLDAPS, SSHA-1(BASE64), NETSCAPE LDAP SSHA, got %v", hashes)
	}
}

func TestORACLE_S__TYPE__ORACLE_11__(t *testing.T) {
	if hashes := gdth.Detect("ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130"); !checkIncludedHashID(hashes, 112) {
		t.Errorf("Expected ORACLE S: TYPE (ORACLE 11+), got %v", hashes)
	}
}

func TestSMF__SIMPLE_MACHINES_FORUM____V1_1(t *testing.T) {
	if hashes := gdth.Detect("ecf076ce9d6ed3624a9332112b1cd67b236fdd11:17782686"); !checkIncludedHashID(hashes, 121) {
		t.Errorf("Expected SMF (SIMPLE MACHINES FORUM) > V1.1, got %v", hashes)
	}
}

func TestMACOS_V10_4__MACOS_V10_5__MACOS_V10_6(t *testing.T) {
	if hashes := gdth.Detect("1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683"); !checkIncludedHashID(hashes, 122) {
		t.Errorf("Expected MACOS V10.4, MACOS V10.5, MACOS V10.6, got %v", hashes)
	}
}

func TestDJANGO__SHA_1_(t *testing.T) {
	if hashes := gdth.Detect("sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013"); !checkIncludedHashID(hashes, 124) {
		t.Errorf("Expected DJANGO (SHA-1), got %v", hashes)
	}
}

func TestMSSQL__2000_(t *testing.T) {
	if hashes := gdth.Detect("0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578"); !checkIncludedHashID(hashes, 131) {
		t.Errorf("Expected MSSQL (2000), got %v", hashes)
	}
}

func TestMSSQL__2005_(t *testing.T) {
	if hashes := gdth.Detect("0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe"); !checkIncludedHashID(hashes, 132) {
		t.Errorf("Expected MSSQL (2005), got %v", hashes)
	}
}

func TestPEOPLESOFT(t *testing.T) {
	if hashes := gdth.Detect("uXmFVrdBvv293L9kDR3VnRmx4ZM="); !checkIncludedHashID(hashes, 133) {
		t.Errorf("Expected PEOPLESOFT, got %v", hashes)
	}
}

func TestEPISERVER_6_X____NET_4(t *testing.T) {
	if hashes := gdth.Detect("$episerver$*0*bEtiVGhPNlZpcUN4a3ExTg==*utkfN0EOgljbv5FoZ6+AcZD5iLk"); !checkIncludedHashID(hashes, 141) {
		t.Errorf("Expected EPISERVER 6.X < .NET 4, got %v", hashes)
	}
}

func TestHMAILSERVER(t *testing.T) {
	if hashes := gdth.Detect("8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3"); !checkIncludedHashID(hashes, 1421) {
		t.Errorf("Expected HMAILSERVER, got %v", hashes)
	}
}

func TestEPISERVER_6_X_____NET_4(t *testing.T) {
	if hashes := gdth.Detect("$episerver$*1*MDEyMzQ1Njc4OWFiY2RlZg==*lRjiU46qHA7S6ZE7RfKUcYhB85ofArj1j7TrCtu3u6Y"); !checkIncludedHashID(hashes, 1441) {
		t.Errorf("Expected EPISERVER 6.X >= .NET 4, got %v", hashes)
	}
}

func TestSSHA_512_BASE64___LDAP__SSHA512_(t *testing.T) {
	if hashes := gdth.Detect("{SSHA512}ALtwKGBdRgD+U0fPAy31C28RyKYx7+a8kmfksccsOeLknLHv2DBXYI7TDnTolQMBuPkWDISgZr2cHfnNPFjGZTEyNDU4OTkw"); !checkIncludedHashID(hashes, 1711) {
		t.Errorf("Expected SSHA-512(BASE64), LDAP {SSHA512}, got %v", hashes)
	}
}

func TestMACOS_V10_7(t *testing.T) {
	if hashes := gdth.Detect("648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d"); !checkIncludedHashID(hashes, 1722) {
		t.Errorf("Expected MACOS V10.7, got %v", hashes)
	}
}

func TestMSSQL__2012__2014_(t *testing.T) {
	if hashes := gdth.Detect("0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375"); !checkIncludedHashID(hashes, 1731) {
		t.Errorf("Expected MSSQL (2012, 2014), got %v", hashes)
	}
}

func TestVBULLETIN___V3_8_5(t *testing.T) {
	if hashes := gdth.Detect("16780ba78d2d5f02f3202901c1b6d975:568"); !checkIncludedHashID(hashes, 2611) {
		t.Errorf("Expected VBULLETIN < V3.8.5, got %v", hashes)
	}
}

func TestPHPS(t *testing.T) {
	if hashes := gdth.Detect("$PHPS$34323438373734$5b07e065b9d78d69603e71201c6cf29f"); !checkIncludedHashID(hashes, 2612) {
		t.Errorf("Expected PHPS, got %v", hashes)
	}
}

func TestVBULLETIN____V3_8_5(t *testing.T) {
	if hashes := gdth.Detect("bf366348c53ddcfbd16e63edfdd1eee6:181264250056774603641874043270"); !checkIncludedHashID(hashes, 2711) {
		t.Errorf("Expected VBULLETIN >= V3.8.5, got %v", hashes)
	}
}

func TestMYBB_1_2___IPB2___INVISION_POWER_BOARD_(t *testing.T) {
	if hashes := gdth.Detect("8d2129083ef35f4b365d5d87487e1207:47204"); !checkIncludedHashID(hashes, 2811) {
		t.Errorf("Expected MYBB 1.2+, IPB2+ (INVISION POWER BOARD), got %v", hashes)
	}
}

func TestMEDIAWIKI_B_TYPE(t *testing.T) {
	if hashes := gdth.Detect("$B$56668501$0ce106caa70af57fd525aeaf80ef2898"); !checkIncludedHashID(hashes, 3711) {
		t.Errorf("Expected MEDIAWIKI B TYPE, got %v", hashes)
	}
}

func TestMACOS_V10_8___PBKDF2_SHA512_(t *testing.T) {
	if hashes := gdth.Detect("$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222"); !checkIncludedHashID(hashes, 7100) {
		t.Errorf("Expected MACOS V10.8+ (PBKDF2-SHA512), got %v", hashes)
	}
}

