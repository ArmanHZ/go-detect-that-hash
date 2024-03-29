# Go Detect that Hash!
Go Detect that Hash (gdth) is a hash detector written in Go.

You input a hash string and it will output the potential algorithm(s) used when hashing the input string according to our [rules.go](https://github.com/ArmanHZ/go-detect-that-hash/blob/master/rules.go) file. The matching is done by utilizing RegEx.

# Why?
Most of the popular hash detection/identifier tools are written in Python. So, we wanted to take a different approach and write it in Go!

# Installation
To install the `gdth` tool:

```bash
go install github.com/ArmanHZ/go-detect-that-hash/cmd/gdth@latest
```

To install the repository as a module:

```bash
go install github.com/ArmanHZ/go-detect-that-hash@latest
```

You can also change the `latest` part above to install any specific version you want. E.g. `v1.0.1`.

# Usage
We currently don't have a `-h` support, but we will add it sometime soon™

In the meantime, to build the project:

```bash
git pull https://github.com/ArmanHZ/go-detect-that-hash
go build cmd/gdth/gdth.go

# After building
./gdth <input_hash>

# Alternatively, without building
go run cmd/gdth/gdth.go <input_hash>
```

The output has 4 fields:
- Name: Name of the Hashing algorithm used
- HashCat: HashCat ID for the hash when you want to use HashCat to crack the hash
- John: John ID similar to HashCat ID
- Is extended: Is the Hash salted or not

# Example

```bash
echo 'gdth' | sha256sum

# Out
8e821b2c107564180e6bef9fdd2005a5f0a9c8b9c4e674433ab05232a34e2bf6

./gdth 8e821b2c108e821b2c107564180e6bef9fdd2005a5f0a9c8b9c4e674433ab05232a34e2bf6

# Out
------------------------------------------------------------------------------------+
                  Name                   |  HashCat  |      John      |  Extended?  |
------------------------------------------------------------------------------------+
               Snefru-256                |    N/A    |   snefru-256   |    False    |
                 SHA-256                 |   1400    |   raw-sha256   |    False    |
               RIPEMD-256                |    N/A    |      N/A       |    False    |
                Haval-256                |    N/A    |  haval-256-3   |    False    |
             GOST R 34.11-94             |   6900    |      gost      |    False    |
          GOST CryptoPro S-Box           |    N/A    |      N/A       |    False    |
                SHA3-256                 |   5000    | raw-keccak-256 |    False    |
                Skein-256                |    N/A    |   skein-256    |    False    |
             Skein-512(256)              |    N/A    |      N/A       |    False    |
                Ventrilo                 |    N/A    |      N/A       |    True     |
           sha256($pass.$salt)           |   1410    |      N/A       |    True     |
           sha256($salt.$pass)           |   1420    |      N/A       |    True     |
      sha256(unicode($pass).$salt)       |   1430    |      N/A       |    True     |
      sha256($salt.unicode($pass))       |   1440    |      N/A       |    True     |
        HMAC-SHA256 (key = $pass)        |   1450    |  hmac-sha256   |    True     |
        HMAC-SHA256 (key = $salt)        |   1460    |  hmac-sha256   |    True     |
              Cisco Type 7               |    N/A    |      N/A       |    True     |
                BigCrypt                 |    N/A    |    bigcrypt    |    True     |
------------------------------------------------------------------------------------+
```

# Usage as a library

```go
package main

import (
  "fmt"

  gdth "github.com/ArmanHZ/go-detect-that-hash"
)

func main() {
  results := gdth.Detect("127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935")
  fmt.Println(results)
}
```

# TODO
- [ ] Flag for `csv` output for potentially piping the output with other tools
- [x] ~~Add easy install via Go cmd tool~~
- [ ] Cleanup the code and fix some bugs (never ending task)
- [ ] Prettier output and colors using custom table printing functions
- [ ] Add command line argument parser
- [ ] Let the user to print only certain columns of the output. E.g. Name only
- [x] ~~Unit testing~~
### Later down the line stuff
- [ ] Print out analysis and sort the output by the likelyhood of the algorithm used in hashing

**Open to recommendations for features. You can open an Issue**

# Similar Projects
- https://github.com/psypanda/hashID/tree/master  (Python)
- https://github.com/blackploit/hash-identifier  (Pytohn)
- https://github.com/HashPals/Name-That-Hash  (Python)
