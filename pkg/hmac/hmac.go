package hmac

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// validateMAC reports whether messageMAC is a valid HMAC tag for message.
func validMAC(message, messageMAC, key []byte, shaVersion string) bool {
	var mac hash.Hash

	if shaVersion == "sha256" {
		mac = hmac.New(sha256.New, key)
	} else if shaVersion == "sha1" {
		mac = hmac.New(sha1.New, key)
	} else {
		fmt.Errorf("Invalid shaVersion")
	}

	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

// CreateHash a message with the key and return bytes.
func CreateHash(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	hash := mac.Sum(nil)
	return hash
}

// Verify validates an encodedHash
func Verify(bytesIn []byte, encodedHash string, secretKey string, shaVersion string) error {
	var results error

	if strings.Contains(encodedHash, "=") {

		shaName := strings.Split(encodedHash, "=")
		if shaName[0] != shaVersion {
			return fmt.Errorf("Incorrect hashing method: %s", shaName[0])
		}

		messageMAC := shaName[1]
		messageMACBuf, _ := hex.DecodeString(messageMAC)

		check := validMAC(bytesIn, []byte(messageMACBuf), []byte(secretKey), shaVersion)
		if check == false {
			results = fmt.Errorf("Invalid message digest or key")
		}
	} else {
		results = fmt.Errorf("EncodedHash does not contain a =")
	}

	return results
}

func init() {

}
