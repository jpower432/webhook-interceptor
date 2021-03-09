package hmac

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func Test_EncodedHashLength(t *testing.T) {

	digest := "sign this message"
	key := "my key"
	sha := "sha256"

	encodedHash := "123"

	err := Verify([]byte(digest), encodedHash, key, sha)
	wantErr := "EncodedHash does not contain a ="

	if err == nil {
		t.Errorf("Expected an error about the encode has length")
		t.Fail()
	} else if err.Error() != wantErr {
		t.Errorf("want: %s, got: %s", wantErr, err.Error())
		t.Fail()
	}
}

func Test_WrongHash(t *testing.T) {
	digest := "sign this message"
	key := "my key"
	sha := "sha256"

	encodedHash := "sha256=" + "1f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7"

	err := Verify([]byte(digest), encodedHash, key, sha)
	wantErr := "Invalid message digest or key"

	if err == nil {
		t.Errorf("Expected error due to missing prefix")
		t.Fail()
	} else if err.Error() != wantErr {
		t.Errorf("want: %s, got: %s", wantErr, err.Error())
		t.Fail()
	}
}

func Test_SHAPrefix(t *testing.T) {
	digest := "sign this message"
	key := "my key"
	sha := "sha256"

	encodedHash := "sha1=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7"
	shaName := strings.Split(encodedHash, "=")[0]

	err := Verify([]byte(digest), encodedHash, key, sha)
	wantErr := fmt.Sprintf("Incorrect hashing method: %s", shaName)

	if err == nil {
		t.Errorf("Expected error due wring Hash type ")
		t.Fail()
	} else if err.Error() != wantErr {
		t.Errorf("want: %s, got: %s", wantErr, err.Error())
		t.Fail()
	}
}

func Test_CreateHash(t *testing.T) {
	digest := "sign this message"
	key := []byte("my key")

	wantHash := "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7"

	hash := CreateHash([]byte(digest), key)
	encodedHash := hex.EncodeToString(hash)

	if encodedHash != wantHash {
		t.Errorf("Sign want hash: %s, got: %s", wantHash, encodedHash)
		t.Fail()
	}
}

func Test_CorrectHash(t *testing.T) {
	digest := "sign this message"
	key := "my key"
	sha := "sha256"

	encodedHash := "sha256=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7"

	err := Verify([]byte(digest), encodedHash, key, sha)

	if err != nil {
		t.Errorf("Error %s occurred, was not expecting error", err)
		t.Fail()
	}
}
