package hmac

import (
	"encoding/hex"
	"testing"
)


func Test_Verify_Errors(t *testing.T) {

	type args struct {
		digest  string
		key    string
		algorithm string
		encodedHash string
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "Encode Hash Length",
			args: args{
				digest:   "sign this message",
				key:     "my key",
				algorithm: "sha256",
				encodedHash: "123",
			},
			wantErr: "EncodedHash does not contain a =",

		},
		{
			name: "Invalid digest",
			args: args{
				digest:   "sign this message",
				key:     "my key",
				algorithm: "sha256",
				encodedHash: "sha256=" + "1f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
			wantErr: "Invalid message digest or key",

		},
		{
			name: "Incorrect algorithm",
			args: args{
				digest:   "sign this message",
				key:     "my key",
				algorithm: "sha256",
				encodedHash: "sha1=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
			wantErr: "Incorrect hashing method: sha1",

		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify([]byte(tt.args.digest), tt.args.encodedHash, tt.args.key, tt.args.algorithm)
			if err == nil {
				t.Errorf("Expected an error about the encode has length")
				t.Fail()
			} else if err.Error() != tt.wantErr {
				t.Errorf("want: %s, got: %s", tt.wantErr, err.Error())
				t.Fail()
			}
		})
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
