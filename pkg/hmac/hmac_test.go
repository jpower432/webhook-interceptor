package hmac

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func Test_Verify_Errors(t *testing.T) {

	type args struct {
		digest      string
		key         string
		algorithm   string
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
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha256",
				encodedHash: "123",
			},
			wantErr: "encoded hash does not contain a =",
		},
		{
			name: "Invalid digest",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha256",
				encodedHash: "sha256=" + "1f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
			wantErr: "invalid message digest or key",
		},
		{
			name: "Incorrect algorithm",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha256",
				encodedHash: "sha512=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
			wantErr: "incorrect hashing method: sha512",
		},
		{
			name: "Unsupported algorithm",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha1",
				encodedHash: "sha1=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
			wantErr: "unsupported SHA version: sha1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify([]byte(tt.args.digest), tt.args.encodedHash, tt.args.key, tt.args.algorithm)
			if err == nil {
				t.Errorf("Expected error %s", tt.wantErr)
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

func Test_Verify_Success(t *testing.T) {

	type args struct {
		digest      string
		key         string
		algorithm   string
		encodedHash string
	}
	tests := []struct {
		name    string
		args    args
	}{
		{
			name: "SHA512 Test",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha512",
				encodedHash: "sha512=" +
					"fd91565c37915e8ddcc0af4ae9bea67495a8a2e930ec10308320c2a60372e9c89fdd9042f23281fac5e39260353523711702d4cfbd6b8311e2d037a81e8c82c0",
			},
		},
		{
			name: "SHA256 Test",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha256",
				encodedHash: "sha256=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify([]byte(tt.args.digest), tt.args.encodedHash, tt.args.key, tt.args.algorithm)
			if err != nil {
				t.Errorf("Expected no errors got %v", err)
				t.Fail()
			}
		})
	}
}

func Test_Create_Hash(t *testing.T) {

	type args struct {
		digest string
		key    []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "SHA256 Test",
			args: args{
				digest: "sign this message",
				key:    []byte("my key"),
			},
			want: "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := CreateHash([]byte(tt.args.digest), tt.args.key)
			got := hex.EncodeToString(hash)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateHash got = %v, want %v", got, tt.want)
			}
		})
	}
}
