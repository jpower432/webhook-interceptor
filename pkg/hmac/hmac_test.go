package hmac

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

func Test_Verify(t *testing.T) {

	type args struct {
		digest      string
		key         string
		algorithm   string
		encodedHash string
	}
	tests := []struct {
		name    string
		args    args
		want error
		wantErr bool
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
			wantErr: false,
		},
		{
			name: "SHA256 Test",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha256",
				encodedHash: "sha256=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
			wantErr: false,
		},
		{
			name: "Encode Hash Length",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha256",
				encodedHash: "123",
			},
			wantErr: true,
			want: fmt.Errorf("encoded hash does not contain a ="),
		},
		{
			name: "Invalid digest",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha256",
				encodedHash: "sha256=" + "1f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
			wantErr: true,
			want: fmt.Errorf("invalid message digest or key"),
		},
		{
			name: "Incorrect algorithm",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha256",
				encodedHash: "sha512=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
			wantErr: true,
			want: fmt.Errorf("incorrect hashing method: sha512"),
		},
		{
			name: "Unsupported algorithm",
			args: args{
				digest:      "sign this message",
				key:         "my key",
				algorithm:   "sha1",
				encodedHash: "sha1=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
			},
			wantErr: true,
			want: fmt.Errorf("unsupported SHA version: sha1"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify([]byte(tt.args.digest), tt.args.encodedHash, tt.args.key, tt.args.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				if !reflect.DeepEqual(err, tt.want) {
					t.Errorf("Verify got = %v, want %v", err, tt.want)
				}
			}
		})
	}
}

func Test_Create_Hash(t *testing.T) {

	type args struct {
		digest string
		key    []byte
		algorithm string
	}
	tests := []struct {
		name string
		args args
		want string
		wantErr bool
	}{
		{
			name: "SHA512 Test",
			args: args{
				digest:      "sign this message",
				key:         []byte("my key"),
				algorithm:   "sha512",
			},
			want: "fd91565c37915e8ddcc0af4ae9bea67495a8a2e930ec10308320c2a60372e9c89fdd9042f23281fac5e39260353523711702d4cfbd6b8311e2d037a81e8c82c0",
		},
		{
			name: "SHA256 Test",
			args: args{
				digest: "sign this message",
				key:    []byte("my key"),
				algorithm: "sha256",
			},
			want: "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
		},
		{
			name: "SHA256 Test",
			args: args{
				digest: "sign this message",
				key:    []byte("my key"),
				algorithm: "sha256",
			},
			want: "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := CreateHash([]byte(tt.args.digest), tt.args.key, tt.args.algorithm)
			got := hex.EncodeToString(hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateHash() got = %v, want %v", got, tt.want)
			}
		})
	}
}
