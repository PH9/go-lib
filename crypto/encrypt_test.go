package crypto

import (
	"encoding/base64"
	"testing"
)

func Test_encryptWithDes(t *testing.T) {
	key := []byte("01234567")
	iv := []byte("01234567")
	originalText := []byte("this is password")
	cipherTextInByte, err := EncryptWithDes(key, iv, originalText)

	if err != nil {
		t.Error(err)
	}

	expectedBase64String := "hRS8vFh7y8DD5N0wsq-hkOyIXZ0LGcNA"
	actualBase64String := base64.URLEncoding.EncodeToString(cipherTextInByte)
	if expectedBase64String != actualBase64String {
		t.Error("cipher should be", expectedBase64String, "but it was", actualBase64String)
	}
}

func Test_encryptWithTripleDes(t *testing.T) {
	key := []byte("0123456789ABCDEFGHIJKLMN")
	iv := []byte("01234567")
	originalText := []byte("this is password")
	cipherTextInByte, err := EncryptWithTripleDes(key, iv, originalText)

	if err != nil {
		t.Error(err)
	}

	expectedBase64String := "THtdCLZ81Q9FvHXaBuPBVUG6od4Vv8nk"
	actualBase64String := base64.URLEncoding.EncodeToString(cipherTextInByte)
	if expectedBase64String != actualBase64String {
		t.Error("cipher should be", expectedBase64String, "but it was", actualBase64String)
	}
}
