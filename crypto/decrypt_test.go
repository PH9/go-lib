package crypto

import (
	"encoding/base64"
	"testing"
)

func Test_dncryptWithDes(t *testing.T) {
	originalCipherText := "hRS8vFh7y8DD5N0wsq-hkOyIXZ0LGcNA"
	key := []byte("01234567")
	iv := []byte("01234567")

	b, err := base64.URLEncoding.DecodeString(originalCipherText)
	if err != nil {
		t.Error(err)
	}

	decryptedResult, err := DecryptWithDes(key, iv, b)
	if err != nil {
		t.Error(err)
	}

	expectedPlainText := "this is password"
	actualPlainText := string(decryptedResult)
	if expectedPlainText != actualPlainText {
		t.Error("plain text should be", expectedPlainText, "but it was", actualPlainText)
	}
}

func Test_dncryptWithTripleDes(t *testing.T) {
	originalCipherText := "THtdCLZ81Q9FvHXaBuPBVUG6od4Vv8nk"
	key := []byte("0123456789ABCDEFGHIJKLMN")
	iv := []byte("01234567")

	b, err := base64.URLEncoding.DecodeString(originalCipherText)
	if err != nil {
		t.Error(err)
	}

	decryptedResult, err := DecryptWithTripleDes(key, iv, b)
	if err != nil {
		t.Error(err)
	}

	expectedPlainText := "this is password"
	actualPlainText := string(decryptedResult)
	if expectedPlainText != actualPlainText {
		t.Error("plain text should be", expectedPlainText, "but it was", actualPlainText)
	}
}
