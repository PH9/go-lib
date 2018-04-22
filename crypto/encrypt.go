package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
)

//
func EncryptWithDes(key, iv, plainText []byte) ([]byte, error) {
	block, err := des.NewCipher(key)

	if err != nil {
		return nil, err
	}

	return encrypt(key, iv, plainText, block), nil
}

//
func EncryptWithTripleDes(key, iv, plainText []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)

	if err != nil {
		return nil, err
	}

	return encrypt(key, iv, plainText, block), nil
}

func encrypt(key, iv, plainText []byte, cipherBlock cipher.Block) []byte {
	blockSize := cipherBlock.BlockSize()
	origData := pkcs5Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(cipherBlock, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted
}

func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}
