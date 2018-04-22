package crypto

import (
	"crypto/cipher"
	"crypto/des"
)

//
func DecryptWithDes(key, iv, cipherText []byte) ([]byte, error) {
	block, err := des.NewCipher(key)

	if err != nil {
		return nil, err
	}

	return decrypt(key, iv, cipherText, block), nil
}

//
func DecryptWithTripleDes(key, iv, cipherText []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)

	if err != nil {
		return nil, err
	}

	return decrypt(key, iv, cipherText, block), nil
}

func decrypt(key, iv, cipherText []byte, cipherBlock cipher.Block) []byte {
	blockMode := cipher.NewCBCDecrypter(cipherBlock, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs5UnPadding(origData)
	return origData
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
