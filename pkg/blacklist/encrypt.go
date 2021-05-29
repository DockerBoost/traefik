package blacklist

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"os"
)

var iv *[]byte
var key *[]byte

func getIv() []byte {
	if iv == nil {
		ivEnv := decodeBase64(os.Getenv("BL_IV"))
		if len(ivEnv) == 0 {
			ivEnv = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
		}
		iv = &ivEnv
	}
	return *iv
}

func getKey() []byte {
	if key == nil {
		keyEnv := decodeBase64(os.Getenv("BL_KEY"))
		if len(keyEnv) == 0 {
			keyEnv = []byte("36b4d6b58215a7da96e3bf71a602e3ea")
		}
		key = &keyEnv
	}
	return *key
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func Encrypt(text string) string {
	block, err := aes.NewCipher(getKey())
	if err != nil {
		panic(err)
	}
	plaintext := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, getIv())
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)
	return encodeBase64(ciphertext)
}

func Decrypt(text string) string {
	block, err := aes.NewCipher(getKey())
	if err != nil {
		panic(err)
	}
	ciphertext := decodeBase64(text)
	cfb := cipher.NewCFBEncrypter(block, getIv())
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)
	return string(plaintext)
}
