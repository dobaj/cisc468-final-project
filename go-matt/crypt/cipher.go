package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log"
)
const NONCE_SIZE = 12

func Encrypt(key []byte, data []byte) ([]byte, []byte, error) {
	ciph, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal("Error creating cipher")
	}
	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		log.Fatal("Error creating GCM")
	}
	nonce := make([]byte, NONCE_SIZE)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Ok now we made the aes cipher, encrypt
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return nonce, ciphertext, nil
}

func Decrypt(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	ciph, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal("Error creating cipher")
	}

	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		log.Fatal("Error creating GCM")
	}

	if len(nonce) != NONCE_SIZE {
		return nil, errors.New("invalid nonce size")
	}

	// Likewise to Encrypt(), now we decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}