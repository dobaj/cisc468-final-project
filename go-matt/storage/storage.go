package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/dobaj/cisc468-final-project/crypt"
	"golang.org/x/crypto/pbkdf2"
)

const NonceLen = 12

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}

func getStorageDir(baseDir string) (string, error) {
	// Make sure folder is real
	storageDir := filepath.Join(baseDir, "storage")
	err := os.MkdirAll(storageDir, os.ModePerm)
	return storageDir, err
}

func EncryptAndStore(i *crypt.Identity, filePath string, salt []byte, data []byte) error {

	key := deriveKey(i.Password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Okay make the file
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	// writing with this format [saltLen(4 bytes)][salt][nonce][ciphertext]
	if err := binary.Write(f, binary.BigEndian, uint32(len(salt))); err != nil {
		return err
	}

	if _, err := f.Write(salt); err != nil {
		return err
	}

	if _, err := f.Write(nonce); err != nil {
		return err
	}

	if _, err := f.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

func LoadAndDecrypt(i *crypt.Identity, filepath string) ([]byte, error) {
	f, err := os.Open(filepath)
	if err != nil {
		log.Println("File not found!")
		return nil, err
	}
	defer f.Close()

	// [saltLen(4 bytes)][salt][nonce][ciphertext]
	var saltLen uint32
	if err := binary.Read(f, binary.BigEndian, &saltLen); err != nil {
		return nil, err
	}

	if saltLen != 12 {
		return nil, errors.New("invalid salt length")
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(f, salt); err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(f, nonce); err != nil {
		return nil, err
	}

	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Okay now we did the load lets decrypt
	key := deriveKey(i.Password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed (wrong password or corrupted file)")
	}

	return plaintext, nil
}

func FileExists(filepath string) bool {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		// File doesn't exist
		return false
	}
	return true
}
