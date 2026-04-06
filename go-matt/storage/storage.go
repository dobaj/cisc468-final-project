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

func EncryptAndStore(i *crypt.Identity, filename string, data []byte) error {
	storageDir, err := getStorageDir(i.Identity_dir)
	if err != nil {
		return err
	}

	// Generate salt
	salt := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

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

	// [saltLen(4 bytes)][salt][nonce][ciphertext]
	outPath := filepath.Join(storageDir, filename)
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

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

func LoadAndDecrypt(i *crypt.Identity, filename string) ([]byte, error) {
	storageDir, err := getStorageDir(i.Identity_dir)
	if err != nil {
		return nil, err
	}

	inPath := filepath.Join(storageDir, filename)
	f, err := os.Open(inPath)
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

func DeleteFile(i *crypt.Identity, filename string) error {
	// Delete
	storageDir, err := getStorageDir(i.Identity_dir)
	if err != nil {
		return err
	}

	return os.Remove(filepath.Join(storageDir, filename))
}

func ListFiles(i *crypt.Identity) ([]string, error) {
	storageDir, err := getStorageDir(i.Identity_dir)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(storageDir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}

	return files, nil
}
