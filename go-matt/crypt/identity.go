package crypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/youmark/pkcs8"
)

type Identity struct {
	Name          string
	Password      string
	Base_dir      string
	Priv_key      ed25519.PrivateKey
	Pub_key       ed25519.PublicKey
	Identity_dir  string
	Priv_key_path string
}

func Load_or_create(i *Identity) (*Identity, error) {
	// Do some initialization stuff
	if i.Identity_dir == "" {
		i.Identity_dir = filepath.Join(i.Base_dir, i.Name)
	}
	if i.Priv_key_path == "" {
		i.Priv_key_path = filepath.Join(i.Identity_dir, "identity.pem")
	}
	os.MkdirAll(i.Identity_dir, os.ModePerm)

	data, err := os.ReadFile(i.Priv_key_path)
	if err == nil {
		// We can read it from the file
		block, _ := pem.Decode(data)
		if block == nil {
			log.Println("Error reading priv key")
		}
		// Get priv/pub key back from the block
		priv_key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(i.Password))
		if err != nil {
			log.Println("Error reading priv key. Your password may be wrong.")
			return nil, errors.New("Wrong pass")
		}
		i.Priv_key = priv_key.(ed25519.PrivateKey)
		i.Pub_key = i.Priv_key.Public().(ed25519.PublicKey)
	} else {
		return i, RotateKey(i)
	}
	return i, nil
}

func Sign(i *Identity, data []byte) []byte {
	return ed25519.Sign(i.Priv_key, data)
}

func SignWithKey(privKey ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(privKey, data)
}

func Verify(pub_key []byte, signature []byte, data []byte) error {
	publicKey := ed25519.PublicKey(pub_key)
	if ed25519.Verify(publicKey, data, signature) == false {
		return errors.New("Verification error")
	} else {
		return nil
	}
}

func Fingerprint(pub_key []byte) []byte {
	sum := sha256.Sum256(pub_key)
	return sum[:]
}

func Save(i *Identity) error {
	// Insert into pem format
	block, err := pkcs8.ConvertPrivateKeyToPKCS8(i.Priv_key, []byte(i.Password))
	i.Priv_key_path = filepath.Join(i.Identity_dir, "identity.pem")
	pemBlock := pem.Block{Type: "PRIVATE KEY", Bytes: block}

	privFile, err := os.Create(i.Priv_key_path)
	if err != nil {
		log.Println("Error writing to file", err)
		return errors.New("Error writing to file")
	}
	pem.Encode(privFile, &pemBlock)
	return privFile.Close()
}

func RotateKey(i *Identity) error {
	var err error
	i.Pub_key, i.Priv_key, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Println("Error generating key", err)
		return errors.New("Error generating key")
	}
	err = Save(i)
	if err != nil {
		return err
	}
	return err
}
