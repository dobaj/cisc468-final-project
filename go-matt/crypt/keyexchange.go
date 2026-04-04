package crypt

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"
)

type Key struct {
	Priv_key *ecdh.PrivateKey
	Pub_key  *ecdh.PublicKey
}

var x25519 ecdh.Curve

func GenerateKey(k *Key) (*Key) {
    // Make curve
    x25519 = ecdh.X25519()
    var err error
    // Make key
    k.Priv_key, err = x25519.GenerateKey(rand.Reader)
    
    if (err != nil) {
        log.Fatal("Error generating key:", err)
    }
    k.Pub_key = k.Priv_key.PublicKey()
    return k
}

func CompSecret (k *Key, peerPublicKey []byte) ([]byte, error){
    peerPub, err := x25519.NewPublicKey(peerPublicKey)
    if err != nil {
        log.Println("Error deriving shared secret:", err)
        return []byte{}, errors.New("Error deriving shared secret")
    }
    // Hope this works!
    sharedSecret, err := k.Priv_key.ECDH(peerPub)
    if err != nil {
        log.Println("Error deriving shared secret:", err)
        return []byte{}, errors.New("Error deriving shared secret")
    }

    return sharedSecret, nil
}

func DeriveKey (secret []byte) ([]byte) {
	hash := sha256.New
	keyLen := 32

	info := "session key"

	// Generate key
    key, err := hkdf.Key(hash, secret, nil, info, keyLen)
    if err != nil {
        log.Fatal("Error deriving shared key:", err)
    }
    return key
}