package crypto

import (
	"crypto/rand"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"path/filepath"
	"github.com/youmark/pkcs8"
)

type Identity struct {
	Name string
	Password string
	Base_dir string
	Priv_key ed25519.PrivateKey
	Pub_key ed25519.PublicKey
	Identity_dir string
	Priv_key_path string
}

func Load_or_create(i *Identity) (*Identity, error) {
	// Do some initialization stuff
	if i.Identity_dir == "" {
		i.Identity_dir = filepath.Join(i.Base_dir,i.Name,"shared")
	} 
	if i.Priv_key_path == "" {
		i.Priv_key_path = filepath.Join(i.Identity_dir,"identity.pem")
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
		// Make new key
		var err error
		i.Pub_key, i.Priv_key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Println("Error generating key", err)
		}
		// Insert into pem format
		block, err := pkcs8.ConvertPrivateKeyToPKCS8(i.Priv_key, []byte(i.Password))
		i.Priv_key_path = filepath.Join(i.Identity_dir,"identity.pem") 
		pemBlock := pem.Block{Type: "PRIVATE KEY", Bytes: block}
		
		privFile, err := os.Create(i.Priv_key_path)
		if err != nil {
			panic(err)
		}
		pem.Encode(privFile, &pemBlock)
	}
	return i, nil
}

func Sign(i *Identity, data []byte) ([]byte) {
	return ed25519.Sign(i.Priv_key, data)
}

func Verify(i *Identity, signature []byte, data []byte) (error) {
	if ed25519.Verify(i.Pub_key, signature, data) == false {
		return errors.New("Verification error")
	} else {
		return nil
	}
}

func Fingerprint(i *Identity) ([32]byte) {
	return sha256.Sum256(i.Pub_key)
}

// import hashlib
// from pathlib import Path

// from cryptography.hazmat.primitives import serialization
// from cryptography.hazmat.primitives.asymmetric.ed25519 import (
//     Ed25519PrivateKey,
//     Ed25519PublicKey,
// )


// class Identity:
//     def __init__(self, name, password, base_dir="data"):
//         self.name = name
//         self.password = password
//         self.base_dir = Path(base_dir)
//         self.private_key = None
//         self.public_key = None
//         self.identity_dir = self.base_dir / self.name
//         self.private_key_path = self.identity_dir / "identity.pem"

//     def load_or_create(self):
//         self.identity_dir.mkdir(parents=True, exist_ok=True)

//         if self.private_key_path.exists():
//             pem_bytes = self.private_key_path.read_bytes()
//             self.private_key = serialization.load_pem_private_key(
//                 pem_bytes,
//                 password=self.password.encode("utf-8"),
//             )
//         else:
//             self.private_key = Ed25519PrivateKey.generate()
//             pem_bytes = self.private_key.private_bytes(
//                 encoding=serialization.Encoding.PEM,
//                 format=serialization.PrivateFormat.PKCS8,
//                 encryption_algorithm=serialization.BestAvailableEncryption(
//                     self.password.encode("utf-8")
//                 ),
//             )
//             self.private_key_path.write_bytes(pem_bytes)

//         self.public_key = self.private_key.public_key()
//         return self

//     def sign(self, data: bytes):
//         return self.private_key.sign(data)

//     def verify(self, signature: bytes, data: bytes):
//         self.public_key.verify(signature, data)

//     def get_public_bytes(self):
//         return self.public_key.public_bytes(
//             encoding=serialization.Encoding.Raw,
//             format=serialization.PublicFormat.Raw,
//         )

//     def public_key_hex(self):
//         return self.get_public_bytes().hex()

//     def fingerprint(self):
//         return hashlib.sha256(self.get_public_bytes()).hexdigest()

//     def rotate_key(self):
//         old_private_key = self.private_key
//         self.private_key = Ed25519PrivateKey.generate()
//         self.public_key = self.private_key.public_key()
//         pem_bytes = self.private_key.private_bytes(
//             encoding=serialization.Encoding.PEM,
//             format=serialization.PrivateFormat.PKCS8,
//             encryption_algorithm=serialization.BestAvailableEncryption(
//                 self.password.encode("utf-8")
//             ),
//         )
//         self.private_key_path.write_bytes(pem_bytes)
//         return old_private_key, self.private_key

//     @staticmethod
//     def public_key_from_bytes(public_key_bytes: bytes):
//         return Ed25519PublicKey.from_public_bytes(public_key_bytes)