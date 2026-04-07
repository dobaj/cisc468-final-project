package main

import (
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/peers"
	"github.com/dobaj/cisc468-final-project/protocol"
	"github.com/dobaj/cisc468-final-project/sharing"
	"github.com/dobaj/cisc468-final-project/storage"
	"github.com/dobaj/cisc468-final-project/trust"
)

func makeIdentity(t *testing.T, name string) *crypt.Identity {
	t.Helper()
	i := &crypt.Identity{
		Name:     name,
		Password: "testpass",
		Base_dir: "./testdata/",
	}
	i, err := crypt.Load_or_create(i)
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}
	return i
}

func makeSharedKey(t *testing.T) []byte {
	t.Helper()
	k := &crypt.Key{}
	k = crypt.GenerateKey(k)

	k2 := &crypt.Key{}
	k2 = crypt.GenerateKey(k2)

	secret, err := crypt.CompSecret(k, k2.Pub_key.Bytes())
	if err != nil {
		t.Fatal("Error computing secret")
	}

	shared_key := crypt.DeriveKey(secret)
	return shared_key
}

func TestKeyRotation(t *testing.T) {
	i := makeIdentity(t, "charlie")

	oldPub := i.Pub_key
	err := crypt.RotateKey(i)
	if err != nil {
		t.Errorf("Something went wrong")
	}
	if oldPub.Equal(i.Pub_key) {
		t.Errorf("Public key was not rotated")
	}
}

func TestIdentityStoreLoad(t *testing.T) {
	first := makeIdentity(t, "matt")
	second := makeIdentity(t, "matt")

	if !first.Priv_key.Equal(second.Priv_key) ||
		!first.Pub_key.Equal(second.Pub_key) {
		t.Errorf("Loading error. Fields dont match")
	}
}

func TestFileStorage(t *testing.T) {
	i := makeIdentity(t, "bob")

	fileManager := sharing.NewFileManager(i.Base_dir + "/shared")
	storeStore := storage.NewStoreStore(i, i.Base_dir+"/storestore.json")

	// Make and save test file
	content := []byte("Hello, world!")
	fileName := "testfile.txt"
	record := fileManager.BuildRecordFromFileBytes("testfile.txt", content, i)
	partial := protocol.PartialFileRecord{
		Filename: record.Filename,
		Owner:    record.Owner,
		Sha256:   record.Sha256,
		Size:     record.Size,
	}
	savedPath, err := fileManager.SaveFile(&partial, content)
	if err != nil {
		t.Fatalf("Failed to save file: %v", err)
	}

	// Store encrypted
	name, err := storeStore.SaveFile(fileName, record, content)
	if err != nil {
		t.Fatalf("Failed to store file: %v", err)
	}

	// Retrieve encrypted file
	bytes, newPartial, err := storeStore.GetFile(name)
	if err != nil || string(bytes) != string(content) || partial != *newPartial {
		t.Errorf("Encrypted file content mismatch")
	}

	bytes, newRecord, err := fileManager.GetFile(savedPath, i)
	if err != nil || string(bytes) != string(content) || *record != *newRecord {
		t.Errorf("Stored file content mismatch")
	}
}

func TestDetectSessionMessageTampering(t *testing.T) {
	shared_key := makeSharedKey(t)
	content := []byte("Hello, world!")
	nonce, ciphertext, err := crypt.Encrypt(shared_key, content)
	if err != nil {
		t.Fatal("Error encrypt")
	}
	//Flip one bit
	ciphertext[0] ^= 1

	_, err = crypt.Decrypt(shared_key, nonce, ciphertext)
	if err == nil {
		println("No error in decryption")
		t.FailNow()
	}

}

func TestDetectFileTampering(t *testing.T) {
	i := makeIdentity(t, "bob")
	a := makeIdentity(t, "alice")

	fileManager := sharing.NewFileManager(i.Base_dir + "/shared")
	storeStore := storage.NewStoreStore(i, i.Base_dir+"/storestore.json")
	trustStore := trust.NewTrustStore(i.Base_dir + "/storestore.json")

	peer := protocol.ActivePeer{
		Name:        "bob",
		Sock:        nil,
		Cipher:      makeSharedKey(t),
		Fingerprint: hex.EncodeToString(crypt.Fingerprint(i.Pub_key)),
		IdentityPub: hex.EncodeToString(i.Pub_key),
	}

	// Make and save test file
	content := []byte("Hello, world!")
	fileName := "testfile.txt"
	record := fileManager.BuildRecordFromFileBytes("testfile.txt", content, i)
	msg := protocol.FileChunk(fileName, content, record, true)

	// Send message. This one should have no error
	err := peers.HandleMessage(&peer, msg, fileManager, a, storeStore, trustStore)
	if err != nil {
		t.FailNow()
	}

	//Okay now lets change one byte of the file
	content[0] ^= 1
	msg = protocol.FileChunk(fileName, content, record, true)

	// Send message. This one should have an error
	err = peers.HandleMessage(&peer, msg, fileManager, a, storeStore, trustStore)
	if err == nil {
		t.FailNow()
	}

	// Now let's assume the attacker can get a hash collision
	record.Sha256 = hex.EncodeToString(fileManager.HashBytes(content))
	msg = protocol.FileChunk(fileName, content, record, true)

	// Send message. This one should have an error
	err = peers.HandleMessage(&peer, msg, fileManager, a, storeStore, trustStore)
	if err == nil {
		t.FailNow()
	}
}

func TestMain(m *testing.M) {
	// Run tests
	exitVal := m.Run()
	
	// Delete everything. Keep trying until everything is done
	var err error
	err = os.RemoveAll("./testdata/")
	for {
		if err == nil {
			break
		}
		time.Sleep(time.Second)
		err = os.RemoveAll("./testdata/")
	}

	os.Exit(exitVal)
}
