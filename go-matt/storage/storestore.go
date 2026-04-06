package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/protocol"
)

type StoreStore struct {
	Filepath string
	Identity *crypt.Identity
	Files    map[string]StoreEntry
}

type StoreEntry struct {
	Filename string                      `json:"filename"`
	Record   *protocol.PartialFileRecord `json:"partial_record"`
}

func NewStoreStore(identity *crypt.Identity, filepath string) *StoreStore {
	// Load in storestore from file
	tss := &StoreStore{
		Filepath: filepath,
		Identity: identity,
		Files:    make(map[string]StoreEntry),
	}
	tss.load()
	return tss
}

func (tss *StoreStore) load() {

	tss.Files = make(map[string]StoreEntry)
	// See if file doesn't exist
	if _, err := os.Stat(tss.Filepath); os.IsNotExist(err) {
		return
	}

	// Read it! It does exist
	data, err := LoadAndDecrypt(tss.Identity, tss.Filepath)

	if err != nil {
		log.Println("Error reading trust store:", err)
		return
	}

	var bytes map[string]StoreEntry
	if err := json.Unmarshal(data, &bytes); err != nil {
		log.Println("Error parsing trust store:", err)
		return
	}
	tss.Files = bytes
}

func (tss *StoreStore) save() {
	// Make file if it doesn't exist
	dir := filepath.Dir(tss.Filepath)
	if dir != "" {
		os.MkdirAll(dir, os.ModePerm)
	}

	data, err := json.MarshalIndent(tss.Files, "", "  ")
	if err != nil {
		log.Println("Error jsoning the store store", err)
		return
	}

	// Store it encrypted!
	// Generate salt
	salt := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		log.Println("Error saving the store store", err)
	}

	err = EncryptAndStore(tss.Identity, tss.Filepath, salt, data)
	if err != nil {
		log.Println("Error writing the store store", err)
	}
}

func (tss *StoreStore) AddFile(filename string, partial *protocol.PartialFileRecord, encName string) {
	// Add entry and save
	tss.Files[filename] = StoreEntry{encName, partial}
	tss.save()
}

func (tss *StoreStore) RemoveFile(filename string) {
	// Remove entry and save
	_, ok := tss.Files[filename]
	if ok {
		delete(tss.Files, filename)
		tss.save()
	}
}

func (tss *StoreStore) GetFilename(filename string) string {
	entry, ok := tss.Files[filename]
	if !ok {
		return ""
	}
	return entry.Filename
}

func (tss *StoreStore) GetRecord(filename string) *protocol.PartialFileRecord {
	entry, ok := tss.Files[filename]
	if !ok {
		return nil
	}
	return entry.Record
}

func (tss *StoreStore) SaveFile(filename string, record *protocol.FileRecord, data []byte) (string, error) {
	storageDir, err := getStorageDir(tss.Identity.Identity_dir)
	if err != nil {
		return "", err
	}

	// Generate salt
	salt := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Doing double work but its fine
	key := deriveKey(tss.Identity.Password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	var cipherfilename string
	var newName = filename
	for {
		nonce := make([]byte, NonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}

		cipherfilename = hex.EncodeToString(gcm.Seal(nil, nonce, []byte(filename), nil))
		// make full path
		fullname := filepath.Join(storageDir, "cipherfilename")
		if !FileExists(fullname) {
			// Okay we will save it as this. First get a new filename in storestore
			// Copy code from filemanager. Super messy I know!
			ext := filepath.Ext(filename)
			name := filename[:len(filename)-len(ext)]
			newName = filename

			counter := 1

			for {
				if tss.GetFilename(newName) == "" {
					break
				}
				// File exists, create a new filename and test it
				newName = fmt.Sprintf("%s(%d)%s", name, counter, ext)
				counter++
			}

			// Make partial record with info from full record
			partial := protocol.PartialFileRecord{
				Filename: record.Filename,
				Owner:    record.Owner,
				Sha256:   record.Sha256,
				Size:     record.Size,
			}
			tss.AddFile(newName, &partial, cipherfilename)
			break
		}
	}
	filePath := filepath.Join(storageDir, cipherfilename)

	return newName, EncryptAndStore(tss.Identity, filePath, salt, data)
}

func (tss *StoreStore) GetFile(filename string) ([]byte, *protocol.PartialFileRecord, error) {
	storageDir, err := getStorageDir(tss.Identity.Identity_dir)
	if err != nil {
		return nil, nil, err
	}

	// Get file from store store
	cipherfilename := tss.GetFilename(filename)
	if cipherfilename == "" {
		log.Println("File not found!")
		return nil, nil, err
	}

	partial := tss.GetRecord(filename)

	filepath := filepath.Join(storageDir, cipherfilename)
	data, err := LoadAndDecrypt(tss.Identity, filepath)

	return data, partial, err
}

func (tss *StoreStore) DeleteFile(filename string) error {
	// Delete
	storageDir, err := getStorageDir(tss.Identity.Identity_dir)
	if err != nil {
		return err
	}

	//Get name
	cipherfilename := tss.GetFilename(filename)
	if cipherfilename == "" {
		return err
	}

	return os.Remove(filepath.Join(storageDir, cipherfilename))
}

func (tss *StoreStore) ListFiles() []string {
	// Get them from our store
	var files []string

	for filename := range tss.Files {
		files = append(files, filename)
	}

	return files
}
