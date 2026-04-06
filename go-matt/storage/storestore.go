package storage

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)


type StoreStore struct {
	Filepath string
	Files    map[string]string
}

func NewTrustStore(filepath string) *StoreStore {
	// Load in storestore from file
	ts := &StoreStore{
		Filepath: filepath,
		Files:    make(map[string]string),
	}
	ts.load()
	return ts
}

func (ts *StoreStore) load() {
	// See if file doesn't exist
	if _, err := os.Stat(ts.Filepath); os.IsNotExist(err) {
		ts.Files = make(map[string]string)
		return
	}

	// Read it! It does exist
	data, err := os.ReadFile(ts.Filepath)
	if err != nil {
		log.Println("Error reading trust store:", err)
		return
	}

	var bytes map[string]string
	if err := json.Unmarshal(data, &bytes); err != nil {
		log.Println("Error parsing trust store:", err)
		return
	}

	ts.Files = make(map[string]string)

	for peerName, entry := range bytes {
		// Add entries to trusted
		ts.Files[peerName] = entry
	}
}

func (ts *StoreStore) save() {
	// Make file if it doesn't exist
	dir := filepath.Dir(ts.Filepath)
	if dir != "" {
		os.MkdirAll(dir, os.ModePerm)
	}

	data, err := json.MarshalIndent(ts.Files, "", "  ")
	if err != nil {
		log.Println("Error jsoning the store store", err)
		return
	}

	err = os.WriteFile(ts.Filepath, data, 0644)
	if err != nil {
		log.Println("Error writing the store store", err)
	}
}

func (ts *StoreStore) AddFile(filename string, encName string) {
	// Add entry and save
	ts.Files[filename] = encName
	ts.save()
}

func (ts *StoreStore) RemoveFile(filename string) {
	// Remove entry and save
	_, ok := ts.Files[filename]
	if ok {
		delete(ts.Files, filename)
		ts.save()
	}
}

func (ts *StoreStore) GetFile(peerName string) (string) {
	entry, ok := ts.Files[peerName]
	if !ok {
		return ""
	}
	return entry
}
