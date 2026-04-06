package trust

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

type TrustEntry struct {
	Fingerprint          string   `json:"fingerprint"`
	PreviousFingerprints []string `json:"previous_fingerprints"`
}

type TrustStore struct {
	Filepath string
	Trusted  map[string]TrustEntry
}

func NewTrustStore(filepath string) *TrustStore {
	// Load in truststore from file
	ts := &TrustStore{
		Filepath: filepath,
		Trusted:  make(map[string]TrustEntry),
	}
	ts.load()
	return ts
}

func (ts *TrustStore) load() {
	// See if file doesn't exist
	if _, err := os.Stat(ts.Filepath); os.IsNotExist(err) {
		ts.Trusted = make(map[string]TrustEntry)
		return
	}

	// Read it! It does exist
	data, err := os.ReadFile(ts.Filepath)
	if err != nil {
		log.Println("Error reading trust store:", err)
		return
	}

	var bytes map[string]TrustEntry
	if err := json.Unmarshal(data, &bytes); err != nil {
		log.Println("Error parsing trust store:", err)
		return
	}

	ts.Trusted = make(map[string]TrustEntry)

	for peerName, entry := range bytes {
		// Add entries to trusted
		ts.Trusted[peerName] = entry
	}
}

func (ts *TrustStore) save() {
	// Make file if it doesn't exist
	dir := filepath.Dir(ts.Filepath)
	if dir != "" {
		os.MkdirAll(dir, os.ModePerm)
	}

	data, err := json.MarshalIndent(ts.Trusted, "", "  ")
	if err != nil {
		log.Println("Error jsoning the trust store", err)
		return
	}

	err = os.WriteFile(ts.Filepath, data, 0644)
	if err != nil {
		log.Println("Error writing the trust store", err)
	}
}

func (ts *TrustStore) AddContact(peerName, fingerprint string) {
	prev := []string{}
	entry, ok := ts.Trusted[peerName]
	if ok {
		// Ok we're updating then
		prev = append(entry.PreviousFingerprints, entry.Fingerprint)
	}
	// Add entry and save
	ts.Trusted[peerName] = TrustEntry{
		Fingerprint:          fingerprint,
		PreviousFingerprints: prev,
	}
	ts.save()
}

func (ts *TrustStore) RemoveContact(peerName string) {
	// Remove entry and save
	_, ok := ts.Trusted[peerName]
	if ok {
		delete(ts.Trusted, peerName)
		ts.save()
	}
}

func (ts *TrustStore) CanTrust(peerName, fingerprint string) bool {
	return ts.GetFingerprint(peerName) == fingerprint
}

func (ts *TrustStore) GetFingerprint(peerName string) string {
	entry, ok := ts.Trusted[peerName]
	if !ok {
		return ""
	}
	return entry.Fingerprint
}

func (ts *TrustStore) RotateContactKey(peerName, newFingerprint string) {
	// Get current fingerprint
	current, ok := ts.Trusted[peerName]

	// If fingerprint doesn't exist add contact
	if !ok {
		ts.AddContact(peerName, newFingerprint)
		return
	}

	// Push old one into prev
	oldFingerprint := current.Fingerprint
	prev := current.PreviousFingerprints
	prev = append(prev, oldFingerprint)

	// Modify entry and save
	ts.Trusted[peerName] = TrustEntry{
		Fingerprint:          newFingerprint,
		PreviousFingerprints: prev,
	}

	ts.save()
}

func (ts *TrustStore) ListContacts() map[string]string {
	// Make map of fingerprints
	result := make(map[string]string)

	for peerName, entry := range ts.Trusted {
		result[peerName] = entry.Fingerprint
	}
	return result
}
