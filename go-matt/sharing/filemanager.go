package sharing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dobaj/cisc468-final-project/crypt"
)

type FileManager struct {
	dir string
}

type FileRecord struct {
	Owner        string    `json:"owner"`
	OwnerPub     string    `json:"owner_pub"`
	Filename     string    `json:"filename"`
	Sha256       string    `json:"sha256"`
	Size         int       `json:"size"`
	Signature    string    `json:"signature"`
}

type PartialFileRecord struct {
	// Used to make signature
	Owner        string    `json:"owner"`
	Filename     string    `json:"filename"`
	Sha256       string    `json:"sha256"`
	Size         int       `json:"size"`
}

func NewFileManager(directory string) *FileManager {
	dir := filepath.Join(directory)
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create directory: ", err)
	}

	return &FileManager{dir: dir}
}

func (fm *FileManager) ListFiles() []string {
	var files []string

	err := filepath.Walk(fm.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Add only files to array
		if !info.IsDir() && !strings.HasSuffix(info.Name(), ".meta.json") {
			files = append(files, info.Name())
		}
		return nil
	})
	if err != nil {
		log.Fatal("Error listing files:", err)
	}

	sort.Strings(files)
	return files
}

func (fm *FileManager) GetFilePath(filename string) string {
	return filepath.Join(fm.dir, filename)
}

func (fm *FileManager) ReadFile(filename string) ([]byte, error) {
	filePath := fm.GetFilePath(filename)
	return os.ReadFile(filePath)
}

func (fm *FileManager) SaveFile(filename string, data []byte) error {
	filePath := fm.GetFilePath(filename)
	return os.WriteFile(filePath, data, 0644)
}

func (fm *FileManager) HashFile(filename string) (string, error) {
	data, err := fm.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(fm.HashBytes(data)), nil
}

func (fm *FileManager) BuildFileRecord(filename string, identity *crypt.Identity) (*FileRecord, error) {
	data, err := fm.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return fm.BuildRecordFromFileBytes(filename, data, identity), nil
}

func (fm *FileManager) BuildRecordFromFileBytes(filename string, data []byte, identity *crypt.Identity) *FileRecord {
	sha256Hash := hex.EncodeToString(fm.HashBytes(data))
	payload := fm.RecordForSignature(identity.Name, filename, sha256Hash, len(data))
	signature := crypt.Sign(identity, payload)

	record := &FileRecord{
		Owner:        identity.Name,
		OwnerPub:    hex.EncodeToString(identity.Pub_key),
		Filename:     filename,
		Sha256:       sha256Hash,
		Size:         len(data),
		Signature:    hex.EncodeToString(signature),
	}
	return record
}

func (fm *FileManager) RecordForSignature(owner, filename, sha256 string, size int) []byte {
	payload := map[string]interface{}{
		"filename": filename,
		"owner":    owner,
		"sha256":   sha256,
		"size":     size,
	}

	payloadData, err := json.Marshal(payload)
	if err != nil {
		log.Fatal("Error creating record payload:", err)
	}

	return payloadData
}

func (fm *FileManager) HashBytes(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (fm *FileManager) MetadataPath(filename string) string {
	return filepath.Join(fm.dir, fmt.Sprintf("%s.meta.json", filename))
}