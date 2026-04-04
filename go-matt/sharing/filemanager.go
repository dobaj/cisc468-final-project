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
	Owner     string `json:"owner"`
	OwnerPub  string `json:"owner_pub"`
	Filename  string `json:"filename"`
	Sha256    string `json:"sha256"`
	Size      int    `json:"size"`
	Signature string `json:"signature"`
}

type PartialFileRecord struct {
	// Used to make signature
	Filename string `json:"filename"`
	Owner    string `json:"owner"`
	Sha256   string `json:"sha256"`
	Size     int    `json:"size"`
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

func (fm *FileManager) Verify(record *FileRecord, data []byte) bool {
	expected := hex.EncodeToString(fm.HashBytes(data))
	if expected != record.Sha256 {
		log.Println("File hash doesn't match")
		return false
	}

	partial := fm.RecordForSignature(record.Owner, record.Filename, record.Sha256, record.Size)
	pub_key, err := hex.DecodeString(record.OwnerPub)
	if err != nil {
		log.Println("Error unpacking public key")
		return false
	}
	signature, err := hex.DecodeString(record.Signature)
	if err != nil {
		log.Println("Error unpacking signature")
		return false
	}

	err = crypt.Verify(pub_key, signature, partial)
	if err != nil {
		log.Println("Verification failed")
		return false
	}
	if len(data) != record.Size {
		log.Println("Data size does not match")
		return false
	}

	return true
}

func (fm *FileManager) VerifyAndSave(record *FileRecord, data []byte) bool {
	if fm.Verify(record, data) != false {
		fm.SaveFile(record.Filename, data)
		return true
	}
	return false
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
		Owner:     identity.Name,
		OwnerPub:  hex.EncodeToString(identity.Pub_key),
		Filename:  filename,
		Sha256:    sha256Hash,
		Size:      len(data),
		Signature: hex.EncodeToString(signature),
	}
	return record
}

func (fm *FileManager) RecordForSignature(owner, filename, sha256 string, size int) []byte {
	payload := PartialFileRecord{
		Filename: filename,
		Owner:    owner,
		Sha256:   sha256,
		Size:     size,
	}

	payloadData, err := json.Marshal(payload)
	if err != nil {
		log.Fatal("Error creating record payload:", err)
	}

	return payloadData
}

func (fm *FileManager) GetFile(filename string, identity *crypt.Identity) ([]byte, *FileRecord, error) {
	data, err := fm.ReadFile(filename)
	if err != nil {
		log.Println("Error reading file", err)
		return nil, nil, err
	}
	
	record, err := fm.BuildFileRecord(filename, identity)
	if err != nil {
		log.Println("Error building record", err)
		return nil, nil, err
	}
	return data, record, nil
}

func (fm *FileManager) HashBytes(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (fm *FileManager) MetadataPath(filename string) string {
	return filepath.Join(fm.dir, fmt.Sprintf("%s.meta.json", filename))
}
