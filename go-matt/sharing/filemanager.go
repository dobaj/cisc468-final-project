package sharing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/protocol"
	"github.com/dobaj/cisc468-final-project/storage"
)

type FileManager struct {
	dir string
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

func (fm *FileManager) WriteFile(filename string, data []byte) (string, error) {
	// First make sure we aren't overwriting a file
	ext := filepath.Ext(filename)
	name := filename[:len(filename)-len(ext)]
	newName := filename
	filePath := fm.GetFilePath(newName)

	counter := 1
	for {
		if !storage.FileExists(filePath) {
			// File doesn't exist
			break
		} else {
			// File exists, create a new filename and test it
			newName = fmt.Sprintf("%s(%d)%s", name, counter, ext)
			filePath = fm.GetFilePath(newName)
			counter++
		}
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", err
	}

	return newName, nil
}

func (fm *FileManager) HashFile(filename string) (string, error) {
	data, err := fm.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(fm.HashBytes(data)), nil
}

func (fm *FileManager) Verify(record *protocol.FileRecord, data []byte) bool {
	expected := hex.EncodeToString(fm.HashBytes(data))
	if expected != record.Sha256 {
		log.Println("File hash doesn't match")
		return false
	}

	partial := RecordForSignature(record.Owner, record.Filename, record.Sha256, record.Size)
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

func (fm *FileManager) VerifyAndSave(record *protocol.FileRecord, data []byte) (string, error) {
	if fm.Verify(record, data) != false {
		file, err := fm.SaveFileWithRecord(record, data)
		return file, err
	}
	return "", errors.New("Failed verification")
}

func (fm *FileManager) BuildFileRecord(filename string, identity *crypt.Identity) (*protocol.FileRecord, error) {

	data, err := fm.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	record := fm.BuildRecordFromFileBytes(filename, data, identity)

	partial, err := fm.ReadMetadata(filename)
	if err != nil {
		// No metadata lets just leave
		return record, nil
	}
	if partial.Sha256 == record.Sha256 {
		// This is the same file (hopefully!)
		// Use original owner and resign
		record.Owner = partial.Owner
		record = fm.SignRecord(record, identity)
	}

	return record, nil
}

func (fm *FileManager) BuildRecordFromFileBytes(filename string, data []byte, identity *crypt.Identity) *protocol.FileRecord {
	sha256Hash := hex.EncodeToString(fm.HashBytes(data))
	payload := RecordForSignature(identity.Name, filename, sha256Hash, len(data))
	signature := crypt.Sign(identity, payload)

	record := &protocol.FileRecord{
		Owner:     identity.Name,
		OwnerPub:  hex.EncodeToString(identity.Pub_key),
		Filename:  filename,
		Sha256:    sha256Hash,
		Size:      len(data),
		Signature: hex.EncodeToString(signature),
	}
	return record
}

func (fm *FileManager) SignRecord(record *protocol.FileRecord, identity *crypt.Identity) *protocol.FileRecord {
	payload := RecordForSignature(record.Owner, record.Filename, record.Sha256, record.Size)
	signature := crypt.Sign(identity, payload)

	record.Signature = hex.EncodeToString(signature)
	return record
}

func RecordForSignature(owner, filename, sha256 string, size int) []byte {
	payload := protocol.PartialFileRecord{
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

func (fm *FileManager) GetFile(filename string, identity *crypt.Identity) ([]byte, *protocol.FileRecord, error) {
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

func (fm *FileManager) SaveFileWithRecord(record *protocol.FileRecord, data []byte) (string, error) {
	// rebuild a partial record
	partial := protocol.PartialFileRecord{
		Filename: record.Filename,
		Owner:    record.Owner,
		Sha256:   record.Sha256,
		Size:     record.Size,
	}
	return fm.SaveFile(&partial, data)
}

func (fm *FileManager) SaveFile(record *protocol.PartialFileRecord, data []byte) (string, error) {
	// Save the actual file
	savedName, err := fm.WriteFile(record.Filename, data)
	if err != nil {
		return "", err
	}

	// rebuild a partial record
	partial := protocol.PartialFileRecord{
		Filename: savedName,
		Owner:    record.Owner,
		Sha256:   record.Sha256,
		Size:     record.Size,
	}

	// Save metadata as .meta.json
	metaPath := fm.GetFilePath(savedName + ".meta.json")
	metaData, err := json.MarshalIndent(partial, "", "  ")
	if err != nil {
		return "", fmt.Errorf("Failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metaPath, metaData, 0644); err != nil {
		return "", fmt.Errorf("Failed to write metadata file: %w", err)
	}

	return savedName, nil
}

func (fm *FileManager) ReadMetadata(filename string) (*protocol.PartialFileRecord, error) {
	metaPath := fm.GetFilePath(filename + ".meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var partial protocol.PartialFileRecord
	if err := json.Unmarshal(data, &partial); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &partial, nil
}
