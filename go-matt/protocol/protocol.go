package protocol

import (
	"net"
)

const HKDF_INFO = "session key"
const SERVICE_TYPE = "_p2pfs._tcp."
const DEFAULT_PORT = 6767

// Message types
const KEY_EXCHANGE = "key_exchange"
const HELLO = "hello"
const DATA = "data"

const FILE_LIST_REQUEST = "file_list_request"
const FILE_LIST_RESPONSE = "file_list_response"
const FILE_REQUEST = "file_request"
const FILE_OFFER = "file_offer"
const FILE_OFFER_RESPONSE = "file_offer_response"
const FILE_CHUNK = "file_chunk"
const KEY_MIGRATION = "key_migration"
const ERROR = "error"

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

// Messages
type Hello_Msg struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Identity_Pub string `json:"identity_pub"`
	Fingerprint  string `json:"fingerprint"`
}

type Key_Exch_Msg struct {
	Type string `json:"type"`
	Pub  string `json:"pub"`
}

type Msg struct {
	Type string `json:"type"`
}

type Data_Msg struct {
	Type    string `json:"type"`
	Nonce   string `json:"nonce"`
	Payload string `json:"payload"`
}

type File_List_Res_Msg struct {
	Type  string        `json:"type"`
	Files []*FileRecord `json:"files"`
}

type File_Req_Msg struct {
	Type     string `json:"type"`
	Filename string `json:"filename"`
}

type File_Chunk_Msg struct {
	Type     string      `json:"type"`
	Filename string      `json:"filename"`
	Data     string      `json:"data"`
	Record   *FileRecord `json:"record"`
	Done     bool        `json:"done"`
}

type Key_Migration_Msg struct {
	Type   string `json:"type"`
	NewPub string `json:"new_pub"`
	OldSig string `json:"old_sig"`
	NewSig string `json:"new_sig"`
}

type Error_Msg struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Peer stuff
type ActivePeer struct {
	Name        string
	Sock        net.Conn
	Cipher      []byte
	Fingerprint string
	IdentityPub string
}
