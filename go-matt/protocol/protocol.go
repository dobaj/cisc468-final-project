package protocol

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

type Hello_Msg struct {
    Type string `json:"type"`
	Name string `json:"name"`
	Identity_Pub string `json:"identity_pub"`
	Fingerprint string `json:"fingerprint"`
}

type Key_Exch_Msg struct {
    Type string `json:"type"`
	Pub string `json:"pub"`
}
