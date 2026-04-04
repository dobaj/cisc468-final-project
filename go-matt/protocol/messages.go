package protocol

import (
	"encoding/hex"
	"encoding/json"
	"log"

	"github.com/dobaj/cisc468-final-project/sharing"
)

// import json

// from protocol.message_types import (
//     DATA,
//     ERROR,
//     FILE_CHUNK,
//     FILE_LIST_REQUEST,
//     FILE_LIST_RESPONSE,
//     FILE_OFFER,
//     FILE_OFFER_RESPONSE,
//     FILE_REQUEST,
//     HELLO,
//     KEY_EXCHANGE,
//     KEY_MIGRATION,
// )

// def key_exchange(pub_hex: str):
//     return {
//         "type": KEY_EXCHANGE,
//         "pub": pub_hex,
//     }

// func hello(name string, identity_pub_hex string, fingerprint string) (hello_msg){

//     return hello_msg {
//         Type: HELLO,
//         Name: name,
//         Identity_Pub: identity_pub_hex,
//         Fingerprint: fingerprint,
//     }
// }

func Key_Exchange(pub []byte) []byte {
	pub_hex := hex.EncodeToString(pub)
	key := Key_Exch_Msg{KEY_EXCHANGE, pub_hex}

	msg, err := json.Marshal(key)
	if err != nil {
		log.Panicln("Error encoding public key")
		return []byte{}
	}

	return msg
}

func Hello(name string, identity_pub []byte, fingerprint []byte) []byte {
	pub_hex := hex.EncodeToString([]byte(identity_pub))
	fingerprint_hex := hex.EncodeToString([]byte(fingerprint))
	key := Hello_Msg{HELLO, name, pub_hex, fingerprint_hex}

	msg, err := json.Marshal(key)
	if err != nil {
		log.Panicln("Error encoding public key")
		return []byte{}
	}

	return msg
}

func DataMessage(nonce []byte, payload []byte) []byte {
	nonceHex := hex.EncodeToString(nonce)
	payloadHex := hex.EncodeToString(payload)

	msg, err := json.Marshal(Data_Msg{DATA, nonceHex, payloadHex})
	if err != nil {
		log.Panicln("Something went wrong", err)
		return []byte{}
	}
	return msg
}

func FileListRequest() []byte {
	msg, err := json.Marshal(Msg{FILE_LIST_REQUEST})
	if err != nil {
		log.Panicln("Something went wrong", err)
		return []byte{}
	}

	return msg
}

func FileListResponse(records []*sharing.FileRecord) []byte {
	msg, err := json.Marshal(File_List_Res_Msg{FILE_LIST_RESPONSE, records})
	if err != nil {
		log.Panicln("Something went wrong", err)
		return []byte{}
	}

	return msg
}

func FileRequest(filename string) []byte {
    msg, err := json.Marshal(File_Req_Msg{FILE_REQUEST, filename})
	if err != nil {
		log.Panicln("Something went wrong", err)
		return []byte{}
	}

	return msg
}

// def file_offer(filename: str, record: dict):
//     return {
//         "type": FILE_OFFER,
//         "filename": filename,
//         "record": record,
//     }

// def file_offer_response(filename: str, accepted: bool, message: str = ""):
//     return {
//         "type": FILE_OFFER_RESPONSE,
//         "filename": filename,
//         "accepted": accepted,
//         "message": message,
//     }

func FileChunk(filename string, data []byte, record *sharing.FileRecord, done bool) []byte {
    dataHex := hex.EncodeToString(data)

    msg, err := json.Marshal(File_Chunk_Msg{
        Type: FILE_CHUNK,
        Filename: filename,
        Data: dataHex,
        Record: record,
        Done: done,
    })
	if err != nil {
		log.Panicln("Something went wrong", err)
		return []byte{}
	}

	return msg
}

// def key_migration(new_pub: str, old_sig: str, new_sig: str):
//     return {
//         "type": KEY_MIGRATION,
//         "new_pub": new_pub,
//         "old_sig": old_sig,
//         "new_sig": new_sig,
//     }

func ErrorMessage(message string) []byte {
    msg, err := json.Marshal(Error_Msg{ERROR, message})
	if err != nil {
		log.Panicln("Something went wrong", err)
		return []byte{}
	}

	return msg
}

// def encode_payload(message: dict) -> bytes:
//     return json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")

// def decode_payload(payload: bytes) -> dict:
//     return json.loads(payload.decode("utf-8"))
