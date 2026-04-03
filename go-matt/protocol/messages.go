package protocol

import (
	"encoding/hex"
	"encoding/json"
	"log"
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


func Key_Exchange(pub []byte) ([]byte) {
    pub_hex := hex.EncodeToString(pub)
    key := Key_Exch_Msg{KEY_EXCHANGE, pub_hex}

    msg, err := json.Marshal(key)
    if err != nil {
        log.Panicln("Error encoding public key")
        return []byte{}
    }

    return msg
}

func Hello(name string, identity_pub []byte, fingerprint []byte) ([]byte) {
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

// def data_message(nonce_hex: str, payload_hex: str):
//     return {
//         "type": DATA,
//         "nonce": nonce_hex,
//         "payload": payload_hex,
//     }


// def file_list_request():
//     return {"type": FILE_LIST_REQUEST}


// def file_list_response(files: list):
//     return {
//         "type": FILE_LIST_RESPONSE,
//         "files": files,
//     }


// def file_request(filename: str):
//     return {
//         "type": FILE_REQUEST,
//         "filename": filename,
//     }


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


// def file_chunk(filename: str, data_hex: str, record: dict, done: bool = True):
//     return {
//         "type": FILE_CHUNK,
//         "filename": filename,
//         "data": data_hex,
//         "record": record,
//         "done": done,
//     }


// def key_migration(new_pub: str, old_sig: str, new_sig: str):
//     return {
//         "type": KEY_MIGRATION,
//         "new_pub": new_pub,
//         "old_sig": old_sig,
//         "new_sig": new_sig,
//     }


// def error_message(message: str):
//     return {
//         "type": ERROR,
//         "message": message,
//     }


// def encode_payload(message: dict) -> bytes:
//     return json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")


// def decode_payload(payload: bytes) -> dict:
//     return json.loads(payload.decode("utf-8"))