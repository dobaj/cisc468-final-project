package protocol

import (
	"encoding/hex"
	"encoding/json"
	"log"
)

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

func FileListResponse(records []*FileRecord) []byte {
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

func FileChunk(filename string, data []byte, record *FileRecord, done bool) []byte {
	dataHex := hex.EncodeToString(data)

	msg, err := json.Marshal(File_Chunk_Msg{
		Type:     FILE_CHUNK,
		Filename: filename,
		Data:     dataHex,
		Record:   record,
		Done:     done,
	})
	if err != nil {
		log.Panicln("Something went wrong", err)
		return []byte{}
	}

	return msg
}

func KeyMigration(newpub []byte, oldsig []byte, newsig []byte) []byte {
	newPubHex := hex.EncodeToString(newpub)
	oldSigHex := hex.EncodeToString(oldsig)
	newSigHex := hex.EncodeToString(newsig)

	msg, err := json.Marshal(Key_Migration_Msg{KEY_MIGRATION, newPubHex, oldSigHex, newSigHex})
	if err != nil {
		log.Panicln("Something went wrong", err)
		return []byte{}
	}

	return msg
}

func ErrorMessage(message string) []byte {
	msg, err := json.Marshal(Error_Msg{ERROR, message})
	if err != nil {
		log.Panicln("Something went wrong", err)
		return []byte{}
	}

	return msg
}
