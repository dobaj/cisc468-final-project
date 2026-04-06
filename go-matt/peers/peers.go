package peers

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/dobaj/cisc468-final-project/connect"
	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/protocol"
	"github.com/dobaj/cisc468-final-project/sharing"
	"github.com/dobaj/cisc468-final-project/storage"
	"github.com/dobaj/cisc468-final-project/trust"
)

func PeerConnect(conn net.Conn, i *crypt.Identity, trustedStore *trust.TrustStore, activeMap map[string]*protocol.ActivePeer, file_manager *sharing.FileManager, storeStore *storage.StoreStore, incoming bool) error {

	defer conn.Close()

	k := &crypt.Key{}
	k = crypt.GenerateKey(k)

	connect.WriteMessage(conn, protocol.Key_Exchange(k.Pub_key.Bytes()))

	bytes, err := connect.ReadMessage(conn)
	if err != nil {
		log.Println("Error reading message:", err)
		return errors.New("Error reading message")
	}
	var other_key protocol.Key_Exch_Msg
	err = json.Unmarshal(bytes, &other_key)
	if err != nil {
		log.Println("Error unpacking response:", err)
		return errors.New("Error unpacking response")
	}

	// Compute shared key
	other_key_bytes, err := hex.DecodeString(other_key.Pub)
	if err != nil {
		log.Println("Error unpacking response:", err)
		return errors.New("Error unpacking response")
	}

	secret, err := crypt.CompSecret(k, other_key_bytes)
	shared_key := crypt.DeriveKey(secret)

	// Send identity
	connect.WriteMessage(conn, protocol.Hello(i.Name, i.Pub_key, crypt.Fingerprint(i.Pub_key)))
	bytes, err = connect.ReadMessage(conn)
	if err != nil {
		log.Println("Error reading message:", err)
		return errors.New("Error reading message")
	}

	var other_hello protocol.Hello_Msg
	err = json.Unmarshal(bytes, &other_hello)
	if err != nil {
		log.Println("Error unpacking response:", err)
		return errors.New("Error unpacking response")
	}

	err = AuthenticatePeer(other_hello, trustedStore)
	if err != nil {
		log.Println("Error authenticating peer:", err)
		return errors.New("Error authenticating peer")
	}

	// Okay now that they are authenticated let user know
	if incoming {
		println("Incoming connection from '" + other_hello.Name + "'")
	}
	println("Authenticated with '" + other_hello.Name + "' (" + other_hello.Fingerprint[len(other_hello.Fingerprint)-16:] + ")")

	activePeer := protocol.ActivePeer{
		Name:        other_hello.Name,
		Sock:        conn,
		Cipher:      shared_key,
		Fingerprint: other_hello.Fingerprint,
		IdentityPub: other_hello.Identity_Pub}

	oldPeer, ok := activeMap[other_hello.Name]
	if ok {
		ClosePeer(oldPeer)
	}

	activeMap[other_hello.Name] = &activePeer

	for {
		// Read anything from peer
		bytes, err := connect.ReadMessage(conn)
		if err != nil {
			if strings.Contains(err.Error(), "forcibly closed") {
				log.Println("Peer forcibly closed connection")
				return err
			}
			// log.Println("Error receiving from peer", err)
			continue
		}

		// Just get the type field for now
		var msg protocol.Msg
		err = json.Unmarshal(bytes, &msg)
		if err != nil {
			log.Println("Error unpacking", err)
			continue
		}

		if msg.Type == protocol.DATA {
			// This is encrypted (to be expected!)
			var encData protocol.Data_Msg
			err = json.Unmarshal(bytes, &encData)
			if err != nil {
				log.Println("Error unpacking", err)
				continue
			}
			nonce, err := hex.DecodeString(encData.Nonce)
			if err != nil {
				log.Println("Error unpacking", err)
				continue
			}
			payload, err := hex.DecodeString(encData.Payload)
			if err != nil {
				log.Println("Error unpacking", err)
				continue
			}

			data, err := crypt.Decrypt(shared_key, nonce, payload)

			HandleMessage(&activePeer, data, file_manager, i, storeStore)
			continue
		}

		println(string(bytes))
	}
}

func AuthenticatePeer(msg protocol.Hello_Msg, trustStore *trust.TrustStore) error {
	peerName := msg.Name
	fingerprint := msg.Fingerprint
	identityPub := msg.Identity_Pub

	keyBytes, err := hex.DecodeString(identityPub)
	if err != nil {
		return errors.New("Error unpacking response")
	}

	// Derive fingerprint and verify
	derivedFingerprint := hex.EncodeToString(crypt.Fingerprint(keyBytes))
	if derivedFingerprint != fingerprint {
		return errors.New("Peer fingerprint does not match provided key")
	}

	// See if this also matches who we believe peer to be
	expected := trustStore.GetFingerprint(peerName)

	// Trust on first use
	if expected == "" {
		if !RequestConsent(peerName, "trust", fingerprint) {
			return errors.New("untrusted peer rejected by user")
		}

		// Ok we can trust
		trustStore.AddContact(peerName, fingerprint)
		fmt.Printf("Trusted new contact '%s'\n", peerName)
		return nil
	}

	// Not a new peer, check they are the same person
	if expected != fingerprint {
		return errors.New("fingerprint mismatch")
	}

	return nil
}

func HandleMessage(peer *protocol.ActivePeer, message []byte, file_manager *sharing.FileManager, identity *crypt.Identity, storeStore *storage.StoreStore) error {
	var msg protocol.Msg
	err := json.Unmarshal(message, &msg)
	if err != nil {
		log.Println("Error unpacking", err)
		return err
	}

	// Now let's see what kind of message it is
	if msg.Type == protocol.FILE_LIST_REQUEST {
		// Make list of records by iterating through each file
		records := make([]*sharing.FileRecord, 0)
		files := file_manager.ListFiles()
		for _, filename := range files {
			newRecord, err := file_manager.BuildFileRecord(filename, identity)
			if err != nil {
				log.Println("Error making record")
				continue
			}
			records = append(records, newRecord)
		}

		Send(peer, protocol.FileListResponse(records))
		return nil
	}
	if msg.Type == protocol.FILE_LIST_RESPONSE {
		// Lets unpack and see what we're working with!!
		var unpack protocol.File_List_Res_Msg
		err := json.Unmarshal(message, &unpack)
		if err != nil {
			log.Println("Error unpacking file list")
			return err
		}

		if len(unpack.Files) == 0 {
			println("No files available!")
			return nil
		}

		println("Files shared from " + peer.Name + ":")
		for _, record := range unpack.Files {
			println("    " + record.Filename + " (" + record.Sha256[len(record.Sha256)-16:] + ")")
		}
		print("> ")
		return nil
	}
	if msg.Type == protocol.FILE_REQUEST {
		var unpack protocol.File_Req_Msg
		err := json.Unmarshal(message, &unpack)
		if err != nil {
			log.Println("Error unpacking file request")
			return err
		}
		filename := unpack.Filename

		// Make sure this user approves
		if !RequestConsent(peer.Name, "request", filename) {
			Send(peer, protocol.ErrorMessage("File request rejected - "+filename))
			return nil
		}
		data, record, err := file_manager.GetFile(filename, identity)
		if err != nil {
			log.Println("Error reading")
			Send(peer, protocol.ErrorMessage("File not found or otherwise failed - "+filename))
			return err
		}

		// Okay now just send
		Send(peer, protocol.FileChunk(filename, data, record, true))
		println("Sent '" + filename + "' to " + peer.Name)
		return nil
	}
	if msg.Type == protocol.FILE_CHUNK {
		var unpack protocol.File_Chunk_Msg
		err := json.Unmarshal(message, &unpack)
		if err != nil {
			log.Println("Error unpacking file chunk")
			return err
		}
		filename := unpack.Filename
		data, err := hex.DecodeString(unpack.Data)
		if err != nil {
			log.Println("Error unpacking file chunk")
			return err
		}
		record := unpack.Record

		file, err := file_manager.VerifyAndSave(record, data)
		if err != nil {
			log.Println("Error saving file")
			return err
		}
		encfile, err := storeStore.SaveFile(filename, data)
		if err != nil {
			log.Println("Error saving file in encrypted store")
			return err
		}
		println("Received and verified '" + filename + "' from " + peer.Name)
		println("Saved at '" + file + "' in shared folder")
		println("Saved at '" + encfile + "' in encrypted store")
		return nil
	}

	println(string(message))
	return nil
}

func Send(peer *protocol.ActivePeer, bytes []byte) {
	nonce, ciphertext, err := crypt.Encrypt(peer.Cipher, bytes)
	if err != nil {
		log.Fatal("Something went wrong sending message", err)
	}
	connect.WriteMessage(peer.Sock, protocol.DataMessage(nonce, ciphertext))
}

func ClosePeer(peer *protocol.ActivePeer) {
	peer.Sock.Close()
}
