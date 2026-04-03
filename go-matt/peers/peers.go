package peers

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/dobaj/cisc468-final-project/connect"
	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/discovery"
	"github.com/dobaj/cisc468-final-project/protocol"
	"github.com/dobaj/cisc468-final-project/trust"
)

func PeerConnect(peer discovery.Peer, i *crypt.Identity, trustedStore *trust.TrustStore) (error) {
	// Resolve and dial address given
	tcpAddr, err := net.ResolveTCPAddr("tcp", peer.Ip+":"+fmt.Sprint(peer.Port))
	if err != nil {
		log.Println("Error resolving:", err)
		return errors.New("Error resolving")
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Println("Error dialing:", err)
		return errors.New("Error resolving")
	}

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
	// other_key_bytes, err := hex.DecodeString(other_key.Pub)
	// if err != nil {
	// 	log.Println("Error unpacking response:", err)
	// 	return errors.New("Error unpacking response")
	// }

	// secret, err := crypto.CompSecret(k, other_key_bytes)	
	// shared_key := crypto.DeriveKey(secret)

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

	return nil
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