package peers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/dobaj/cisc468-final-project/connect"
	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/discovery"
	"github.com/dobaj/cisc468-final-project/protocol"
)

func PeerConnect(peer discovery.Peer, i *crypt.Identity) (error) {
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

	println(string(bytes), )
	return nil
}