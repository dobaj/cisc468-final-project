package peers

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/dobaj/cisc468-final-project/connect"
	"github.com/dobaj/cisc468-final-project/crypto"
	"github.com/dobaj/cisc468-final-project/discovery"
	"github.com/dobaj/cisc468-final-project/protocol"
)

func PeerConnect(peer discovery.Peer, i *crypto.Identity) (error) {
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

	k := &crypto.Key{}
	k = crypto.GenerateKey(k)

	connect.WriteMessage(conn, protocol.Key_Exchange(k.Pub_key.Bytes()))
	
	bytes, err := connect.ReadMessage(conn)
	println(bytes)
	return nil
}