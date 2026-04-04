package commands

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/discovery"
	"github.com/dobaj/cisc468-final-project/peers"
	"github.com/dobaj/cisc468-final-project/protocol"
	"github.com/dobaj/cisc468-final-project/sharing"
	"github.com/dobaj/cisc468-final-project/trust"
)

func CommandLoop(identity *crypt.Identity, trustedStore *trust.TrustStore, activeMap map[string]*protocol.ActivePeer, file_manager *sharing.FileManager) {
	for {
		reader := bufio.NewReader(os.Stdin)
		print("> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if strings.HasPrefix(input, "peers") {
			if len(discovery.Peers) == 0 {
				println("No peers")
			}
			for key := range discovery.Peers {
				peer := discovery.Peers[key]
				fmt.Printf("%s -> %s:%d\n", peer.Name, peer.Ip, peer.Port)
			}
			continue
		}

		if strings.HasPrefix(input, "connect") {
			// grab peer name
			peerName := strings.Split(input, " ")[1]
			peer := discovery.Peers[peerName]

			// Resolve and dial address given
			tcpAddr, err := net.ResolveTCPAddr("tcp", peer.Ip+":"+fmt.Sprint(peer.Port))
			if err != nil {
				log.Println("Error resolving:", err)
				continue
			}
			conn, err := net.DialTCP("tcp", nil, tcpAddr)
			if err != nil {
				log.Println("Error dialing:", err)
				continue
			}

			go peers.PeerConnect(conn, identity, trustedStore, activeMap, file_manager, false)
			continue
		}

		if strings.HasPrefix(input, "list") {
			peerName := strings.Split(input, " ")[1]
			peer, ok := activeMap[peerName]
			if !ok {
				println("Not connected to that peer")
				continue
			}
			peers.Send(peer, protocol.FileListRequest())
			continue
		}

		if strings.HasPrefix(input, "request ") {
			parts := strings.Fields(input)
			if len(parts) < 3 {
				fmt.Println("Usage: request <peer> <filename>")
				continue
			}

			peerName := parts[1]
			filename := parts[2]

			connection, ok := activeMap[peerName]
			if !ok {
				println("Not connected to that peer")
				continue
			}

			// Create file request message
			reqMsg := protocol.FileRequest(filename)

			// Send it securely over the connection
			peers.Send(connection, reqMsg)
			continue
		}

		if strings.HasPrefix(input, "contacts") {
			contacts := trustedStore.ListContacts()
			
			if len(contacts) == 0 {
				println("No contacts")
			} else {
				for peerName, fingerprint := range contacts {
					fmt.Printf("%s (%s)\n", peerName, fingerprint)
				}
			}
			
			continue
		}

		if input == "exit" {
			println("Goodbye!")
			break
		}

		printHelp()

	}
}

func printHelp() {
	help := []string{
		"Usage:",
		"View list of peers:   peers",
		"Connect to peer:      connect [peer name]",
		"View files from peer: list [peer name]",
	}
	for line := range help {
		println(help[line])
	}

}
