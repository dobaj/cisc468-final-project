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

type Command struct {
	Input string
	Done  chan bool
}

var CommandChan = make(chan Command)
var InputChan = make(chan string)

func UserInput() {
	var pendingRequests *peers.ConsentRequest

	for {
		select {
		case input := <- InputChan:
			if pendingRequests != nil {
				// We're answering a consent prompt
				resp := strings.ToLower(input)
				switch resp {
					case "y", "yes":
						pendingRequests.Response <- true
					case "n", "no":
						pendingRequests.Response <- false
					default:
						fmt.Println("Please enter y/n")
						continue
				}
				// Okay we got answer if we made it here
				pendingRequests = nil
				continue
			}

			// Otherwise normal command
			cmd := Command{
				Input: input,
				Done:  make(chan bool),
			}
			CommandChan <- cmd

			// Wait for finish
			<- cmd.Done

		// Check for incoming request
		case req := <-peers.ConsentChan:
			pendingRequests = &req
			printConsentPrompt(req)
		}
	}
}

func ReadInput() {
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		InputChan <- strings.TrimSpace(input)
	}
}

func CommandLoop(identity *crypt.Identity, trustedStore *trust.TrustStore, activeMap map[string]*protocol.ActivePeer, file_manager *sharing.FileManager) {
	var command Command
	ok := false
	for {
		if ok != false {
			command.Done <- true
		}
		command, ok = <- CommandChan
		input := command.Input

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
			fields := strings.Fields(input)
			if len(fields) < 2 {
				printHelp()
				continue
			}
			// grab peer name
			peerName := fields[1]
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
			fields := strings.Fields(input)
			if len(fields) < 2 {
				printHelp()
				continue
			}
			// grab peer name
			peerName := fields[1]
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
		"View list of peers:     peers",
		"Connect to peer:        connect [peer name]",
		"View files from peer:   list [peer name]",
		"Request file from peer: request [peer name] [filename]",
	}
	for line := range help {
		println(help[line])
	}

}

func printConsentPrompt(req peers.ConsentRequest) {
	var prompt string
	switch req.Action {
	case "send":
		prompt = fmt.Sprintf("%s wants to send you '%s'. Allow? (y/n): ", req.PeerName, req.Filename)
	case "request":
		prompt = fmt.Sprintf("%s is requesting file '%s'. Allow? (y/n): ", req.PeerName, req.Filename)
	case "trust":
		prompt = fmt.Sprintf("Trust peer '%s' with fingerprint %s? (y/n): ", req.PeerName, req.Filename)
	default:
		prompt = fmt.Sprintf("%s wants to %s. Allow? (y/n): ", req.PeerName, req.Action)
	}

	fmt.Print(prompt)
}