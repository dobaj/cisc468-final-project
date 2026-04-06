package commands

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/discovery"
	"github.com/dobaj/cisc468-final-project/peers"
	"github.com/dobaj/cisc468-final-project/protocol"
	"github.com/dobaj/cisc468-final-project/sharing"
	"github.com/dobaj/cisc468-final-project/storage"
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
		case input := <-InputChan:
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
			<-cmd.Done

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

func CommandLoop(identity *crypt.Identity, trustedStore *trust.TrustStore, activeMap map[string]*protocol.ActivePeer, file_manager *sharing.FileManager, storeStore *storage.StoreStore) {
	var command Command
	ok := false
	for {
		if ok != false {
			command.Done <- true
		}
		command, ok = <-CommandChan
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
				println("peer not found!")
				continue
			}
			conn, err := net.DialTCP("tcp", nil, tcpAddr)
			if err != nil {
				println("peer not found!")
				continue
			}

			go peers.PeerConnect(conn, identity, trustedStore, activeMap, file_manager, storeStore, false)
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
			filename := input[strings.Index(input, peerName)+len(peerName)+1:]
			filename = strings.TrimSpace(filename)

			// Remove quotes if there
			if (strings.HasPrefix(filename, "\"") && strings.HasSuffix(filename, "\"")) ||
				(strings.HasPrefix(filename, "'") && strings.HasSuffix(filename, "'")) {
				unquoted, err := strconv.Unquote(filename)
				if err != nil {
					log.Println("Invalid quoted filename")
					continue
				}
				filename = unquoted
			}

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

		if strings.HasPrefix(input, "stored") {
			files := storeStore.ListFiles()

			if len(files) == 0 {
				println("No enc files stored")
			} else {
				for _, file := range files {
					fmt.Printf("%s \n", file)
				}
			}

			continue
		}

		if strings.HasPrefix(input, "decrypt") {
			filename := strings.TrimSpace(input[len("decrypt"):])
			if filename == "" {
				println("Usage: decrypt <filename>")
				continue
			}

			// Remove quotes if there
			if (strings.HasPrefix(filename, "\"") && strings.HasSuffix(filename, "\"")) ||
				(strings.HasPrefix(filename, "'") && strings.HasSuffix(filename, "'")) {
				unquoted, err := strconv.Unquote(filename)
				if err != nil {
					log.Println("Invalid quoted filename")
					continue
				}
				filename = unquoted
			}

			bytes, partial, err := storeStore.GetFile(filename)
			if err != nil {
				log.Println("Something went wrong decrypting file")
				continue
			}

			file, err := file_manager.SaveFile(partial, bytes)
			if err != nil {
				log.Println("Something went wrong saving file")
				continue
			}

			println("Saved '" + filename + "' at '" + file + "' in shared folder")

			continue
		}

		if strings.HasPrefix(input, "migrate") {
			oldPriv, oldPub := identity.Priv_key, identity.Pub_key
			crypt.RotateKey(identity)
			oldSig := crypt.SignWithKey(oldPriv, identity.Pub_key)
			newSig := crypt.Sign(identity, oldPub)
			msg := protocol.KeyMigration(identity.Pub_key, oldSig, newSig)

			// Send to everyone
			for _, peer := range activeMap {
				peers.Send(peer, msg)
				println("Sent new key to", peer.Name)
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
		"View encrypted files:   stored",
		"Decrypt and save file:  decrypt [filename]",
		"Migrate to new keys:    migrate",
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
