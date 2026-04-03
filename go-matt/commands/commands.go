package commands

import (
	"bufio"
	"fmt"

	// "sync"

	// "fmt"
	"os"
	"strings"

	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/discovery"
	"github.com/dobaj/cisc468-final-project/peers"
	"github.com/dobaj/cisc468-final-project/trust"
)

func CommandLoop(identity *crypt.Identity, trustedStore *trust.TrustStore) {
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
			
			_ = peers.PeerConnect(peer, identity, trustedStore)
			continue
		}

		if input == "exit" {
			println("Goodbye!")
			break;
		}

		printHelp()
		
	}
}

func printHelp () {
	help := []string{
		"Usage:",
		"View list of peers: peers",
		"Connect to peer:    connect [peer name]",
	}
	for line := range(help) {
		println(help[line])
	}

}