package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"strings"

	// "github.com/dobaj/cisc468-final-project/crypto"
	"github.com/dobaj/cisc468-final-project/commands"
	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/discovery"
	"github.com/dobaj/cisc468-final-project/peers"
	"github.com/dobaj/cisc468-final-project/protocol"
	"github.com/dobaj/cisc468-final-project/sharing"
	"github.com/dobaj/cisc468-final-project/trust"
)

// type messageFormat struct {
//     Type   string      `json:"type"`
//     Message string `json:"message"`
// }

func listen(listener net.Listener, i *crypt.Identity, trustedStore *trust.TrustStore, activeMap map[string]*protocol.ActivePeer, file_manager *sharing.FileManager) {
	// Server side of app
	defer listener.Close()

	for {

		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting conn:", err)
			continue
		}
		// peer discovery.Peer, i *crypt.Identity, trustedStore *trust.TrustStore, activeMap map[string]*protocol.ActivePeer, file_manager *sharing.FileManager
		go peers.PeerConnect(conn, i, trustedStore, activeMap, file_manager, true)
	}
}

func login() (name string, pass string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter name: ")
	name, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("Error parsing name:", err)
	}
	name = strings.TrimSpace(name)

	fmt.Println("Enter password: ")
	pass, err = reader.ReadString('\n')
	if err != nil {
		log.Fatal("Error parsing name:", err)
	}
	pass = strings.TrimSpace(pass)

	return name, pass
}

func openTCP() (listener net.Listener, port int) {
	listener, err := net.Listen("tcp4", ":"+fmt.Sprint(protocol.DEFAULT_PORT))

	if err != nil {
		// Try random port, maybe the other one was busy
		listener, err = net.Listen("tcp4", ":0")
	}
	if err != nil {
		log.Fatal("Error listening:", err)
	}

	addr := strings.SplitAfter(listener.Addr().String(), ":")
	port, err = strconv.Atoi(addr[len(addr)-1])
	if err != nil {
		log.Fatal("Error parsing port:", err)
	}
	return listener, port
}

func main() {
	listener, port := openTCP()
	var name, password string
	var i *crypt.Identity
	for {
		name, password = login()

		var err error
		i = &crypt.Identity{Name: name, Password: password, Base_dir: "./data/", Priv_key: nil, Pub_key: nil, Identity_dir: "", Priv_key_path: ""}
		i, err = crypt.Load_or_create(i)
		if err == nil {
			// Success!
			break
		}
	}

	// Load files
	trustedStore := trust.NewTrustStore("data/" + name + "/truststore.json")
	var activeMap map[string]*protocol.ActivePeer
	activeMap = make(map[string]*protocol.ActivePeer)
	file_manager := sharing.NewFileManager("data/" + name + "/shared")

	// mDNS
	go discovery.Init(name, port)
	go discovery.Listen()

	go listen(listener, i, trustedStore, activeMap, file_manager)
	// go sendMessage()
	var blockSync sync.WaitGroup
	blockSync.Go(func() {
		commands.CommandLoop(i, trustedStore, activeMap, file_manager)
	})
	blockSync.Wait()

	// Shut off mDNS
	discovery.Shutdown()
}
