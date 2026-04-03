package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"strings"

	// "github.com/dobaj/cisc468-final-project/crypto"
	"github.com/dobaj/cisc468-final-project/commands"
	"github.com/dobaj/cisc468-final-project/connect"
	"github.com/dobaj/cisc468-final-project/crypt"
	"github.com/dobaj/cisc468-final-project/discovery"
	"github.com/dobaj/cisc468-final-project/protocol"
)

// type messageFormat struct {
//     Type   string      `json:"type"`
//     Message string `json:"message"`
// }

func sendMessage() {
	// Client side of app
	for {
        reader := bufio.NewReader(os.Stdin)
        fmt.Println("\nEnter peer's addr: ")
        input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		// Resolve and dial address given
		tcpAddr, err := net.ResolveTCPAddr("tcp", input)
		if err != nil {
			log.Println("Error resolving:", err)
			continue
    	}
		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			log.Println("Error dialing:", err)
			continue
		}

		fmt.Println("Enter message: ")
		data, _ := reader.ReadString('\n')
		// TODO make this not trim spaces we want to keep
		data = strings.TrimSpace(data)

		message := "{\"type\": \"MESSAGE\", \"message\": \""+data+"\"}"

		err = connect.WriteMessage(conn, []byte(message))
		if err != nil {
			log.Println("Error writing to peer:", err)
			continue
		}

		log.Println("Sending :", message)

		response, err := connect.ReadMessage(conn)
		if err != nil {
			log.Println("Error receiving from peer:", err)
			continue
		}

		log.Println("Recieved :", string(response))

		conn.Close()
    }
}

func listen(listener net.Listener) {
	// Server side of app
	defer listener.Close()

	for {

        conn, err := listener.Accept()
        if err != nil {
            log.Println("Error accepting conn:", err)
            continue
        }

        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
	// Handle incoming client
    defer conn.Close()

    message, err := connect.ReadMessage(conn)
    if err != nil {
        log.Printf("Read error: %v", err)
        return
    }
	messageStr := string(message)

	// Unpack json
    var res map[string]interface{}
    json.Unmarshal([]byte(messageStr), &res)

    if res["type"] == "MESSAGE" {
		log.Println("Recieved message:", res["message"])
	}

	// Return ack for now
    ackMsg := fmt.Sprintf("ACK: %s", strings.TrimSpace(messageStr))
	err = connect.WriteMessage(conn, []byte(ackMsg))
    if err != nil {
        log.Printf("Error sending response: %v", err)
    }
}

func login() (name string, pass string){
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

	addr := strings.SplitAfter(listener.Addr().String(),":")
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
	
	// mDNS
	go discovery.Init(name, port)
	go discovery.Listen()

	go listen(listener)
	// go sendMessage() 
	var blockSync sync.WaitGroup
	blockSync.Go(func () {
		commands.CommandLoop(i)
	} )
    blockSync.Wait()

	// Shut off mDNS
	discovery.Shutdown()
}