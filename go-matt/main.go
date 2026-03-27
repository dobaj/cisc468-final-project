package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"strings"

	// "github.com/dobaj/cisc468-final-project/crypto"
	"github.com/dobaj/cisc468-final-project/discovery"
	"github.com/dobaj/cisc468-final-project/protocol"
)

// type messageFormat struct {
//     Type   string      `json:"type"`
//     Message string `json:"message"`
// }

const maxMessageSize = 10 * 1024 * 1024 // 10 MB

func writeMessage(conn net.Conn, data []byte) error {
	if len(data) > maxMessageSize {
		return fmt.Errorf("message too large: %d bytes", len(data))
	}

	// Write len to header
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))

	// Send!!
	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	return nil
}

func readMessage(conn net.Conn) ([]byte, error) {
	// Get message length
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Check it's the right size
	size := binary.BigEndian.Uint32(header)
	if size > maxMessageSize {
		return nil, fmt.Errorf("message size %d exceeds limit", size)
	}

	// Read data
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

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

		err = writeMessage(conn, []byte(message))
		if err != nil {
			log.Println("Error writing to peer:", err)
			continue
		}

		log.Println("Sending :", message)

		response, err := readMessage(conn)
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

    message, err := readMessage(conn)
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
	err = writeMessage(conn, []byte(ackMsg))
    if err != nil {
        log.Printf("Error sending response: %v", err)
    }
}

func login() (name string){
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter name: ")
    name, err := reader.ReadString('\n')
	if err != nil {
        log.Fatal("Error parsing name:", err)
    }
	name = strings.TrimSpace(name)

	return name
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
	// i := identity.Identity{Name: "matt", Password: "pass", Base_dir: "./data/", Priv_key: nil,Pub_key: nil,Identity_dir: "./data/matt", Priv_key_path: ""}
    // i = *identity.Load_or_create(&i)
	
	
	listener, port := openTCP()
	name := login()
	
	go discovery.Init(name, port)
	go discovery.Listen()

	var blockSync sync.WaitGroup
	blockSync.Add(2)
	go listen(listener)
	go sendMessage() 
    blockSync.Wait()

	discovery.Shutdown()
}