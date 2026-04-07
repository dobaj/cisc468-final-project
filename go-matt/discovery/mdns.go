package discovery

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dobaj/cisc468-final-project/protocol"
	"github.com/grandcat/zeroconf"
)

type Peer struct {
    Name string
	Ip string
    Port int
}

var server *zeroconf.Server // So we can shut it down manually later
var listenContext context.Context
var cancel context.CancelFunc

var hostName string
var Peers map[string]Peer

func Init(name string, port int) {
	var err error
	hostName = name

	// Not sure what those strings do but they were in the zeroconf example code
	server, err = zeroconf.Register(name, protocol.SERVICE_TYPE, "local.", port, []string{"txtv=0", "lo=1", "la=2"}, nil)
	if err != nil {
		panic(err)
	}

	log.Println("mDNS registered ("+"localhost:"+fmt.Sprint(port)+")")
	for {
		server.Shutdown()
		server, err = zeroconf.Register(name, protocol.SERVICE_TYPE, "local.", port, []string{"txtv=0", "lo=1", "la=2"}, nil)
		if err != nil {
			log.Fatalln("Failed to browse:", err.Error())
		}
        time.Sleep(5 * time.Second) // Reregister to aggressively announce
    }
}

func Listen() {
	Peers = make(map[string]Peer)

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatalln("Failed to initialize resolver:", err.Error())
	}

	entries := make(chan *zeroconf.ServiceEntry)
	// This will run as we get new entries
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			// Ignore ourselves and previously discovered people
			if (entry.Instance != hostName) {
				_, ok := Peers[entry.Instance]
				if !ok { 
					log.Println("Discovered:", entry.Instance, "("+entry.AddrIPv4[0].String()+":"+fmt.Sprint(entry.Port)+")")
				}
				Peers[entry.Instance] = Peer{entry.Instance, entry.AddrIPv4[0].String(), entry.Port}
			}
		}
	}(entries)

	listenContext, cancel = context.WithCancel(context.Background())

	for {
        err = resolver.Browse(listenContext, protocol.SERVICE_TYPE, "local.", entries)
		if err != nil {
			log.Fatalln("Failed to browse:", err.Error())
		}
        time.Sleep(5 * time.Second) // Rebrowse to aggressively discover
    }
}

func Shutdown() {
	// Shut down mDNS server and listener
	server.Shutdown()
	cancel()
}