package discovery

import (
	"context"
	"fmt"
	"log"

	"github.com/dobaj/cisc468-final-project/protocol"
	"github.com/grandcat/zeroconf"
)

type Peer struct {
    ip string
    port int
}

var server *zeroconf.Server // So we can shut it down manually later
var listenContext context.Context
var cancel context.CancelFunc

var hostName string
var peers map[string]Peer

func Init(name string, port int) {
	var err error
	hostName = name

	// Not sure what those strings do but they were in the zeroconf example code
	server, err = zeroconf.Register(name, protocol.SERVICE_TYPE, "local.", port, []string{"txtv=0", "lo=1", "la=2"}, nil)
	if err != nil {
		panic(err)
	}

	log.Println("mDNS registered ("+"localhost:"+fmt.Sprint(port)+")")
}

func Listen() {
	peers = make(map[string]Peer)

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
				_, ok := peers[entry.Instance]
				if !ok { 
					log.Println("Discovered:", entry.Instance, "("+entry.AddrIPv4[0].String()+":"+fmt.Sprint(entry.Port)+")")
				}
				peers[entry.Instance] = Peer{entry.AddrIPv4[0].String(), entry.Port}
			}
		}
	}(entries)

	listenContext, cancel = context.WithCancel(context.Background())

	err = resolver.Browse(listenContext, protocol.SERVICE_TYPE, "local.", entries)
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}
}

func Shutdown() {
	// Shut down mDNS server and listener
	server.Shutdown()
	<-listenContext.Done()
	cancel()
}