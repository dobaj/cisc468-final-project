package peers

type ConsentRequest struct {
	PeerName string
	Action   string
	Filename string
	Response chan bool
}

var ConsentChan = make(chan ConsentRequest)

func RequestConsent(peerName, action, filename string) bool {
	// Send request back to the console (in commands file!!)
	req := ConsentRequest{
		PeerName: peerName,
		Action:   action,
		Filename: filename,
		Response: make(chan bool),
	}

	ConsentChan <- req

	// Wait for user decision
	return <-req.Response
}
