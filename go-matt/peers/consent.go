package peers

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func RequestConsent(peerName, action, filename string) bool {
	reader := bufio.NewReader(os.Stdin)
	
	var prompt string
	switch action {
		case "send":
			prompt = fmt.Sprintf("%s wants to send you '%s'. Allow? (y/n): ", peerName, filename)
		case "request":
			prompt = fmt.Sprintf("%s is requesting file '%s'. Allow? (y/n): ", peerName, filename)
		case "trust":
			prompt = fmt.Sprintf("Trust peer '%s' with fingerprint %s? (y/n): ", peerName, filename)
		default:
			prompt = fmt.Sprintf("%s wants to %s. Allow? (y/n): ", peerName, action)
	}

	for {
		fmt.Print(prompt)

		input, err := reader.ReadString('\n')
		if err != nil {
			// Just go with no worst case
			log.Println("Error reading input:", err)
			return false
		}

		response := strings.TrimSpace(strings.ToLower(input))

		if response == "y" || response == "yes" {
			return true
		}
		if response == "n" || response == "no" {
			return false
		}

		fmt.Println("Please enter 'y' or 'n'.")
	}
}