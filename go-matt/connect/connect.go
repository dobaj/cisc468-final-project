package connect

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)


const maxMessageSize = 10 * 1024 * 1024 // 10 MB

func WriteMessage(conn net.Conn, data []byte) error {
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

func ReadMessage(conn net.Conn) ([]byte, error) {
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