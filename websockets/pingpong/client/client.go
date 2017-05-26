package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

var server = flag.String("server", "localhost:80", "server address")

func main() {
    flag.Parse()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	// Create log file and logger.
	logFile, err := os.Create("ping.log")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ping.log")
		os.Exit(1)
	}
	defer logFile.Close()
	log := log.New(logFile, "", log.Lmicroseconds)

	url := url.URL {
		Scheme: "ws",
		Host: *server,
		Path: "/pingpong",
	}
	log.Printf("Making connection to: %s", url.String())

	conn, _, err := websocket.DefaultDialer.Dial(url.String(), nil)
	if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to dial: %s. %s\n", url.String(), err)
		log.Printf("Failed to dial: %s. %s", url.String(), err)
        os.Exit(1)
	}
	defer conn.Close()

	done := make(chan struct{})

	// This Goroutine is our read/write loop. It keeps going until it cannot use the WebSocket anymore.
	go func() {
		defer conn.Close()
		defer close(done)

		for {
			log.Println("Sending: ping.")
			err = conn.WriteMessage(websocket.TextMessage, []byte("ping"))
			if err != nil {
				log.Println("Write Error: ", err)
				break
			}

			msgType, bytes, err := conn.ReadMessage()
			if err != nil {
				log.Println("WebSocket closed.")
				return
			}
			// We don't recognize any message that is not "pong".
			if msg := string(bytes[:]); msgType != websocket.TextMessage && msg != "pong" {
				log.Println("Unrecognized message received.")
				continue
			} else {
				log.Println("Received: pong.")
			}

			time.Sleep(5 * time.Second)
		}
	}()

	for {
		select {
		// Block until interrupted. Then send the close message to the server and wait for our other read/write Goroutine
		// to signal 'done'. This is how you safely terminate a WebSocket connection.
		case <-interrupt:
			log.Println("Client interrupted.")
			err = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("WebSocket Close Error: ", err)
			}
			// Wait for 'done' or one second to pass.
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		// WebSocket has terminated before interrupt.
		case <-done:
			log.Println("WebSocket connection terminated.")
			return
		}
	}
}
