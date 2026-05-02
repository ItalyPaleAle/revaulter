package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
)

// This app starts a minimal SSH server for E2E tests
func main() {
	listenAddr := flag.String("listen", "127.0.0.1:0", "TCP listen address")
	authorizedKeyFile := flag.String("authorized-key-file", "", "Path to an authorized_keys entry")
	message := flag.String("message", "hello from revaulter ssh e2e\n", "Message written to the SSH client")
	flag.Parse()

	if *authorizedKeyFile == "" {
		_, _ = fmt.Fprintln(os.Stderr, "missing required --authorized-key-file")
		os.Exit(2)
	}

	authorizedKey, err := loadAuthorizedKey(*authorizedKeyFile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "load authorized key: %v\n", err)
		os.Exit(1)
	}

	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "generate host key: %v\n", err)
		os.Exit(1)
	}

	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create host signer: %v\n", err)
		os.Exit(1)
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), authorizedKey.Marshal()) {
				return nil, nil
			}

			return nil, errors.New("unauthorized key")
		},
	}
	serverConfig.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("READY %s\n", listener.Addr().String())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	go func() {
		<-signals
		_ = listener.Close()
	}()

	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}

		go handleConn(conn, serverConfig, *message)
	}
}

func loadAuthorizedKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func handleConn(conn net.Conn, serverConfig *ssh.ServerConfig, message string) {
	defer conn.Close()

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		return
	}
	defer serverConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, requests, acceptErr := newChannel.Accept()
		if acceptErr != nil {
			continue
		}

		go handleSession(channel, requests, message)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, message string) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "exec", "shell":
			err := req.Reply(true, nil)
			if err != nil {
				return
			}

			_, _ = io.WriteString(channel, message)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
			return
		case "env", "pty-req":
			err := req.Reply(true, nil)
			if err != nil {
				return
			}
		default:
			err := req.Reply(false, nil)
			if err != nil {
				return
			}
		}
	}
}
