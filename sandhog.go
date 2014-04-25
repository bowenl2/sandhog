package main

import (
	"code.google.com/p/go.crypto/ssh"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
)

var (
	logger *log.Logger
)

type SandhogClientKeyring struct {
	key *rsa.PrivateKey
}

func LoadKeyring(keyPath string) (*SandhogClientKeyring, error) {
	// Read the key material
	privateKeyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	// Decode the key material
	block, _ := pem.Decode(privateKeyPEM)

	// Parse the key
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Could not parse the key from the decoded PEM
		return nil, err
	}

	keyring := &SandhogClientKeyring{rsaKey}

	// Everything turned out fine!
	return keyring, nil
}

func (keyring *SandhogClientKeyring) Key(i int) (ssh.PublicKey, error) {
	// Only support one key
	if i != 0 {
		return nil, nil
	}

	// Wrap the RSA public key in the SSH package's PublicKey wrapper
	publicKey, err := ssh.NewPublicKey(keyring.key.PublicKey)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func (keyring *SandhogClientKeyring) Sign(i int, rand io.Reader, data []byte) (sig []byte, err error) {
	// Only support one key
	if i != 0 {
		return nil, nil
	}

	hashImpl := crypto.SHA1
	hashFunc := hashImpl.New()
	hashFunc.Write(data)
	digest := hashFunc.Sum(nil)
	return rsa.SignPKCS1v15(rand, keyring.key, hashImpl, digest)
}

func loadConfig() (*configStruct, error) {
	var config configStruct

	flag.IntVar(&config.localPort, "local-port", 0, "Local port on which to listen to forward from remote")
	flag.IntVar(&config.remotePort, "remote-port", 0, "Remote port on which to listen to forward to local")
	flag.StringVar(&config.keyPath, "key", "", "Path to id_rsa")
	flag.StringVar(&config.remoteHost, "host", "", "Remote host to forward data from")

	flag.Parse()

	if config.localPort == 0 {
		return nil, configError{"Local port must be specified"}
	}
	if config.remotePort == 0 {
		return nil, configError{"Remote port must be specified"}
	}
	if config.keyPath == "" {
		return nil, configError{"Key path must be specified"}
	}
	if config.remoteHost == "" {
		return nil, configError{"Remote host must be specified"}
	}

	return &config, nil
}

type configError struct {
	errorString string
}

func (e configError) Error() string {
	return e.errorString
}

type configStruct struct {
	keyPath    string
	localPort  int
	remotePort int
	remoteHost string
}

func printUsage() {
	fmt.Println("usage: sandhog -key <id_rsa> -local-port <port> -remote-port <port> -host <remote-host>")
}

func handleConn(remoteConn net.Conn, configData configStruct) {
	// TODO Create local connection
	localDestination := fmt.Sprintf("127.0.0.1:%d", configData.localPort)
	logger.Printf("making connection from %s to %s\n", remoteConn, localDestination)

	// Read/write forever

}

func main() {
	logger = log.New(os.Stdout, "wam: ", log.LstdFlags|log.Lshortfile)
	logger.Println("sandhog")

	configData, err := loadConfig()
	if err != nil {
		printUsage()
		logger.Fatalln(err)
	}

	keyring, err := LoadKeyring(configData.keyPath)
	if err != nil {
		logger.Fatalln(err)
	}
	logger.Printf("loaded keyring: %s", keyring)

	sshConfig := &ssh.ClientConfig{
		User: "wam",
		Auth: []ssh.ClientAuth{
			ssh.ClientAuthKeyring(keyring),
		},
	}
	logger.Printf("created SSH client config: %s", sshConfig)

	// Dial your ssh server.
	logger.Println("connecting")
	conn, err := ssh.Dial("tcp", "localhost:22", sshConfig)
	if err != nil {
		logger.Fatalf("unable to connect: %s\n", err)
	}
	defer conn.Close()
	logger.Println("connected!")

	// Request the remote side to open port 8080 on all interfaces.
	// When they
	remoteListenEndpoint := fmt.Sprintf("127.0.0.1:%d", configData.remotePort)
	logger.Printf("requesting remote host listen on: %s\n", remoteListenEndpoint)
	listener, err := conn.Listen("tcp", remoteListenEndpoint)
	if err != nil {
		log.Fatalf("unable to register tcp forward: %s", err)
	}
	defer listener.Close()

	logger.Printf("remote host listening on %s\n", remoteListenEndpoint)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Println(err)
			break
		}
		go handleConn(conn, configData)
	}
	// Serve HTTP with your SSH server acting as a reverse proxy.
	http.Serve(listener, http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(resp, "Hello world!\n")
	}))
}
