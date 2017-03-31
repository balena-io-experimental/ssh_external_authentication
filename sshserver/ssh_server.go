package sshserver

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"os"

	"github.com/kr/pty"
	"github.com/resin-io-playground/go-crypto-fork/ssh"
)

func dummyAuthKeyHandler() func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {

	handler := func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, errors.New("Unauthorized")
	}
	return handler
}

type RemoteAuth struct {
	ServiceURL  string
	SuperSecret string
}

func (auth *RemoteAuth) Request(authRequest *ssh.AuthRequest) (*ssh.AuthResponse, error) {
	url := auth.ServiceURL + "/auth"

	jsonStr, err := json.Marshal(authRequest)

	log.Printf("Sending auth request: %v", string(jsonStr))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Authorization", "ApiKey "+auth.SuperSecret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	log.Println("Requesting Auth from server")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	log.Println("Got auth response from server")

	if resp.StatusCode != 200 {

		log.Printf("Response %v", resp.StatusCode)

		return nil, errors.New(resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	var t ssh.AuthResponse
	err = decoder.Decode(&t)

	return &t, nil
}

type RemoteKex struct {
	ServiceURL  string
	SuperSecret string
}

func (kex *RemoteKex) Request(kexRequest *ssh.KexRemoteRequest) (*ssh.KexRemoteResponse, error) {
	url := kex.ServiceURL + "/kex"

	jsonStr, err := json.Marshal(kexRequest)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Authorization", "ApiKey "+kex.SuperSecret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	log.Println("Requesting KEX from server")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	log.Println("Got KEX from server")
	decoder := json.NewDecoder(resp.Body)
	var t ssh.KexRemoteResponse
	err = decoder.Decode(&t)

	return &t, nil
}

// RunConvertKey Converts a given ssh public key to a go public key format
func RunConvertKey(sourceFile string, destinationFile string) {
	log.Println("Converting public key")

	log.Printf("Converting file %v to %v\n", sourceFile, destinationFile)

	privateKeyBytes, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		log.Fatalf("Failed to load private key (%v): %v\n", sourceFile, err)
	}

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key (%v): %v\n", sourceFile, err)
	}

	err = ioutil.WriteFile(destinationFile, signer.PublicKey().Marshal(), 0664)

	if err != nil {
		log.Fatalf("Failed to write public key (%v): %v\n", destinationFile, err)
	}

	os.Exit(0)
}

// RunSSHServer runs the ssh server
func RunSSHServer(serviceURL string, serviceSecret string, publicKeyFile string, bindingAddress string) {

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: dummyAuthKeyHandler(),
		PublicKeyRemoteAuth: &RemoteAuth{
			ServiceURL:  serviceURL,
			SuperSecret: serviceSecret,
		},
		Config: ssh.Config{
			RemoteKexService: &RemoteKex{
				ServiceURL:  serviceURL,
				SuperSecret: serviceSecret,
			},
		},
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	publicKeyBytes, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		log.Fatalf("Failed to load public key (%v)\n", publicKeyFile)
	}

	//signer, _ := ssh.ParsePrivateKey(publicKeyBytes)
	//ioutil.WriteFile("id_rsa.pub.go", signer.PublicKey().Marshal(), 0664)

	public, err := ssh.ParsePublicKey(publicKeyBytes)
	if err != nil {
		log.Fatal("Failed to parse public key\n", err)
	}

	signer, err := ssh.NewDummySignerFromPublicKey(public)

	sshConfig.AddHostKey(signer)

	listeningAddr, err := net.ResolveTCPAddr("tcp", bindingAddress)

	if err != nil {
		log.Fatalf("Listen on address %v\n", bindingAddress)
	}

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", bindingAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %v (%s)\n", listeningAddr.Port, err)
	}

	// Accept all connections
	log.Printf("Listening on %v...\n", listeningAddr.Port)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)\n", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			log.Printf("Failed to handshake (%s)\n", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)\n", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Fire up bash for this session
	bash := exec.Command("bash")

	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		}
		log.Printf("Session closed")
	}

	// Allocate a terminal for this channel
	log.Print("Creating pty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		close()
		return
	}

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
