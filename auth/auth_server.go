package auth

import (
	"bufio"
	"crypto/md5"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"

	"net"

	"github.com/afitzek/crypto/ssh"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var encryptionKey []byte

var authorizedKeys []ssh.PublicKey

var apiKey string

var privateSSHKeyFile string

func checkAPIAccess(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("authorization") == "ApiKey "+apiKey {
		return nil
	}

	return errors.New("Unauthorized")
}

func authhandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Got Auth request")

	if err := checkAPIAccess(w, r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var t ssh.AuthRequest
	err := decoder.Decode(&t)

	if err != nil {
		log.Printf("Failed to parse request! %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong request"))
		return
	}

	keyHandler := func(user string, key ssh.PublicKey) (*ssh.Permissions, error) {
		h := md5.New()
		h.Write(key.Marshal())
		fp := fmt.Sprintf("%x", h.Sum(nil))

		log.Printf("Authentication %v via key: %v\n", user, fp)

		for _, authKey := range authorizedKeys {
			log.Printf("AuthKey: %v, Key: %v", authKey, key)
			if subtle.ConstantTimeCompare(authKey.Marshal(), key.Marshal()) == 1 {
				log.Printf("Success!")
				return nil, nil
			}
		}

		return nil, errors.New("Unauthorised")
	}

	log.Printf("Provided token: %v", t.KexToken)

	tok, err := jwt.ParseEncrypted(t.KexToken)

	if err != nil {
		log.Printf("Failed to parse encrypted Token! %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid KEX Token"))
		return
	}

	out := jwt.Claims{}

	if err := tok.Claims(encryptionKey, &out); err != nil {
		log.Printf("Failed to decrypted Token! %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid KEX Token"))
		return
	}

	log.Printf("Got sessionID: %v", out.Subject)
	sessionID, err := base64.StdEncoding.DecodeString(out.Subject)

	clientAddr, err := net.ResolveTCPAddr("tcp", t.RemoteAddr)

	if err != nil {
		log.Fatal(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	log.Printf("Client IP: %v", clientAddr.IP)

	perms, cont, packet, err := ssh.ValidatePublicKey(t.Packet, t.User, clientAddr, sessionID, keyHandler)

	respError := ""
	if err != nil {
		log.Printf("Validation: %v\n", err)
		respError = err.Error()
	}

	resp := &ssh.AuthResponse{
		Cont:     cont,
		KexToken: t.KexToken,
		Packet:   packet,
		Perm:     perms,
		Err:      respError,
	}

	jresp, err := json.Marshal(resp)

	if err != nil {
		log.Fatal("Marshal failed")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong request"))
		return
	}

	//fmt.Println("Sending KEX response: ", jresp)
	w.WriteHeader(http.StatusOK)
	w.Write(jresp)
}

func kexhandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Got KEX request")

	if err := checkAPIAccess(w, r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var t ssh.KexRemoteRequest
	err := decoder.Decode(&t)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong request"))
		return
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile(privateSSHKeyFile)
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong request"))
		return
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong request"))
		return
	}

	kexRemote := ssh.NewKexRemoteBackend(t.KexAlgo, private)

	resp, err := kexRemote.Request(&t)

	if err != nil {
		log.Fatal("Failed to perform kex")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong request"))
		return
	}

	sessionIDString := base64.StdEncoding.EncodeToString(resp.Result.H)

	log.Println("SSH KEX done: sessionID: ", sessionIDString)

	// TODO: create a signed JWT token
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: encryptionKey}, nil)

	if err != nil {
		log.Fatal("Failed to create encrypter")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong request"))
		return
	}

	cl := jwt.Claims{
		Subject: sessionIDString,
		Issuer:  "ThisServer ...",
	}

	raw, err := jwt.Encrypted(encrypter).Claims(cl).CompactSerialize()

	if err != nil {
		log.Fatal("Failed to create encrypted JWT")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong request"))
		return
	}

	resp.AuthToken = raw

	log.Printf("Handing out token: %s", raw)

	jresp, err := json.Marshal(resp)

	if err != nil {
		log.Fatal("Marshal failed")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Wrong request"))
		return
	}

	//fmt.Println("Sending KEX response: ", jresp)
	w.WriteHeader(http.StatusOK)
	w.Write(jresp)
}

// RunAuthServer runs an authentication server
func RunAuthServer(authorizedKeysFile string, localapiKey string, sshKeyFile string, bindingAddress string) {
	encryptionKey = make([]byte, 16)
	apiKey = localapiKey
	privateSSHKeyFile = sshKeyFile

	rand.Read(encryptionKey)

	log.Printf("%x", encryptionKey)

	authorizedKeys = make([]ssh.PublicKey, 0)

	file, err := os.Open(authorizedKeysFile)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
		if err != nil {
			log.Fatalln(err)
		}

		h := md5.New()
		h.Write(pubKey.Marshal())
		fp := fmt.Sprintf("%x", h.Sum(nil))

		log.Printf("Adding Authorized Key: %x", fp)

		authorizedKeys = append(authorizedKeys, pubKey)
	}

	log.Printf("Authorized Keys: %v\n", authorizedKeys)

	if err := scanner.Err(); err != nil {
		log.Fatalln(err)
	}

	http.HandleFunc("/kex", kexhandler)
	http.HandleFunc("/auth", authhandler)

	listeningAddr, err := net.ResolveTCPAddr("tcp", bindingAddress)

	if err != nil {
		log.Fatalf("Failed to parse bindingAddress %v\n", bindingAddress)
	}

	log.Printf("Auth Server listening on address %v\n", listeningAddr.Port)

	log.Fatal(http.ListenAndServe(bindingAddress, nil))
}
