package main

import (
	"flag"
	"log"
	"os"

	"github.com/resin-io-playground/ssh_external_authentication/sshserver"
	"github.com/resin-io-playground/ssh_external_authentication/auth"
)

var commandFlag = flag.String("cmd", "", "Command to execute [ssh, sshck, auth]")
var serviceURLFlag = flag.String("url", "", "Authentication Service URL")
var serviceSecretFlag = flag.String("sec", "", "Authentication Service APIKEY")
var publicKeyFlag = flag.String("pk", "", "Public Key file")
var privateKeyFlag = flag.String("prk", "", "Private Key file")
var authorizedKeysFlag = flag.String("ak", "", "Authorized Keys")
var listenAddr = flag.String("l", "", "Listening Addr")

//func init() {
//	flag.StringVar(commandFlag, "cmd", "", "Command to run");
//}

func main() {
	flag.Parse()
	tail := flag.Args()

	switch *commandFlag {
	case "test":
		log.Printf("Running test command!\n")
		break
	case "sshck":
		log.Printf("Running sshck command!\n")

		if len(tail) <= 1 {
			log.Println("No files given")
			os.Exit(0)
		}

		sshserver.RunConvertKey(tail[0], tail[1])

		break
	case "ssh":
		log.Printf("Running ssh server\n")

		sshserver.RunSSHServer(*serviceURLFlag, *serviceSecretFlag,
			*publicKeyFlag, *listenAddr)

		break
	case "auth":
		log.Printf("Running auth server\n")

		auth.RunAuthServer(*authorizedKeysFlag, *serviceSecretFlag, *privateKeyFlag,
			*listenAddr)

		break
	default:
		log.Printf("Unkown command!\n")
		flag.PrintDefaults();

	}
}
