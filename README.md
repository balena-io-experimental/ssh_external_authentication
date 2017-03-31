Remoting the SSH Key Exchange and the Public Key Authentication from an ssh server to a webservice.

# Warning

So far this is just a proof of concept and should not be used in any public service!

# Usage

Run `prepare.sh` to setup test keys.

The command: `go run main.go -cmd auth -sec "SUPER_SECRET_API_KEY" -ak "tmp/testClientKey.pub" -prk "tmp/testServerKey" -l "127.0.0.1:8080"` will start a simple webserver listening on port 8080, that will perform the acutal key exchange and authentication.

The command: `go run -a main.go -cmd ssh -url "http://127.0.0.1:8080" -sec "SUPER_SECRET_API_KEY" -pk "tmp/testServerKey.pub.go" -l "127.0.0.1:2200"` will start the ssh server that, uses the authentication server started with the command above.

With the command: `ssh localhost -p 2200 -i tmp/testClientKey` one can then log into the local computer through this ssh server.

# Description

During the KeyExchange the authentication server performs a DH operation and calculates the shared secret between the server and the client. The first created shared secret is the session id. The authentication server hands out the required cryptographic primitives to the ssh server and a JWE token, containing the session id.
During the authentication phase this token is again provided to the authentication server, because as proof of possession of the private key, the client uses the private key to sign some information including the session id. Therefore the token binds the key exchange operation to the acutal authentication. 