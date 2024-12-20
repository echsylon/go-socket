# The Signer Service
This is an example of a Unix Domain Socket communication implementation.

The use case is a simple "signer" work flow, where there is a server that knows how to sign messages and a client that sends messages to sign to it. The server owns a private key which it uses for the signing process.

The server exposes its services through two streaming sockets. It offers a unidirectional socket on which it publishes its public key as soon as a client connects to it. The other socket is a bidirectional socket which the client first needs to send a message on. The server takes the message, signs it and finally sends back the signature, all on the same bidirectional socket.

There is a strict separation of concerns between the server and the client. The client doesn't know anything about cryptography or how to sign messages. It has neither compile time, nor runtime dependencies to the signing server implementation. It only knows how to read and write a socket.

## Building and launching the Signer Service
The Signer Service is written in C and the example code provides a `make` file for convenient building of the service artifacts. On a developer machine it should only be a matter of launching a new terminal window, navigating to the example projects root directory and then:

```bash
cd server
make
./out/signer
```

Would the `make` script fail for any reason, it might be due to missing dependencies which, on a fairly recent Debian based Linux machine, easily can be remedied by:

```bash
sudo apt install build-essentials libssl-dev
```

## Building and launching the Client

Similarly, building and launching the consuming client is done by launching another terminal window, navigating to the same root directory and:

```bash
cd client
make
./out/client
```

Starting the client without arguments will show you the help menu. At a minimum you need to provide a path argument, pointing at a file you wish to sign:

```bash 
./out/client ../../LICENSE
```

will sign the project `LICENSE` file. Once the client has finished executing it will present you with a suggestion on how to manually verify the signature.

## Doing it manually

The full signing process (what the client and server does together) can be repeated manually as well. Assuming your working directory is the root of the project root, it could look something like:

```bash
# extract public key
openssl pkey -in server/etc/ed25519_key.pem -pubout -out public.pem

# sign the LICENSE file, writing the signature to file
openssl pkeyutl -sign -inkey server/etc/ed25519_key.pem -out signature.bin -rawin -in LICENSE

# verify signature, expected output: Signature Verified Successfully
openssl pkeyutl -verify -pubin -inkey public.pem -rawin -in LICENSE -sigfile signature.bin

# clean up, because that's how momma raised us
rm public.pem signature.bin
```

