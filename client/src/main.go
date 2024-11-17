/*
 *  MIT License
 *
 *  Copyright (c) 2024 Echsylon Digital Solutions AB
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/echsylon/go-args"
)

const (
	publicKeySocket      = "/tmp/key"
	signingSocket        = "/tmp/sign"
	defaultPublicKeyFile = "./public.pem"
	defaultSignatureFile = "./signature.bin"

	maxMessageLength = 4096
)

var (
	ErrConnection = errors.New("connection error")
	ErrSockWrite  = errors.New("socket write error")
	ErrSockRead   = errors.New("socket read error")
	ErrFileWrite  = errors.New("file write error")
	ErrFileRead   = errors.New("file read error")
)

func main() {
	args.SetApplicationDescription("A simple Signer Service consumer client.")
	args.DefineOptionHelp("h", "help", "Prints this help text.")
	args.DefineOption("p", "Output file for public key, default "+defaultPublicKeyFile)
	args.DefineOption("s", "Output file for signature, default "+defaultSignatureFile)
	args.DefineArgument("FILE", "File to sign")

	args.Parse()

	input := normalizePath(args.GetArgumentValues("FILE")[0])
	publicKey := normalizePath(args.GetOptionValue("p", defaultPublicKeyFile))
	signature := normalizePath(args.GetOptionValue("s", defaultSignatureFile))

	if err := getPublicKey(publicKeySocket, publicKey); err != nil {
		os.Exit(1)
	}

	if err := getInputSignature(signingSocket, input, signature); err != nil {
		os.Exit(1)
	}

	fmt.Printf("The file '%[1]s' has been signed successfully. You can verify it by: \n\n"+
		"openssl pkeyutl \\ \n"+
		"    -verify -pubin -inkey %[3]s \\ \n"+
		"    -rawin -in %[1]s \\ \n"+
		"    -sigfile %[2]s \n\n",
		input, signature, publicKey)
}

func getPublicKey(socketFile string, publicKeyFile string) error {
	// Connect to the signer service's public key socket...
	conn, err := net.Dial("unix", socketFile)
	if err != nil {
		fmt.Printf("Couldn't connect to public key socket (make sure the signer is up and running): %s \n", err)
		return errors.Join(ErrConnection, err)
	}

	defer conn.Close()

	// ...read the public key byte array...
	buffer := make([]byte, 4096)
	count, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("Couldn't read from public key socket: %s \n", err)
		return errors.Join(ErrSockRead, err)
	}

	// ... and write it to the given file.
	err = os.WriteFile(publicKeyFile, buffer[:count], 0666)
	if err != nil {
		fmt.Printf("Couldn't save public key to %s: %s \n", publicKeyFile, err)
		return errors.Join(ErrFileWrite, err)
	}

	return nil
}

func getInputSignature(socketFile string, inputFile string, signatureFile string) error {
	// Connect to the signer service's sign socket...
	conn, err := net.Dial("unix", socketFile)
	if err != nil {
		fmt.Printf("Couldn't connect to signing socket (make sure the signer is up and running): %s \n", err)
		return errors.Join(ErrConnection, err)
	}

	defer conn.Close()

	// Read user input to sign...
	buffer, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Couldn't read %s: %s \n", inputFile, err)
		return errors.Join(ErrFileRead, err)
	}

	// ...send it to the signing service...
	count, err := conn.Write(buffer)
	if err != nil || count != len(buffer) {
		fmt.Printf("Couldn't write to signing socket: %s \n", err)
		return errors.Join(ErrSockWrite, err)
	}

	// ..read the signature response...
	buffer = make([]byte, maxMessageLength)
	count, err = conn.Read(buffer)
	if err != nil {
		fmt.Printf("Couldn't read signature from signing socket: %s \n", err)
		return errors.Join(ErrSockRead, err)
	}

	// ...and write it to the given file.
	err = os.WriteFile(signatureFile, buffer[:count], 0644)
	if err != nil {
		fmt.Printf("Couldn't save signature to %s: %s \n", signatureFile, err)
		return errors.Join(ErrFileWrite, err)
	}

	return nil
}

func normalizePath(file string) string {
	if filepath.IsAbs(file) {
		return file
	}

	proc, err := os.Executable()
	if err != nil {
		return file
	}

	base := filepath.Dir(proc)
	normal := filepath.Join(base, file)
	parent := filepath.Dir(normal)

	err = os.MkdirAll(parent, 0755)
	if err != nil {
		return file
	}

	return normal
}
