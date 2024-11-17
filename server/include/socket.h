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

#ifndef SOCKET_H
#define SOCKET_H

#define DEFAULT_PUBLIC_KEY_SOCKET "/tmp/key"
#define DEFAULT_SIGNING_SOCKET "/tmp/sign"
#define MAX_MESSAGE_LENGTH 10485760
#define MAX_SIGNATURE_LENGTH 256
#define MAX_KEY_LENGTH 256
#define MAX_CLIENTS 5

/*
 * Serves the signing service's public key in a streaming fashion to
 * any clients. Will only serve [MAX_CLIENTS] clients at any given time.
 *
 * socket_path: The unix domain socket to serve on.
 * key_file:    Path to the key file.
 *
 * returns:     0 on success. Any other value is an error code.
 */
int serve_public_key(const char* socket_path, const char* key_file);

/*
 * Signs a message that is written to the streaming socket and writes
 * back the signature on the same socket. Will only serve [MAX_CLIENTS]
 * clients at any given time.
 *
 * socket_path: The unix domain socket to serve on.
 * key_file:    Path to the key file.
 *
 * returns:     0 on success. Any other value is an error code.
 */
int serve_signing_service(const char* socket_path, const char* key_file);

#endif
