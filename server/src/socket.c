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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../include/socket.h"
#include "../include/signing.h"

/*
 * Opens a new streaming unix domain socket at the given path. If the path
 * doesn't exist, it will be created. Only [MAX_CLIENTS] number of clients
 * will be accepted at any given time. Any further simultaneous client
 * connection attempts will be denied.
 *
 * path:    The desired path to the socket file descriptor.
 *
 * return:  The socket handle. Int greater than 0 on success, -1 on failure.
 */
int open_socket(const char* path) {
    int sock;
    struct sockaddr_un server;

    unlink(path);
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
        printf("Error opening public key socket, leaving \n");
        return -1;
    }

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, path);
    if (bind(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)))
    {
        printf("Error binding to public key socket, leaving \n");
        return -1;
    }

    printf("Successfully opened %s, observing connections... \n", path);
    listen(sock, MAX_CLIENTS);

    return sock;
}

/*
 * Serves the public key that can be used to verify signatures of
 * messages that has been signed by this service.
 *
 * socket_path: The socket to serve the public key on.
 * key_file:    Path to the key file to extract the public key from.
 *
 * returns:     0 on success. Any other value is an error code.
 */
int serve_public_key(const char* socket_path, const char* key_file)
{
    uint8_t* key;
    size_t key_len;
    int sock, conn;

    sock = open_socket(socket_path);
    if (sock == -1)
    {
        printf("Error opening socket, aborting");
        return -1;
    }

    key = malloc(MAX_KEY_LENGTH);
    if (!get_public_key(key_file, key, &key_len))
    {
        printf("Error caching public key, aborting");
        free(key);
        return -1;
    }

    for (;;)
    {
        conn = accept(sock, 0, 0);
        if (conn == -1)
        {
            printf("Error opening connection, skipping");
            continue;
        }

        if (write(conn, key, key_len) == -1)
            printf("Failed serving public key \n");
        else
            printf("Successfully served public key \n");

        close(conn);
    }

    free(key);
    close(sock);
    unlink(socket_path);
    printf("Successfully closed public key socket");

    return 0;
}

/*
 * Signs a message that is written to the given socket and writes back
 * the signature on the same socket.
 *
 * socket_path: The socket to read from and write to.
 * key_file:    Path to the key file to sign with.
 *
 * returns:     0 on success. Any other value is an error code.
 */
int serve_signing_service(const char* socket_path, const char* key_file)
{
    uint8_t* msg;
    uint8_t* sig;
    size_t msg_len, sig_len;
    int sock, conn;

    sock = open_socket(socket_path);
    if (sock == -1)
    {
        printf("Error opening socket, aborting");
        return -1;
    }

    msg_len = MAX_MESSAGE_LENGTH;
    msg = malloc(MAX_MESSAGE_LENGTH);
    sig = malloc(MAX_SIGNATURE_LENGTH);

    for (;;)
    {
        conn = accept(sock, 0, 0);
        if (conn == -1)
        {
            printf("Error opening connection, skipping");
            continue;
        }

        msg_len = read(conn, msg, MAX_MESSAGE_LENGTH);
        if (sign_message(key_file, msg, msg_len, sig, &sig_len) == 0)
            printf("Failed signing message \n");
        else if (write(conn, sig, sig_len) == -1)
            printf("Failed sending signature \n");
        else
            printf("Successfully signed message \n");

        close(conn);
    }

    free(msg);
    free(sig);
    close(sock);
    unlink(socket_path);
    printf("Successfully closed signing socket");

    return 0;
}
