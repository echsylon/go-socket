#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/signing.h"
#include "../include/socket.h"
#include "../include/thread.h"

void* start_key_server(void* arg)
{
    thread_param* p = (thread_param*) arg;
    int s = serve_public_key(p->socket, p->key_file);
    p->exit_status = s;
    return NULL;
}

void* start_sign_server(void* arg)
{
    thread_param* p = (thread_param*) arg;
    int s = serve_signing_service(p->socket, p->key_file);
    p->exit_status = s;
    return NULL;
}

int main()
{
    pthread_t key_tid, sign_tid;
    thread_param* key_tparam;
    thread_param* sign_tparam;

    key_tparam = malloc(sizeof(thread_param));
    key_tparam->socket = (const char*) DEFAULT_PUBLIC_KEY_SOCKET;
    key_tparam->key_file = (const char*) DEFAULT_KEY_FILE;
    key_tparam->exit_status = 0;
    pthread_create(&key_tid, NULL, start_key_server, (void*) key_tparam);

    sign_tparam = malloc(sizeof(thread_param));
    sign_tparam->socket = (const char*) DEFAULT_SIGNING_SOCKET;
    sign_tparam->key_file = (const char*) DEFAULT_KEY_FILE;
    sign_tparam->exit_status = 0;
    pthread_create(&sign_tid, NULL, start_sign_server, (void*) sign_tparam);

    pthread_join(key_tid, NULL);
    pthread_join(sign_tid, NULL);

    free(key_tparam);
    free(sign_tparam);

    printf("Signing service shut down. Bye!");
}

/*
#define SOCKET_PATH "/tmp/echo.sock"
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 5


int main()
{
    int sock, conn, count;
    char buffer[BUFFER_SIZE];
    struct sockaddr_un server;

    set_signal_action();
    unlink(SOCKET_PATH);

    // Create the socket file descriptor.
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("opening socket");
        exit(1);
    }

    // Configure socket bindings. Accept a maximum of MAX_CLIENTS number of
    // connections. Any connection attempts beyond that will be refused.
    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, SOCKET_PATH);
    if (bind(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)))
    {
        perror("binding socket");
        exit(1);
    }

    printf("Successfully opened socket at %s\n", server.sun_path);
    listen(sock, MAX_CLIENTS);

    for (;;)
    {
        // Wait for the next connection. This call is blocking.
        conn = accept(sock, 0, 0);
        if (conn == -1)
        {
            printf("Error opening connection, skipping");
            continue;
        }

        do {
            // Read all data from the connection.
            bzero(buffer, BUFFER_SIZE);
            count = read(conn, buffer, BUFFER_SIZE);
            if (count < 0)
            {
                perror("reading connection");
            }
            else if (count > 0)
            {
                printf("Echoing message: %s", buffer);
                write(conn, buffer, count);
            }
            else
            {
                printf("Finished reading from connection, closing");
            }
        } while (count > 0);

        // We are done with the connection. Close it.
        close(conn);
    }

    // The server is terminating. Clean up resources.
    close(sock);
    unlink(SOCKET_PATH);
}
*/
