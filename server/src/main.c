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
