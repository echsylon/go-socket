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

#include <openssl/pem.h>

#include "../include/signing.h"

/*
 * Reads the raw public key bytes to the [pub] buffer and updates the [pub_len]
 * size with the actual number of bytes that was read. It is upon the caller to
 * ensure that [pub] has capacity to take an ed25519 public key.
 *
 * key_file:    Path to the key file to extract the public key from.
 * pub:         The resulting PEM public key byte buffer.
 * pub_len:     The actual number of bytes that was read.
 *
 * returns:     1 on success, 0 otherwise.
 */
int get_public_key(const char* key_file, uint8_t* pub, size_t* pub_len)
{
    EVP_PKEY* key;
    BUF_MEM* buf;
    BIO* bio;
    int ok;

    // Read key file
    bio = BIO_new_file(key_file, "r");
    if (!bio)
        return 0;

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!key)
        return 0;

    // Write its public key in PEM format to memory IO sink
    bio = BIO_new(BIO_s_mem());
    if (!bio)
        return 0;

    ok = PEM_write_bio_PUBKEY(bio, key);
    EVP_PKEY_free(key);
    if (!ok)
        return 0;

    // Copy the PEM bytes to the result buffer
    ok = BIO_get_mem_ptr(bio, &buf);
    *pub_len = buf->length;
    memcpy(pub, buf->data, buf->length);
    BIO_free(bio);

    return ok;
}

/*
 * Signs [msg_len] bytes of the given [msg] buffer and populates [sig] and
 * [sig_len] respectively with the resulting signature and signature length.
 *
 * key_file:    Path to the key file to sign with.
 * msg:         The message buffer to sign.
 * msg_len:     Number of bytes from [msg] to sign.
 * sig:         The resulting signature buffer.
 * sig_len:     The length of the signature.
 *
 * returns:     1 on success, 0 otherwise.
 */
int sign_message(const char* key_file, uint8_t* msg, size_t msg_len, uint8_t* sig, size_t* sig_len)
{
    EVP_MD_CTX* ctx;
    EVP_PKEY* key;
    BIO* bio;
    int ok;

    // Read key file
    bio = BIO_new_file(key_file, "r");
    if (bio == NULL)
        return 0;

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (key == NULL)
        return 0;

    // Sign the message and copy signature on success
    ctx = EVP_MD_CTX_new();
    ok = EVP_DigestSignInit(ctx, NULL, NULL, NULL, key);
    if (ok)
        ok = EVP_DigestSign(ctx, sig, sig_len, msg, msg_len);

    EVP_MD_CTX_free(ctx);
    return ok;
}
