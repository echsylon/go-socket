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

#ifndef SIGNING_H
#define SIGNING_H

#include <stdint.h>
#include <stddef.h>

#define DEFAULT_KEY_FILE "./etc/ed25519_key.pem"

/*
 * Reads the public key byte buffer from the signing key used internally.
 *
 * key_file:    Path to the key file.
 * key:         The public key buffer.
 * key_len:     The length of the public key.
 *
 * returns:     1 on success, 0 otherwise.
 */
int get_public_key(const char* key_file, uint8_t* key, size_t* key_len);

/*
 * Signs a given message with an internal key and populates the given
 * buffer with the resulting signature.
 *
 * key_file:    Path to the key file.
 * msg:         The message buffer to sign.
 * msg_len:     The number of bytes to sign.
 * sig:         The resulting signature buffer.
 * sig_len:     The length of the signature.
 *
 * returns:     1 on success, 0 otherwise.
 */
int sign_message(const char* key_file, uint8_t* msg, size_t msg_len, uint8_t* sig, size_t* sig_len);

#endif
