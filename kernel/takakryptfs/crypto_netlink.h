#ifndef TAKAKRYPTFS_CRYPTO_NETLINK_H
#define TAKAKRYPTFS_CRYPTO_NETLINK_H

#include "takakryptfs.h"
#include "../takakrypt.h"

/* Crypto operation constants */
#define TAKAKRYPT_CRYPTO_TIMEOUT_MS  5000  /* 5 second timeout for crypto operations */
#define TAKAKRYPT_MAX_KEY_ID_LEN     255   /* Maximum key ID length */

/* Encryption request structure for kernel->userspace */
struct takakryptfs_encrypt_request {
    struct takakrypt_msg_header header;
    uint32_t key_id_len;
    uint32_t data_len;
    /* Followed by:
     * char key_id[key_id_len];
     * char data[data_len];
     */
} __packed;

/* Decryption request structure for kernel->userspace */
struct takakryptfs_decrypt_request {
    struct takakrypt_msg_header header;
    uint32_t key_id_len;
    uint32_t data_len;
    /* Followed by:
     * char key_id[key_id_len];
     * char encrypted_data[data_len];
     */
} __packed;

/* Response structure for userspace->kernel */
struct takakryptfs_crypto_response {
    struct takakrypt_msg_header header;
    uint32_t data_len;
    /* Followed by:
     * char data[data_len];  // Encrypted or decrypted data
     */
} __packed;

/* Function prototypes for crypto-netlink operations */
int takakryptfs_send_encrypt_request(const char *key_id, const void *plaintext, 
                                     size_t plaintext_len, void **ciphertext, 
                                     size_t *ciphertext_len);
int takakryptfs_send_decrypt_request(const char *key_id, const void *ciphertext,
                                     size_t ciphertext_len, void **plaintext,
                                     size_t *plaintext_len);

#endif /* TAKAKRYPTFS_CRYPTO_NETLINK_H */