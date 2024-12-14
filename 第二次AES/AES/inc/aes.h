#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C"
{
#endif

#define AES_BLOCK_BITS 128 /* bits of AES algoithm block */
#define AES_BLOCK_SIZE 16  /* bytes of AES algoithm block */
#define AES_KEY_SIZE 16    /* bytes of AES algoithm double key */

    /**
     * @brief Generate encryption subkeys
     * @param[in] key original key
     * @param[out] subKeys generated encryption subkeys
     * @return 0 OK
     * @return 1 Failed
     */
    int aes_make_enc_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]);

    /**
     * @brief Generate decryption subkeys
     * @param[in] key original key
     * @param[out] subKeys generated decryption subkeys
     * @return 0 OK
     * @return 1 Failed
     */
    int aes_make_dec_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]);

    /**
     * @brief AES encrypt single block
     * @param[in] input plaintext, [length = AES_BLOCK_SIZE]
     * @param[in] subKeys subKeys
     * @param[out] output ciphertext, [length = AES_BLOCK_SIZE]
     */
    void aes_encrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output);

    /**
     * @brief AES decrypt single block
     * @param[in] input ciphertext, [length = AES_BLOCK_SIZE]
     * @param[in] subKeys subKeys
     * @param[out] output plaintext, [length = AES_BLOCK_SIZE]
     */
    void aes_decrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif // AES_H
