#ifndef SM4_H
#define SM4_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#define SM4_BLOCK_BITS 128 /* bits of AES algoithm block */
#define SM4_BLOCK_SIZE 16  /* bytes of AES algoithm block 16 * 8 = 128 */
#define SM4_KEY_SIZE 16    /* bytes of AES algoithm double key 16 * 8 = 128  */
#define SM4_ROUNDS 32

    /**
     * @brief Generate encryption subkeys
     * @param[in] key original key
     * @param[out] encSubKeys generated subkeys
     * @return 0 OK
     * @return 1 Failed
     */
    int sm4_make_enc_subkeys(const unsigned char key[SM4_KEY_SIZE], uint32_t encSubKeys[SM4_ROUNDS]);

    /**
     * @brief Generate decryption subkeys
     * @param[in] key original key
     * @param[out] decSubKeys generated subkeys
     * @return 0 OK
     * @return 1 Failed
     */
    int sm4_make_dec_subkeys(const unsigned char key[SM4_KEY_SIZE], uint32_t decSubKeys[SM4_ROUNDS]);

    /**
     * @brief SM4 encrypt single block
     * @param[in] input plaintext, [length = SM4_BLOCK_SIZE]
     * @param[in] encSubKeys encryption subKeys
     * @param[out] output ciphertext, [length = SM4_BLOCK_SIZE]
     */
    void sm4_encrypt_block(const unsigned char *input, const uint32_t encSubKeys[SM4_ROUNDS], unsigned char *output);

    /**
     * @brief SM4 decrypt single block
     * @param[in] input ciphertext, [length = SM4_BLOCK_SIZE]
     * @param[in] decSubKeys decryption subKeys
     * @param[out] output plaintext, [length = SM4_BLOCK_SIZE]
     */
    void sm4_decrypt_block(const unsigned char *input, const uint32_t decSubKeys[SM4_ROUNDS], unsigned char *output);
    void sm4_cbc_encrypt(const unsigned char *input, unsigned char *output,
                     size_t length, const uint32_t encSubKeys[SM4_ROUNDS],
                     const unsigned char iv[SM4_BLOCK_SIZE]);

    void sm4_cbc_decrypt(const unsigned char *input, unsigned char *output,
                     size_t length, const uint32_t decSubKeys[SM4_ROUNDS],
                     const unsigned char iv[SM4_BLOCK_SIZE]);

    void load_test_data(const char *filename, unsigned char **data, size_t *size);

    void test_sm4_cbc_with_file(const char *filename);
#ifdef __cplusplus
}
#endif

#endif // SM4_H
