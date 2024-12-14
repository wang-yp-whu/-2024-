#include "aes.h"
#include <stdint.h>
#include <wmmintrin.h>

// 定义轮密钥扩展函数
static inline void aes_key_expand_step(__m128i *key, int round, int rcon) 
{
    __m128i temp = _mm_aeskeygenassist_si128(key[round - 1], rcon);
    temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(3, 3, 3, 3));
    key[round] = _mm_xor_si128(key[round - 1], _mm_slli_si128(key[round - 1], 4));
    key[round] = _mm_xor_si128(key[round], _mm_slli_si128(key[round], 4));
    key[round] = _mm_xor_si128(key[round], _mm_slli_si128(key[round], 4));
    key[round] = _mm_xor_si128(key[round], temp);
}

// 定义完整的密钥扩展过程
static inline void aes_expand_keys(__m128i *key) 
{
    aes_key_expand_step(key, 1, 0x01);
    aes_key_expand_step(key, 2, 0x02);
    aes_key_expand_step(key, 3, 0x04);
    aes_key_expand_step(key, 4, 0x08);
    aes_key_expand_step(key, 5, 0x10);
    aes_key_expand_step(key, 6, 0x20);
    aes_key_expand_step(key, 7, 0x40);
    aes_key_expand_step(key, 8, 0x80);
    aes_key_expand_step(key, 9, 0x1B);
    aes_key_expand_step(key, 10, 0x36);
}

// 定义静态轮密钥存储
static __m128i KEY[11];

// 生成加密子密钥
int aes_make_enc_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]) 
{
    if (!key || !subKeys) 
    {
        return 1; // 输入无效
    }
    // 加载初始密钥
    KEY[0] = _mm_loadu_si128((const __m128i *)key);
    // 扩展轮密钥
    aes_expand_keys(KEY);
    // 存储结果到 subKeys
    for (int i = 0; i < 11; i++) 
    {
        _mm_storeu_si128((__m128i *)subKeys[i], KEY[i]);
    }
    return 0; // 成功
}

// 生成解密子密钥
int aes_make_dec_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]) 
{
    if (!key || !subKeys) 
    {
        return 1; // 输入无效
    }
    __m128i DECRYPT_KEY[11];
    // 调用加密子密钥生成
    if (aes_make_enc_subkeys(key, (unsigned char (*)[16])KEY) != 0) 
    {
        return 1; // 加密密钥生成失败
    }
    // 解密子密钥逆序生成
    DECRYPT_KEY[0] = KEY[10];
    DECRYPT_KEY[10] = KEY[0];
    for (int i = 1; i < 10; i++) 
    {
        DECRYPT_KEY[i] = _mm_aesimc_si128(KEY[10 - i]); // 对中间轮密钥执行 aesimc 操作
    }
    // 存储结果到 subKeys
    for (int i = 0; i < 11; i++) 
    {
        _mm_storeu_si128((__m128i *)subKeys[i], DECRYPT_KEY[i]);
    }
    return 0; // 成功
}

// 加密单个块
void aes_encrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output) 
{
    __m128i block = _mm_loadu_si128((const __m128i *)input); // 加载明文块
    // 初始轮 AddRoundKey
    block = _mm_xor_si128(block, _mm_loadu_si128((const __m128i *)subKeys[0]));
    // 前9轮
    for (int i = 1; i < 10; i++) 
    {
        block = _mm_aesenc_si128(block, _mm_loadu_si128((const __m128i *)subKeys[i])); // 完整一轮
    }
    // 最后一轮（无 MixColumns）
    block = _mm_aesenclast_si128(block, _mm_loadu_si128((const __m128i *)subKeys[10]));
    // 存储加密结果
    _mm_storeu_si128((__m128i *)output, block);
}

// 解密单个块
void aes_decrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output) 
{
    __m128i block = _mm_loadu_si128((const __m128i *)input); // 加载密文块
    // 初始轮 AddRoundKey
    block = _mm_xor_si128(block, _mm_loadu_si128((const __m128i *)subKeys[0]));
    // 前9轮
    for (int i = 1; i < 10; i++) 
    {
        block = _mm_aesdec_si128(block, _mm_loadu_si128((const __m128i *)subKeys[i])); // 完整一轮
    }
    // 最后一轮（无 MixColumns）
    block = _mm_aesdeclast_si128(block, _mm_loadu_si128((const __m128i *)subKeys[10]));
    // 存储解密结果
    _mm_storeu_si128((__m128i *)output, block);
}