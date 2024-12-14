#include "sm4.h"
#include <stdio.h>   // 文件操作: FILE, fopen, fclose, fseek, ftell, printf
#include <stdlib.h>  // 内存操作: malloc, free, exit; EXIT_FAILURE 宏
#include <string.h>  // 内存比较: memcmp
#include <time.h>    // 时间函数: clock, clock_t, CLOCKS_PER_SEC


static const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static uint32_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

static inline uint32_t rotate_left(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t sm4_t(uint32_t b)
{
    uint8_t a[4] = {
        (b >> 24) & 0xff,
        (b >> 16) & 0xff,
        (b >> 8) & 0xff,
        b & 0xff
    };

    for (int i = 0; i < 4; i++)
        a[i] = SM4_SBOX[a[i]];

    uint32_t c = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
    return c ^ rotate_left(c, 2) ^ rotate_left(c, 10) ^ rotate_left(c, 18) ^ rotate_left(c, 24);
}

static uint32_t sm4_t_prime(uint32_t b)
{
    uint8_t a[4] = {
        (b >> 24) & 0xff,
        (b >> 16) & 0xff,
        (b >> 8) & 0xff,
        b & 0xff
    };

    for (int i = 0; i < 4; i++)
        a[i] = SM4_SBOX[a[i]];

    uint32_t c = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
    return c ^ rotate_left(c, 13) ^ rotate_left(c, 23);
}

int sm4_make_enc_subkeys(const unsigned char key[SM4_KEY_SIZE], uint32_t encSubKeys[SM4_ROUNDS])
{
    uint32_t k[4];
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint32_t)key[i * 4 + 0] << 24) |
               ((uint32_t)key[i * 4 + 1] << 16) |
               ((uint32_t)key[i * 4 + 2] << 8) |
               ((uint32_t)key[i * 4 + 3]);
        k[i] ^= FK[i];
    }

    for (int i = 0; i < SM4_ROUNDS; i++) {
        k[(i + 4) % 4] = k[i % 4] ^ sm4_t_prime(k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ CK[i]);
        encSubKeys[i] = k[(i + 4) % 4];
    }
    return 0;
}

int sm4_make_dec_subkeys(const unsigned char key[SM4_KEY_SIZE], uint32_t decSubKeys[SM4_ROUNDS])
{
    uint32_t encSubKeys[SM4_ROUNDS];
    sm4_make_enc_subkeys(key, encSubKeys);
    for (int i = 0; i < SM4_ROUNDS; i++)
        decSubKeys[i] = encSubKeys[SM4_ROUNDS - 1 - i];
    return 0;
}

void sm4_encrypt_block(const unsigned char *input, const uint32_t encSubKeys[SM4_ROUNDS], unsigned char *output)
{
    uint32_t x[4];
    for (int i = 0; i < 4; i++) {
        x[i] = ((uint32_t)input[i * 4 + 0] << 24) |
               ((uint32_t)input[i * 4 + 1] << 16) |
               ((uint32_t)input[i * 4 + 2] << 8) |
               ((uint32_t)input[i * 4 + 3]);
    }

    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = x[0] ^ sm4_t(x[1] ^ x[2] ^ x[3] ^ encSubKeys[i]);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = temp;
    }

    for (int i = 0; i < 4; i++) {
        output[i * 4 + 0] = (x[3 - i] >> 24) & 0xff;
        output[i * 4 + 1] = (x[3 - i] >> 16) & 0xff;
        output[i * 4 + 2] = (x[3 - i] >> 8) & 0xff;
        output[i * 4 + 3] = x[3 - i] & 0xff;
    }
}

void sm4_decrypt_block(const unsigned char *input, const uint32_t decSubKeys[SM4_ROUNDS], unsigned char *output)
{
    sm4_encrypt_block(input, decSubKeys, output);
}

//下面是CBC模式的代码
void sm4_cbc_encrypt(const unsigned char *input, unsigned char *output,
                     size_t length, const uint32_t encSubKeys[SM4_ROUNDS],
                     const unsigned char iv[SM4_BLOCK_SIZE])
{
    unsigned char block[SM4_BLOCK_SIZE];
    unsigned char current_iv[SM4_BLOCK_SIZE];
    memcpy(current_iv, iv, SM4_BLOCK_SIZE);

    for (size_t i = 0; i < length; i += SM4_BLOCK_SIZE) {
        for (size_t j = 0; j < SM4_BLOCK_SIZE; j++) {
            block[j] = input[i + j] ^ current_iv[j];
        }
        sm4_encrypt_block(block, encSubKeys, output + i);
        memcpy(current_iv, output + i, SM4_BLOCK_SIZE);
    }
}

void sm4_cbc_decrypt(const unsigned char *input, unsigned char *output,
                     size_t length, const uint32_t decSubKeys[SM4_ROUNDS],
                     const unsigned char iv[SM4_BLOCK_SIZE])
{
    unsigned char block[SM4_BLOCK_SIZE];
    unsigned char current_iv[SM4_BLOCK_SIZE];
    memcpy(current_iv, iv, SM4_BLOCK_SIZE);

    for (size_t i = 0; i < length; i += SM4_BLOCK_SIZE) {
        sm4_decrypt_block(input + i, decSubKeys, block);
        for (size_t j = 0; j < SM4_BLOCK_SIZE; j++) {
            output[i + j] = block[j] ^ current_iv[j];
        }
        memcpy(current_iv, input + i, SM4_BLOCK_SIZE);
    }
}

void load_test_data(const char *filename, unsigned char **data, size_t *size)
{
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    *data = malloc(*size);
    if (!*data) {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    fread(*data, 1, *size, file);
    fclose(file);
}

void test_sm4_cbc_with_file(const char *filename)
{
    printf("Testing with file: %s\n", filename);

    unsigned char *data;
    size_t size;

    // Load test data
    load_test_data(filename, &data, &size);

    unsigned char *ciphertext = malloc(size);
    unsigned char *decrypted = malloc(size);

    unsigned char key[SM4_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char iv[SM4_BLOCK_SIZE];
    for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
        iv[i] = rand() & 0xFF;
    }

    uint32_t encSubKeys[SM4_ROUNDS];
    uint32_t decSubKeys[SM4_ROUNDS];
    sm4_make_enc_subkeys(key, encSubKeys);
    sm4_make_dec_subkeys(key, decSubKeys);

    // Set repeat count based on file size
    int repeats;
    if (size == 64) {
        repeats = 100000;
    } 
    else if (size == 2048) {
        repeats = 10000;
    } 
    else {
        repeats = 1; // Default for unusual sizes
    }

    clock_t start, end;
    double total_time = 0.0;

    // Encryption
    start = clock();
    for (int i = 0; i < repeats; i++) {
        sm4_cbc_encrypt(data, ciphertext, size, encSubKeys, iv);
    }
    end = clock();
    total_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double avg_enc_time = total_time / (repeats > 1 ? repeats : 1);
    double enc_throughput_mbps = ((double)(size * 8) / 1e6) / avg_enc_time;

    // Decryption
    start = clock();
    for (int i = 0; i < repeats; i++) {
        sm4_cbc_decrypt(ciphertext, decrypted, size, decSubKeys, iv);
    }
    end = clock();
    total_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double avg_dec_time = total_time / (repeats > 1 ? repeats : 1);
    double dec_throughput_mbps = ((double)(size * 8) / 1e6) / avg_dec_time;

    // Output results
    long int size_2 = size;
    printf("  the size of the test_file is %ld bytes\n", size_2);
    printf("  Average encryption time: %f seconds\n", avg_enc_time);
    printf("  Encryption throughput: %f Mbps\n", enc_throughput_mbps);
    printf("  Average decryption time: %f seconds\n", avg_dec_time);
    printf("  Decryption throughput: %f Mbps\n", dec_throughput_mbps);

    // Verify correctness
    if (memcmp(data, decrypted, size) == 0) {
        printf("  Correctness test passed.\n");
    } else {
        printf("  Correctness test failed.\n");
    }
    printf("\n");

    free(data);
    free(ciphertext);
    free(decrypted);
}