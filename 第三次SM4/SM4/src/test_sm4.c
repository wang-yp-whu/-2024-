#include "sm4.h"
#include "benchmark.h"

#define BENCHS 10
#define ROUNDS 100000

// Print bytes in hexadecimal format
void print_bytes(const unsigned char *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

// Correctness test function
void test_sm4_correctness()
{
    // Fixed example key  0x0123456789abcdeffedcba9876543210  
    unsigned char key[SM4_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 
    0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    // Fixed example plaintext 0x0123456789abcdeffedcba9876543210 
    unsigned char plaintext[SM4_BLOCK_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 
    0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    // Corresponding ciphertext 0x681edf34d206965e86b3e94f536e4246
    unsigned char correctResult[SM4_BLOCK_SIZE] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};

    unsigned char ciphertext[SM4_BLOCK_SIZE];
    unsigned char decrypted[SM4_BLOCK_SIZE];

    uint32_t encSubKeys[SM4_ROUNDS];
    uint32_t decSubKeys[SM4_ROUNDS];

    // Generate encryption subkeys
    if (sm4_make_enc_subkeys(key, encSubKeys) != 0)
    {
        printf("Failed to generate encryption subkeys.\n");
        return;
    }

    // Generate decryption subkeys
    if (sm4_make_dec_subkeys(key, decSubKeys) != 0)
    {
        printf("Failed to generate decryption subkeys.\n");
        return;
    }

    printf("Original plaintext: ");
    print_bytes(plaintext, SM4_BLOCK_SIZE);

    printf("Correct ciphertext: ");
    print_bytes(correctResult, SM4_BLOCK_SIZE);

    // Encrypt
    sm4_encrypt_block(plaintext, encSubKeys, ciphertext);
    printf("Encrypted ciphertext: ");
    print_bytes(ciphertext, SM4_BLOCK_SIZE);

    // Decrypt
    sm4_decrypt_block(ciphertext, decSubKeys, decrypted);
    printf("Decrypted plaintext: ");
    print_bytes(decrypted, SM4_BLOCK_SIZE);

    // Verify encryption result
    if ((memcmp(ciphertext, correctResult, SM4_BLOCK_SIZE) == 0) && (memcmp(plaintext, decrypted, SM4_BLOCK_SIZE) == 0))
    {
        printf(">> Correctness test passed.\n\n");
    }
    else
    {
        printf(">> Correctness test failed.\n\n");
    }
}

void encInit(unsigned char key[SM4_KEY_SIZE], uint32_t encSubKeys[SM4_ROUNDS])
{
    srand((unsigned int)time(NULL));
    // random key
    for (int i = 0; i < SM4_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }

    // Generate encryption subkeys
    if (sm4_make_enc_subkeys(key, encSubKeys) != 0)
    {
        printf("Failed to generate encryption subkeys.\n");
        return;
    }
}

void decInit(unsigned char key[SM4_KEY_SIZE], uint32_t decSubKeys[SM4_ROUNDS])
{
    srand((unsigned int)time(NULL));
    // random key
    for (int i = 0; i < SM4_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }

    // Generate decryption subkeys
    if (sm4_make_dec_subkeys(key, decSubKeys) != 0)
    {
        printf("Failed to generate decryption subkeys.\n");
        return;
    }
}

// Performance test function
void test_sm4_performance()
{
    srand((unsigned int)time(NULL));
    // random key
    unsigned char key[SM4_KEY_SIZE];
    // random plaintext
    unsigned char plaintext[SM4_BLOCK_SIZE];
    for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
        plaintext[i] = rand() & 0xFF;
    }

    unsigned char ciphertext[SM4_BLOCK_SIZE];
    unsigned char decrypted[SM4_BLOCK_SIZE];
    
    uint32_t encSubKeys[SM4_ROUNDS];
    uint32_t decSubKeys[SM4_ROUNDS];

    // Perform performance test
    encInit(key, encSubKeys);
    sm4_encrypt_block(plaintext, encSubKeys, ciphertext);
    BPS_BENCH_START("SM4 encryption", BENCHS);
    BPS_BENCH_ITEM(encInit(key, encSubKeys), sm4_encrypt_block(ciphertext, encSubKeys, ciphertext), ROUNDS);
    BPS_BENCH_FINAL(SM4_BLOCK_BITS);

    decInit(key, decSubKeys);
    sm4_decrypt_block(ciphertext, decSubKeys, decrypted);
    BPS_BENCH_START("SM4 decryption", BENCHS);
    BPS_BENCH_ITEM(decInit(key,decSubKeys), sm4_decrypt_block(decrypted, decSubKeys, decrypted), ROUNDS);
    BPS_BENCH_FINAL(SM4_BLOCK_BITS);
}

//CBC
void test_sm4_cbc_performance()
{
    unsigned char key[SM4_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char iv[SM4_BLOCK_SIZE];
    for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
        iv[i] = rand() & 0xFF; // 随机生成 0-255 的字节
    }
    size_t sizes[] = {64, 2048, 10 * 1024 * 1024};
    const char *labels[] = {"64B", "2KB", "10MB"};

    for (int test = 0; test < 3; test++) {
        size_t size = sizes[test];
        unsigned char *plaintext = malloc(size);
        unsigned char *ciphertext = malloc(size);
        unsigned char *decrypted = malloc(size);
        memset(plaintext, 0xAA, size); // Example plaintext

        uint32_t encSubKeys[SM4_ROUNDS];
        uint32_t decSubKeys[SM4_ROUNDS];
        sm4_make_enc_subkeys(key, encSubKeys);
        sm4_make_dec_subkeys(key, decSubKeys);

        clock_t start, end;

        // Encrypt
        start = clock();
        sm4_cbc_encrypt(plaintext, ciphertext, size, encSubKeys, iv);
        end = clock();
        double enc_time = ((double)(end - start)) / CLOCKS_PER_SEC;

        // Decrypt
        start = clock();
        sm4_cbc_decrypt(ciphertext, decrypted, size, decSubKeys, iv);
        end = clock();
        double dec_time = ((double)(end - start)) / CLOCKS_PER_SEC;

        printf("Test %s:\n", labels[test]);
        printf("  Encryption time: %f seconds\n", enc_time);
        printf("  Decryption time: %f seconds\n", dec_time);

        // Verify correctness
        if (memcmp(plaintext, decrypted, size) == 0) {
            printf("  Correctness test passed.\n");
        } else {
            printf("  Correctness test failed.\n");
        }

        free(plaintext);
        free(ciphertext);
        free(decrypted);
    }
}

int main()
{
    // Perform correctness test
    printf(">> Performing correctness test...\n");
    test_sm4_correctness();

    // Perform performance test
    printf(">> Performing performance test...\n");
    test_sm4_performance();

    printf(">> Testing SM4-CBC with data files...\n");
    test_sm4_cbc_with_file("SM4_test_64B.bin");
    test_sm4_cbc_with_file("SM4_test_2KB.bin");
    test_sm4_cbc_with_file("SM4_test_10MB.bin");

    return 0;
}


