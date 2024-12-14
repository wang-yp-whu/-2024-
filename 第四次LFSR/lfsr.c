#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint8_t lfsr(uint16_t *state, uint16_t taps) 
{
    uint16_t feedback = *state & taps;  // 提取需要反馈的位
    uint16_t new_bit = 0;
    // 计算反馈位
    while (feedback) 
    {
        new_bit ^= (feedback & 1);
        feedback >>= 1;
    }
    // 更新 LFSR 状态：右移并插入新位（仅保留 4 位）
    uint8_t output_bit = *state & 1;  // 输出最低位
    *state = ((*state >> 1) & 0x7) | (new_bit << 3);  // 插入新位到最高位
    return output_bit;
}

// 用 LFSR 生成字节流
void generate_key_stream(uint16_t seed, uint16_t taps, size_t length, uint8_t *key_stream) 
{
    uint16_t state = seed;
    for (size_t i = 0; i < length; i++) 
    {
        key_stream[i] = 0;
        for (int j = 0; j < 8; j++) 
        {  // 生成 8 个位组成一个字节
            key_stream[i] = (key_stream[i] << 1) | lfsr(&state, taps);
        }
    }
}

// 文件加密/解密
void encrypt_file(const char *input_file, const char *output_file, uint16_t seed, uint16_t taps) 
{
    FILE *fin = fopen(input_file, "rb");
    FILE *fout = fopen(output_file, "wb");
    if (!fin || !fout) 
    {
        perror("文件打开失败");
        exit(EXIT_FAILURE);
    }
    // 获取文件大小
    fseek(fin, 0, SEEK_END);
    size_t file_size = ftell(fin);
    rewind(fin);
    // 分配内存
    uint8_t *data = (uint8_t *)malloc(file_size);
    uint8_t *key_stream = (uint8_t *)malloc(file_size);
    if (!data || !key_stream) 
    {
        perror("内存分配失败");
        fclose(fin);
        fclose(fout);
        exit(EXIT_FAILURE);
    }
    // 读取文件数据
    fread(data, 1, file_size, fin);
    // 生成密钥流
    generate_key_stream(seed, taps, file_size, key_stream);
    // 加密/解密数据
    for (size_t i = 0; i < file_size; i++) 
    {
        data[i] ^= key_stream[i];  // 异或操作
    }
    // 写入加密/解密后的数据
    fwrite(data, 1, file_size, fout);
    // 释放资源
    free(data);
    free(key_stream);
    fclose(fin);
    fclose(fout);
}

// 主函数
int main() 
{
    const char *input_file = "input.txt";        // 原始明文
    const char *encrypted_file = "encrypted.bin"; // 加密文件
    const char *decrypted_file = "decrypted.txt"; // 解密后文件
    uint16_t seed = 0xB;                      // 加密时的种子
    uint16_t taps = 0x9;                      // 加密时的反馈多项式

    // 加密文件
    printf("the file is being encrypted now...\n");
    encrypt_file(input_file, encrypted_file, seed, taps);
    printf("successfully done:   %s\n", encrypted_file);

    // 解密文件
    printf("the file is being decrypted now...\n");
    encrypt_file(encrypted_file, decrypted_file, seed, taps);
    printf("sucessfully done:    %s\n", decrypted_file);
    printf("\n");
    return 0;
}