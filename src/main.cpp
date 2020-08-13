/*
 * Copyright (C) 2020 BrianYi, All rights reserved
 */
#include "rsa.h"

int main(int argc, char **argv)
{
    rsa_init();
    rsa_pub_key pubkey;
    rsa_pri_key prikey;
    rsa_gen_key(&pubkey, &prikey);
    char plain[] = "abcdefg?who are you?";
    char *cipher = nullptr;
    size_t plain_size = strlen(plain);
    size_t cipher_size;
    printf("n=%lld e=%lld d=%lld\r\n", pubkey.n, pubkey.e, prikey.d);
    rsa_encrypt(&pubkey, plain, plain_size, &cipher, &cipher_size);
    unsigned char *pcipher_str, *pplain_str;
    size_t cipher_str_size, plain_str_size;
    rsa_bin2str((unsigned char *)cipher, cipher_size, &pcipher_str, &cipher_str_size);
    rsa_bin2str((unsigned char *)plain, plain_size, &pplain_str, &plain_str_size);
    unsigned char *new_cipher;
    size_t new_cipher_size;
    rsa_str2bin(pcipher_str, cipher_str_size, &new_cipher, &new_cipher_size);
    printf("plain: %s\r\n", plain);
    printf("plain hex: %s\r\n", pplain_str);
    printf("ciphr hex: %s\r\n", pcipher_str);
    char *pln = nullptr;
    size_t pln_size;
    rsa_decrypt(&prikey, cipher, cipher_size, &pln, &pln_size);
    printf("%s", pln);
    exit(0);
}
