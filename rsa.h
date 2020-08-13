/*
 * Copyright (C) 2020 BrianYi, All rights reserved
 */
#include <iostream>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <string.h>
#include <assert.h>
#include <time.h>
using namespace std;

#define MAX_PRIME_LIMIT 10000
#define hex2bin(x) ((((x) >= '0') && ((x) <= '9')) ? ((x) - '0') : \
                            (((toupper(x) >= 'A') && (toupper(x) <= 'F')) ? (toupper(x) - 'A' + 10) : 0))

struct rsa_pub_key
{
    unsigned long long n;
    unsigned long long e;
};

struct rsa_pri_key
{
    unsigned long long n;
    unsigned long long d;
};

/**
 * @brief rsa initialization.
 *
 * @return 
 */
int rsa_init();

/**
 * @brief generate prime table.
 *
 * @return 
 */
int rsa_gen_prime_table();

/**
 * @brief generate rsa key pairs.
 *
 * @param pubkey public key.
 * @param prikey private key.
 */
void rsa_gen_key(rsa_pub_key* pubkey, rsa_pri_key* prikey, unsigned long long *outP = nullptr, unsigned long long *outQ = nullptr);

/**
 * @brief rsa encrypt function
 *
 * @param pubkey public key.
 * @param plain plain text.
 * @param plain_size plain text size.
 * @param cipher cipher text.
 * @param cipher_size cipher text size.
 *
 * @return 
 */
int rsa_encrypt(rsa_pub_key* pubkey, const char *plain, const size_t plain_size, char **cipher, size_t *cipher_size);

/**
 * @brief rsa decrypt function
 *
 * @param prikey public key.
 * @param cipher cipher text.
 * @param cipher_size cipher text size.
 * @param plain plain text.
 * @param plain_size plain text size.
 *
 * @return 
 */
int rsa_decrypt(rsa_pri_key* prikey, const char *cipher, const size_t cipher_size, char **plain, size_t *plain_size);


/*
 * Tools function
 */

/**
 * @brief translate binary to hex string.
 *
 * @param pbin      [in] binary data.
 * @param bin_size  [in] binary data size.
 * @param ppstr     [out] hex string.
 * @param pstr_size [out] hex string size.
 * @param delimiter [in] has delimiter?
 */
void rsa_bin2str(const unsigned char* pbin, size_t bin_size, char **ppstr, size_t *pstr_size, bool delimiter=false);

/**
 * @brief translate hex string to binary.
 *
 * @param pstr      [in] hex string.
 * @param str_size  [in] hex string size.
 * @param ppbin     [out] binary data.
 * @param pbin_size [out] binary data size.
 * @param delimiter [in] has delimiter?
 */
void rsa_str2bin(const unsigned char *pstr, size_t str_size, char **ppbin, size_t *pbin_size, bool delimiter=false);
