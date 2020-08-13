/*
 * Copyright (C) 2020 BrianYi, All rights reserved
 */
#include "rsa.h"
#include <strings.h>

vector<int> g_primes;

int rsa_init()
{
    srand(time(0));
    rsa_gen_prime_table();
    return 0;
}

int rsa_gen_prime_table()
{
    vector<int> primes(MAX_PRIME_LIMIT+1,1);
    int sqt = sqrt(MAX_PRIME_LIMIT), i = 0, j = 0;
    for (i = 2; i <= sqt; ++i)
    {
        if (primes[i])
        {
            for (j = 2 * i; j <= MAX_PRIME_LIMIT; j += i)
                primes[j] = 0;
        }
    }

    // lose 2
    for (i = 3; i <= MAX_PRIME_LIMIT; ++i)
    {
        if (primes[i])
            g_primes.push_back(i);
    }
    return 0;
}

int rsa_gen_prime()
{
    if (g_primes.empty())
        return -1;

    int nprime = g_primes.size();
    int idx = rand() % nprime;
    return g_primes[idx];
}

size_t rsa_bits(int n)
{
    int size = sizeof(n);
    int i;
    for (i = size * 8 - 1; i >= 0; --i)
        if ((n>>i) & 1) return ((i+1)+7)/8*8;
    return 0;
}

unsigned long long rsa_power_mode(long long a, long long e, long long n)
{
    unsigned long long res = 1;
    for (;e--;)
    {
        res *= a;
        res %= n;
    }
    return res;
}

void rsa_gen_key(rsa_pub_key* pubkey, rsa_pri_key* prikey)
{
    unsigned long long P, Q, n=0, m, e, d;
    
    // n
    for (;n<=255;)
    {
        P = rsa_gen_prime();
        Q = rsa_gen_prime();
        n = P * Q;
    }

    // m
    m = (P-1) * (Q-1);
    
    // e
    for (;;)
    {
        e = rsa_gen_prime();
        if ((e > 1) && (e < m))
            break;
    }

    // d
    for (d=m>e?m/e:1;;++d)
    {
        if (e * d % m == 1)
            break;
    }

    // public key
    pubkey->n = n;
    pubkey->e = e;

    // private key
    prikey->n = n;
    prikey->d = d;
}

// (n,e)
int rsa_encrypt(rsa_pub_key* pubkey, char *plain, size_t plain_size, char **cipher, size_t *cipher_size)
{
    size_t nbits = rsa_bits(pubkey->n);
    size_t nbytes = nbits / 8;
    size_t i;
    unsigned long long cipblock;
    assert(nbytes > 1);
    *cipher_size = nbytes * plain_size;
    *cipher = (char *)malloc(*cipher_size);
    bzero(*cipher, *cipher_size);

    for (i = 0; i < plain_size; ++i)
    {
        cipblock = rsa_power_mode(plain[i], pubkey->e, pubkey->n);
        memcpy(*cipher + i * nbytes, (char *)&cipblock, nbytes);
    }
    return 0;
}

// (n,d)
int rsa_decrypt(rsa_pri_key* prikey, char *cipher, size_t cipher_size, char **plain, size_t *plain_size)
{
    size_t nbits = rsa_bits(prikey->n);
    size_t nbytes = nbits / 8;
    size_t i;
    unsigned long long plnblock, t;
    assert(nbytes > 1);
    *plain_size = cipher_size / nbytes;
    *plain = (char *)malloc(*plain_size);
    bzero(*plain, *plain_size);

    for (i = 0; i < *plain_size; ++i)
    {
        t = *((unsigned long long*)&(cipher[i * nbytes]));
        t &= ~((unsigned long long)(-1) << nbits);
        plnblock = rsa_power_mode(t, prikey->d, prikey->n);
        memcpy(*plain + i, (char *)&plnblock, 1);
    }
    return 0;
}

void rsa_bin2str(const unsigned char* pbin, size_t bin_size, unsigned char **ppstr, size_t *pstr_size, bool delimiter/*=false*/)
{
    size_t i;
    unsigned char *pcurr;
    const char* kHEXChars = { "0123456789ABCDEF"  };
    if (delimiter)
        *pstr_size = bin_size * 3 - 1;
    else
        *pstr_size = bin_size * 2;
    *ppstr = (unsigned char *)malloc(*pstr_size + 1);
    for (i = 0, pcurr = *ppstr; i < bin_size; i++)
    {
        *pcurr++ = kHEXChars[pbin[i] >> 4];
        *pcurr++ = kHEXChars[pbin[i] & 0xF];
        if (delimiter)
            *pcurr++ = ' ';
    }
    *pcurr = 0;
}

void rsa_str2bin(const unsigned char *pstr, size_t str_size, unsigned char **ppbin, size_t *pbin_size, bool delimiter/*=false*/)
{
    size_t i;
    const unsigned char *pcurr;
    if (delimiter)
        *pbin_size = (str_size + 1) / 3;
    else
        *pbin_size = str_size / 2;
    *ppbin = (unsigned char *)malloc(*pbin_size);
    for (i = 0, pcurr = pstr; (i < str_size) && (*pcurr != 0); i++)
    {
        (*ppbin)[i] = hex2bin(*pcurr) << 4;
        pcurr++;
        if (*pcurr != 0)
        {
            (*ppbin)[i] |= hex2bin(*pcurr);
            pcurr++;
        }
        if (*pcurr == ' ')
            pcurr++; // skip delimiter
    }
}
