#include <iostream>
#include <cstdio>
#include <vector>
#include <string>

#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "merkel_hash.h"

merkel_hash::merkel_hash() {
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
}
merkel_hash::~merkel_hash() {
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

int merkel_hash::compute_hash(std::vector<std::string> blocks) {
    unsigned int digest_len;
    std::vector<hash_val> hashes;
    hash_val hash;
    int ret;

    for (auto it : blocks) {
        ret = compute_hash_val(it.c_str(), it.length(), hash.hash, &digest_len);
        if (ret != 0) {
            return -1;
        }

        hashes.push_back(hash);
    }

    std::vector<hash_val>::iterator it = hashes.begin();

    merkelh = *it;

    for (it = hashes.begin() + 1; it != hashes.end(); it ++) {
        ret = compute_merkel_hash_val(merkelh.hash, 32, it->hash, 32, merkelh.hash, &digest_len);
        if (ret != 0) {
            return -1;
        }
    }
    return 0;
}

void merkel_hash::dump_merkel_hash() {
    int i;

    printf("merkelh: ");
    for (i = 0; i < 32; i ++) {
        printf("%02x", merkelh.hash[i]);
    }
    printf("\n");
}


int merkel_hash::compute_hash_val(const char *input, size_t input_len, uint8_t *out, unsigned int *outlen)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    unsigned int digest_len;
    hash_val hash;
    int ret;

    ctx = EVP_MD_CTX_create();
    if (!ctx) {
        return -1;
    }

    md = EVP_sha256();

    ret = EVP_DigestInit(ctx, md);
    if (ret != 1) {
        return -1;
    }

    ret = EVP_DigestUpdate(ctx, input, input_len);
    if (ret != 1) {
        return -1;
    }

    ret = EVP_DigestFinal_ex(ctx, out, outlen);
    if (ret != 1) {
        return -1;
    }

    EVP_MD_CTX_destroy(ctx);

    return 0;
}

int merkel_hash::compute_merkel_hash_val(uint8_t *input_a, size_t input_a_len,
                                    uint8_t *input_b, size_t input_b_len,
                                    uint8_t *out, unsigned int *outlen)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    unsigned int digest_len;
    hash_val hash;
    int ret;

    ctx = EVP_MD_CTX_create();
    if (!ctx) {
        return -1;
    }

    md = EVP_sha256();

    ret = EVP_DigestInit(ctx, md);
    if (ret != 1) {
        return -1;
    }

    ret = EVP_DigestUpdate(ctx, input_a, input_a_len);
    if (ret != 1) {
        return -1;
    }

    ret = EVP_DigestUpdate(ctx, input_b, input_b_len);
    if (ret != 1) {
        return -1;
     }

     ret = EVP_DigestFinal_ex(ctx, out, outlen);
     if (ret != 1) {
         return -1;
     }

     EVP_MD_CTX_destroy(ctx);

     return 0;
}

void merkel_hash::dump(uint8_t *hash_val)
{
     int i;

     printf("hash: ");
     for (i = 0; i < 32; i ++) {
         printf("%02x", hash_val[i]);
     }
     printf("\n");
}

#ifdef EXEC_TEST_VECTOR
int main()
{
    std::vector<std::string> blocks;

    blocks.push_back("hello");
    blocks.push_back("merkel");
    blocks.push_back("hash");
    blocks.push_back("testing");

    merkel_hash h;

    h.compute_hash(blocks);

    h.dump_merkel_hash();
}

#endif
