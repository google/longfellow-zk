// This is free and unencumbered software released into the public domain.
// it comes from https://github.com/kokke/tiny-AES-c/
// and is stripped down to fit the purpose of longfellow-zk

#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#define AES_KEYLEN 32
#define AES_keyExpSize 240

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);

void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);

#endif
