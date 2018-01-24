#pragma once

#include <stdint.h>
#include <openssl/sha.h>

#define SHA256_BLOCK_SIZE 32 

namespace opt_ssl
{
	typedef SHA256_CTX _SHA256_CTX;
#define state h
#define bitlen Nl
#define bitlenH Nh
#define datalen num

	void sha256_init(_SHA256_CTX *ctx);
	void sha256_update(_SHA256_CTX *ctx, const uint8_t *data, size_t len);
	void sha256_final(_SHA256_CTX *ctx, uint8_t *hash);

	void set_state(_SHA256_CTX *ctx, uint32_t* state, size_t size);

	void shasha(uint32_t* state, uint64_t nonce, uint8_t *hash);
};
