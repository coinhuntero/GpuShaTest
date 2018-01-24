#include <stdlib.h>
#include <memory.h>
#include "sha256_opt_ssl.h"

namespace opt_ssl
{
	inline uint64_t bswap_64x32(uint64_t x)
	{
		return (((x & 0xff00000000000000ull) >> 24)
			| ((x & 0x00ff000000000000ull) >> 8)
			| ((x & 0x0000ff0000000000ull) << 8)
			| ((x & 0x000000ff00000000ull) << 24)
			| ((x & 0x00000000ff000000ull) >> 24)
			| ((x & 0x0000000000ff0000ull) >> 8)
			| ((x & 0x000000000000ff00ull) << 8)
			| ((x & 0x00000000000000ffull) << 24));
	}

	void static inline WriteBE64x32(uint64_t* ptr, uint64_t x)
	{
		*ptr = bswap_64x32(x);
	}

	void sha256_init(_SHA256_CTX *ctx)
	{
		ctx->datalen = 0;
		ctx->bitlen = 0;
		ctx->bitlenH = 0;
		ctx->state[0] = 0x6a09e667;
		ctx->state[1] = 0xbb67ae85;
		ctx->state[2] = 0x3c6ef372;
		ctx->state[3] = 0xa54ff53a;
		ctx->state[4] = 0x510e527f;
		ctx->state[5] = 0x9b05688c;
		ctx->state[6] = 0x1f83d9ab;
		ctx->state[7] = 0x5be0cd19;
		ctx->md_len = SHA256_BLOCK_SIZE;
	}

	void sha256_update(_SHA256_CTX *ctx, const uint8_t *data, size_t len)
	{
		uint8_t *cdata = (uint8_t *)ctx->data;

		for (uint32_t i = 0; i < len; ++i)
		{
			cdata[ctx->datalen] = data[i];
			ctx->datalen++;
			if (ctx->datalen == 64)
			{
				SHA256_Transform(ctx, cdata);
				ctx->bitlen += 512;
				ctx->datalen = 0;
			}
		}
	}

	void sha256_final(_SHA256_CTX *ctx, uint8_t *hash)
	{
		uint8_t *cdata = (uint8_t *)ctx->data;

		uint32_t i = ctx->datalen;

		// Pad whatever data is left in the buffer.
		if (ctx->datalen < 56)
		{
			cdata[i++] = 0x80;
			while (i < 56)
			{
				cdata[i++] = 0x00;
			}
		}
		else
		{
			cdata[i++] = 0x80;
			while (i < 64)
			{
				cdata[i++] = 0x00;
			}
			SHA256_Transform(ctx, cdata);
			memset(cdata, 0, 56);
		}

		// Append to the padding the total message's length in bits and transform.
		ctx->bitlen += ctx->datalen * 8;
		cdata[63] = ctx->bitlen;
		cdata[62] = ctx->bitlen >> 8;
		cdata[61] = ctx->bitlen >> 16;
		cdata[60] = ctx->bitlen >> 24;
		cdata[59] = ctx->bitlenH;
		cdata[58] = ctx->bitlenH >> 8;
		cdata[57] = ctx->bitlenH >> 16;
		cdata[56] = ctx->bitlenH >> 24;
		SHA256_Transform(ctx, cdata);

		// Since this implementation uses little endian byte ordering and SHA uses big endian,
		// reverse all the bytes when copying the final state to the output hash.
		for (i = 0; i < 4; ++i)
		{
			hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
		}
	}

	void set_state(_SHA256_CTX *ctx, uint32_t* state, size_t size)
	{
		memcpy(ctx->state, state, 32);
		ctx->datalen = 0;
		ctx->bitlen = size << 3;
		ctx->bitlenH = 0;
		ctx->md_len = SHA256_BLOCK_SIZE;
	}

	void shasha(uint32_t* state, uint64_t nonce, uint8_t *hash)
	{
		_SHA256_CTX ctx;

		memcpy(ctx.h, state, 32);

		((uint64_t*)ctx.data)[0] = nonce;
		((uint64_t*)ctx.data)[1] = 0x80;
		memset(ctx.data + 4, 0, 40);
		((uint64_t*)ctx.data)[7] = 0x400E000000000000;
		SHA256_Transform(&ctx, (uint8_t*)ctx.data);

		WriteBE64x32(((uint64_t*)ctx.data), ((uint64_t*)ctx.h)[0]);
		WriteBE64x32(((uint64_t*)ctx.data) + 1, ((uint64_t*)ctx.h)[1]);
		WriteBE64x32(((uint64_t*)ctx.data) + 2, ((uint64_t*)ctx.h)[2]);
		WriteBE64x32(((uint64_t*)ctx.data) + 3, ((uint64_t*)ctx.h)[3]);

		((uint64_t*)ctx.h)[0] = 0xbb67ae856a09e667;
		((uint64_t*)ctx.h)[1] = 0xa54ff53a3c6ef372;
		((uint64_t*)ctx.h)[2] = 0x9b05688c510e527f;
		((uint64_t*)ctx.h)[3] = 0x5be0cd191f83d9ab;

		((uint64_t*)ctx.data)[4] = 0x80;
		memset(ctx.data + 10, 0, 16);
		((uint64_t*)ctx.data)[7] = 0x0001000000000000;
		SHA256_Transform(&ctx, (uint8_t*)ctx.data);

		WriteBE64x32((uint64_t*)hash, ((uint64_t*)ctx.h)[0]);
		WriteBE64x32((uint64_t*)(hash + 8), ((uint64_t*)ctx.h)[1]);
		WriteBE64x32((uint64_t*)(hash + 16), ((uint64_t*)ctx.h)[2]);
		WriteBE64x32((uint64_t*)(hash + 24), ((uint64_t*)ctx.h)[3]);
	}
}
