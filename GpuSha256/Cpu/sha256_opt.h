#ifndef SHA256_OPT_H
#define SHA256_OPT_H

#include <stdint.h>

#define SHA256_BLOCK_SIZE 32     

namespace opt
{ 
    typedef struct
    {
        uint8_t data[64];
        uint32_t datalen;
        unsigned long long bitlen;
        uint32_t state[8];
    } SHA256_CTX;

    void sha256_init(SHA256_CTX *ctx);
    void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
    void sha256_final(SHA256_CTX *ctx, uint8_t *hash);

	void set_state(SHA256_CTX *ctx, uint32_t* state, uint8_t* data);

	void shasha(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t *hash);
}
#endif  
