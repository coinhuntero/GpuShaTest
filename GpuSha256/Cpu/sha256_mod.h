#pragma once

#include <stdint.h>

#define SHA256_BLOCK_SIZE 32

namespace mod
{
    void shasha(uint32_t* state, uint64_t nonce, uint8_t *hash);

    void search_nonce(uint32_t const* hashState,
        uint64_t startNonce,
        uint32_t iterations,
        uint32_t const* targetHash,
        uint64_t *output,
        uint32_t *outputHash);
}