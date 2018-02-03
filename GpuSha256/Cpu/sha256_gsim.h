#pragma once

#include <stdint.h>

#define SHA256_BLOCK_SIZE 32

namespace gsim
{

    void search_nonce(uint32_t const* hashState,
		uint32_t const* data,
        uint64_t startNonce,
        uint32_t iterations,
        uint32_t const* targetHash,
        uint64_t *output,
        uint32_t *outputHash);

    void search_nonce2(uint32_t const* hashState,
        uint32_t const* data,
        uint64_t startNonce,
        uint32_t iterations,
        uint32_t const* targetHash,
        uint64_t *output,
        uint64_t id);
}