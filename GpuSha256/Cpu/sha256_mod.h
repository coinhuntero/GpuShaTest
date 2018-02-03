#pragma once

#include <stdint.h>

#define SHA256_BLOCK_SIZE 32

namespace mod
{
    void shasha(uint32_t* state, uint32_t* data, uint64_t nonce, uint8_t *hash);
}