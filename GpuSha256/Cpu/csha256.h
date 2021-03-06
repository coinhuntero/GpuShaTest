#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stdlib.h>
#include <string>

/** A hasher class for SHA-256. */
class CSHA256
{
private:
    uint32_t _state[8];
    unsigned char _buf[64];
    uint64_t _bytes;

public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA256();
    void SetState(const uint32_t* state, const uint8_t* data, size_t size);
    CSHA256& Write(const uint8_t* data, size_t len);
    void Finalize(uint8_t hash[OUTPUT_SIZE]);
    CSHA256& Reset();
};

#endif // SHA256_H
