#include "sha256_mod.h"
#include <cstdio>
#include <string.h>

////// SHA-256

#define ulong uint64_t
#define uint uint32_t
#define uchar uint8_t
#define OUTPUT_SIZE 256
#define OUTPUT_MASK 255

uint rotate(uint x, uint n)
{
    return (x << n) | (x >> (32 - n));
}

//uint inline bytereverse(uint x)
//{
//    return (((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24));
//}
//
//uint rot(uint x, uint y)
//{
//    return rotate(x, (uint)y);
//}
//
//void inline sharound(uint a, uint b, uint c, uint& d, uint e, uint f, uint g, uint& h, uint x, uint K)
//{
//    uint t1 = h + (rot(e, 26) ^ rot(e, 21) ^ rot(e, 7)) + (g ^ (e&(f^g))) + K + x;
//    uint t2 = (rot(a, 30) ^ rot(a, 19) ^ rot(a, 10)) + ((a&b) | (c&(a | b)));
//    d += t1;
//    h = t1 + t2;
//}

void DumpHex(uint *byteArray, uint length)
{
    length <<= 2;
    int width = 0;
    for(uchar* p = (uchar*)byteArray; length > 0; ++p)
    {
        if(width >= 16)
        {
            printf("\n");
            width = 0;
        }
        printf("%02x ", *p);
        --length;
        ++width;
    }
    printf("\n\n");
}


namespace gsim
{
#define bytereverse(x) ( ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24) )
#define rot(x, y) rotate(x, (uint)y)
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
//#define Maj(x, y, z) ((x & y) | (z & (x | y)))
#define Ma(x, y, z) ((y & z) | (x & (y | z)))
#define Sigma0(x) (rot(x, 30) ^ rot(x, 19) ^ rot(x, 10))
#define Sigma1(x) (rot(x, 26) ^ rot(x, 21) ^ rot(x, 7))
#define sigma0(x) (rot(x, 25) ^ rot(x, 14) ^ (x >> 3U))
#define sigma1(x) (rot(x, 15) ^ rot(x, 13) ^ (x >> 10U))
#define Round(a, b, c, d, e, f, g, h, k, w)\
{\
    t1 = h + Sigma1(e) + Ch(e, f, g) + k + w;\
    t2 = Sigma0(a) + Ma(a, b, c);\
    d += t1;\
    h = t1 + t2;\
}

    //uint Ch(uint x, uint y, uint z) { return z ^ (x & (y ^ z)); }
    //uint Maj(uint x, uint y, uint z) { return (x & y) | (z & (x | y)); }
    //uint Sigma0(uint x) { return rot(x, 30) ^ rot(x, 19) ^ rot(x, 10); }
    //uint Sigma1(uint x) { return rot(x, 26) ^ rot(x, 21) ^ rot(x, 7); }
    //uint sigma0(uint x) { return rot(x, 25) ^ rot(x, 14) ^ (x >> 3U); }
    //uint sigma1(uint x) { return rot(x, 15) ^ rot(x, 13) ^ (x >> 10U); }
    //void inline Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t k, uint32_t w)
    //{
    //    uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k + w;
    //    uint32_t t2 = Sigma0(a) + Maj(a, b, c);
    //    d += t1;
    //    h = t1 + t2;
    //}

    void search_nonce(uint const* state,
        uint const* data,
        ulong startNonce,
        uint iterations,
        uint const* targetHash,
        ulong *output,
        uint *outputHash)
    {
        ulong nonce = startNonce + 0;//get_global_id(0);

        uint a2, b2, c2, d2, e2, f2, g2, h2;
        uint t1, t2;

        uint a = state[0];
        uint b = state[1];
        uint c = state[2];
        uint d = state[3];
        uint e = state[4];
        uint f = state[5];
        uint g = state[6];
        uint h = state[7];

        uint w0 = bytereverse(data[0]);
        uint w1 = bytereverse(data[1]);
        uint w2 = bytereverse(data[2]);
        uint w3 = bytereverse(data[3]);
        uint w4 = bytereverse(data[4]);
        uint w5 = bytereverse(data[5]);
        uint w6 = bytereverse(data[6]);
        uint w7 = bytereverse(data[7]);
        uint w8 = bytereverse(data[8]);
        uint w9 = bytereverse(data[9]);
        uint w10 = bytereverse(data[10]);
        uint w11 = bytereverse(data[11]);
        uint w12 = bytereverse(data[12]);
        uint w13 = bytereverse(data[13]);
        uint w14 = bytereverse((uint)nonce);
        uint w15 = bytereverse((uint)(nonce >> 32));

        Round(a, b, c, d, e, f, g, h, 0x428a2f98U, w0);
        Round(h, a, b, c, d, e, f, g, 0x71374491U, w1);
        Round(g, h, a, b, c, d, e, f, 0xb5c0fbcfU, w2);
        Round(f, g, h, a, b, c, d, e, 0xe9b5dba5U, w3);
        Round(e, f, g, h, a, b, c, d, 0x3956c25bU, w4);
        Round(d, e, f, g, h, a, b, c, 0x59f111f1U, w5);
        Round(c, d, e, f, g, h, a, b, 0x923f82a4U, w6);
        Round(b, c, d, e, f, g, h, a, 0xab1c5ed5U, w7);
        Round(a, b, c, d, e, f, g, h, 0xd807aa98U, w8);
        Round(h, a, b, c, d, e, f, g, 0x12835b01U, w9);
        Round(g, h, a, b, c, d, e, f, 0x243185beU, w10);
        Round(f, g, h, a, b, c, d, e, 0x550c7dc3U, w11);
        Round(e, f, g, h, a, b, c, d, 0x72be5d74U, w12);
        Round(d, e, f, g, h, a, b, c, 0x80deb1feU, w13);
        Round(c, d, e, f, g, h, a, b, 0x9bdc06a7U, w14);
        Round(b, c, d, e, f, g, h, a, 0xc19bf174U, w15);
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, d, e, f, g, h, 0xe49b69c1U, w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, c, d, e, f, g, 0xefbe4786U, w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, b, c, d, e, f, 0x0fc19dc6U, w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, a, b, c, d, e, 0x240ca1ccU, w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, h, a, b, c, d, 0x2de92c6fU, w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, g, h, a, b, c, 0x4a7484aaU, w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, f, g, h, a, b, 0x5cb0a9dcU, w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, e, f, g, h, a, 0x76f988daU, w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, d, e, f, g, h, 0x983e5152U, w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, c, d, e, f, g, 0xa831c66dU, w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, b, c, d, e, f, 0xb00327c8U, w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, a, b, c, d, e, 0xbf597fc7U, w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, h, a, b, c, d, 0xc6e00bf3U, w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, g, h, a, b, c, 0xd5a79147U, w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, f, g, h, a, b, 0x06ca6351U, w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, e, f, g, h, a, 0x14292967U, w15);
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, d, e, f, g, h, 0x27b70a85U, w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, c, d, e, f, g, 0x2e1b2138U, w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, b, c, d, e, f, 0x4d2c6dfcU, w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, a, b, c, d, e, 0x53380d13U, w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, h, a, b, c, d, 0x650a7354U, w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, g, h, a, b, c, 0x766a0abbU, w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, f, g, h, a, b, 0x81c2c92eU, w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, e, f, g, h, a, 0x92722c85U, w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1U, w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, c, d, e, f, g, 0xa81a664bU, w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, b, c, d, e, f, 0xc24b8b70U, w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, a, b, c, d, e, 0xc76c51a3U, w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, h, a, b, c, d, 0xd192e819U, w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, g, h, a, b, c, 0xd6990624U, w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, f, g, h, a, b, 0xf40e3585U, w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, e, f, g, h, a, 0x106aa070U, w15);
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, d, e, f, g, h, 0x19a4c116U, w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, c, d, e, f, g, 0x1e376c08U, w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, b, c, d, e, f, 0x2748774cU, w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, a, b, c, d, e, 0x34b0bcb5U, w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, h, a, b, c, d, 0x391c0cb3U, w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, g, h, a, b, c, 0x4ed8aa4aU, w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, f, g, h, a, b, 0x5b9cca4fU, w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, e, f, g, h, a, 0x682e6ff3U, w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, d, e, f, g, h, 0x748f82eeU, w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, c, d, e, f, g, 0x78a5636fU, w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, b, c, d, e, f, 0x84c87814U, w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, a, b, c, d, e, 0x8cc70208U, w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, h, a, b, c, d, 0x90befffaU, w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, g, h, a, b, c, 0xa4506cebU, w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, f, g, h, a, b, 0xbef9a3f7U, w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, e, f, g, h, a, 0xc67178f2U, w15);

        a2 = a = a + state[0];
        b2 = b = b + state[1];
        c2 = c = c + state[2];
        d2 = d = d + state[3];
        e2 = e = e + state[4];
        f2 = f = f + state[5];
        g2 = g = g + state[6];
        h2 = h = h + state[7];

        w0 = 0x80000000U;
        w1 = 0;
        w2 = 0;
        w3 = 0;
        w4 = 0;
        w5 = 0;
        w6 = 0;
        w7 = 0;
        w8 = 0;
        w9 = 0;
        w10 = 0;
        w11 = 0;
        w12 = 0;
        w13 = 0;
        w14 = 0;
        w15 = 0x00001000U;

        Round(a, b, c, d, e, f, g, h, 0x428a2f98U, w0);
        Round(h, a, b, c, d, e, f, g, 0x71374491U, w1);
        Round(g, h, a, b, c, d, e, f, 0xb5c0fbcfU, w2);
        Round(f, g, h, a, b, c, d, e, 0xe9b5dba5U, w3);
        Round(e, f, g, h, a, b, c, d, 0x3956c25bU, w4);
        Round(d, e, f, g, h, a, b, c, 0x59f111f1U, w5);
        Round(c, d, e, f, g, h, a, b, 0x923f82a4U, w6);
        Round(b, c, d, e, f, g, h, a, 0xab1c5ed5U, w7);
        Round(a, b, c, d, e, f, g, h, 0xd807aa98U, w8);
        Round(h, a, b, c, d, e, f, g, 0x12835b01U, w9);
        Round(g, h, a, b, c, d, e, f, 0x243185beU, w10);
        Round(f, g, h, a, b, c, d, e, 0x550c7dc3U, w11);
        Round(e, f, g, h, a, b, c, d, 0x72be5d74U, w12);
        Round(d, e, f, g, h, a, b, c, 0x80deb1feU, w13);
        Round(c, d, e, f, g, h, a, b, 0x9bdc06a7U, w14);
        Round(b, c, d, e, f, g, h, a, 0xc19bf174U, w15);
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, d, e, f, g, h, 0xe49b69c1U, w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, c, d, e, f, g, 0xefbe4786U, w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, b, c, d, e, f, 0x0fc19dc6U, w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, a, b, c, d, e, 0x240ca1ccU, w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, h, a, b, c, d, 0x2de92c6fU, w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, g, h, a, b, c, 0x4a7484aaU, w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, f, g, h, a, b, 0x5cb0a9dcU, w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, e, f, g, h, a, 0x76f988daU, w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, d, e, f, g, h, 0x983e5152U, w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, c, d, e, f, g, 0xa831c66dU, w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, b, c, d, e, f, 0xb00327c8U, w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, a, b, c, d, e, 0xbf597fc7U, w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, h, a, b, c, d, 0xc6e00bf3U, w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, g, h, a, b, c, 0xd5a79147U, w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, f, g, h, a, b, 0x06ca6351U, w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, e, f, g, h, a, 0x14292967U, w15);
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, d, e, f, g, h, 0x27b70a85U, w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, c, d, e, f, g, 0x2e1b2138U, w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, b, c, d, e, f, 0x4d2c6dfcU, w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, a, b, c, d, e, 0x53380d13U, w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, h, a, b, c, d, 0x650a7354U, w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, g, h, a, b, c, 0x766a0abbU, w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, f, g, h, a, b, 0x81c2c92eU, w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, e, f, g, h, a, 0x92722c85U, w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1U, w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, c, d, e, f, g, 0xa81a664bU, w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, b, c, d, e, f, 0xc24b8b70U, w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, a, b, c, d, e, 0xc76c51a3U, w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, h, a, b, c, d, 0xd192e819U, w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, g, h, a, b, c, 0xd6990624U, w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, f, g, h, a, b, 0xf40e3585U, w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, e, f, g, h, a, 0x106aa070U, w15);
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, d, e, f, g, h, 0x19a4c116U, w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, c, d, e, f, g, 0x1e376c08U, w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, b, c, d, e, f, 0x2748774cU, w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, a, b, c, d, e, 0x34b0bcb5U, w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, h, a, b, c, d, 0x391c0cb3U, w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, g, h, a, b, c, 0x4ed8aa4aU, w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, f, g, h, a, b, 0x5b9cca4fU, w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, e, f, g, h, a, 0x682e6ff3U, w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, d, e, f, g, h, 0x748f82eeU, w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, c, d, e, f, g, 0x78a5636fU, w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, b, c, d, e, f, 0x84c87814U, w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, a, b, c, d, e, 0x8cc70208U, w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, h, a, b, c, d, 0x90befffaU, w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, g, h, a, b, c, 0xa4506cebU, w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, f, g, h, a, b, 0xbef9a3f7U, w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, e, f, g, h, a, 0xc67178f2U, w15);

        // hash the hash now

        w0 = a2 + a;
        w1 = b2 + b;
        w2 = c2 + c;
        w3 = d2 + d;
        w4 = e2 + e;
        w5 = f2 + f;
        w6 = g2 + g;
        w7 = h2 + h;
        w8 = 0x80000000U;
        w9 = 0;
        w10 = 0;
        w11 = 0;
        w12 = 0;
        w13 = 0;
        w14 = 0;
        w15 = 0x00000100U;

        a = 0x6a09e667U;
        b = 0xbb67ae85U;
        c = 0x3c6ef372U;
        d = 0xa54ff53aU;
        e = 0x510e527fU;
        f = 0x9b05688cU;
        g = 0x1f83d9abU;
        h = 0x5be0cd19U;

        Round(a, b, c, d, e, f, g, h, 0x428a2f98U, w0);
        Round(h, a, b, c, d, e, f, g, 0x71374491U, w1);
        Round(g, h, a, b, c, d, e, f, 0xb5c0fbcfU, w2);
        Round(f, g, h, a, b, c, d, e, 0xe9b5dba5U, w3);
        Round(e, f, g, h, a, b, c, d, 0x3956c25bU, w4);
        Round(d, e, f, g, h, a, b, c, 0x59f111f1U, w5);
        Round(c, d, e, f, g, h, a, b, 0x923f82a4U, w6);
        Round(b, c, d, e, f, g, h, a, 0xab1c5ed5U, w7);
        Round(a, b, c, d, e, f, g, h, 0xd807aa98U, w8);
        Round(h, a, b, c, d, e, f, g, 0x12835b01U, w9);
        Round(g, h, a, b, c, d, e, f, 0x243185beU, w10);
        Round(f, g, h, a, b, c, d, e, 0x550c7dc3U, w11);
        Round(e, f, g, h, a, b, c, d, 0x72be5d74U, w12);
        Round(d, e, f, g, h, a, b, c, 0x80deb1feU, w13);
        Round(c, d, e, f, g, h, a, b, 0x9bdc06a7U, w14);
        Round(b, c, d, e, f, g, h, a, 0xc19bf174U, w15);
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, d, e, f, g, h, 0xe49b69c1U, w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, c, d, e, f, g, 0xefbe4786U, w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, b, c, d, e, f, 0x0fc19dc6U, w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, a, b, c, d, e, 0x240ca1ccU, w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, h, a, b, c, d, 0x2de92c6fU, w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, g, h, a, b, c, 0x4a7484aaU, w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, f, g, h, a, b, 0x5cb0a9dcU, w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, e, f, g, h, a, 0x76f988daU, w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, d, e, f, g, h, 0x983e5152U, w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, c, d, e, f, g, 0xa831c66dU, w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, b, c, d, e, f, 0xb00327c8U, w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, a, b, c, d, e, 0xbf597fc7U, w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, h, a, b, c, d, 0xc6e00bf3U, w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, g, h, a, b, c, 0xd5a79147U, w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, f, g, h, a, b, 0x06ca6351U, w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, e, f, g, h, a, 0x14292967U, w15);
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, d, e, f, g, h, 0x27b70a85U, w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, c, d, e, f, g, 0x2e1b2138U, w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, b, c, d, e, f, 0x4d2c6dfcU, w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, a, b, c, d, e, 0x53380d13U, w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, h, a, b, c, d, 0x650a7354U, w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, g, h, a, b, c, 0x766a0abbU, w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, f, g, h, a, b, 0x81c2c92eU, w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, e, f, g, h, a, 0x92722c85U, w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1U, w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, c, d, e, f, g, 0xa81a664bU, w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, b, c, d, e, f, 0xc24b8b70U, w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, a, b, c, d, e, 0xc76c51a3U, w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, h, a, b, c, d, 0xd192e819U, w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, g, h, a, b, c, 0xd6990624U, w13);
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, f, g, h, a, b, 0xf40e3585U, w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, e, f, g, h, a, 0x106aa070U, w15);
        w0 += sigma1(w14) + w9 + sigma0(w1);
        Round(a, b, c, d, e, f, g, h, 0x19a4c116U, w0);
        w1 += sigma1(w15) + w10 + sigma0(w2);
        Round(h, a, b, c, d, e, f, g, 0x1e376c08U, w1);
        w2 += sigma1(w0) + w11 + sigma0(w3);
        Round(g, h, a, b, c, d, e, f, 0x2748774cU, w2);
        w3 += sigma1(w1) + w12 + sigma0(w4);
        Round(f, g, h, a, b, c, d, e, 0x34b0bcb5U, w3);
        w4 += sigma1(w2) + w13 + sigma0(w5);
        Round(e, f, g, h, a, b, c, d, 0x391c0cb3U, w4);
        w5 += sigma1(w3) + w14 + sigma0(w6);
        Round(d, e, f, g, h, a, b, c, 0x4ed8aa4aU, w5);
        w6 += sigma1(w4) + w15 + sigma0(w7);
        Round(c, d, e, f, g, h, a, b, 0x5b9cca4fU, w6);
        w7 += sigma1(w5) + w0 + sigma0(w8);
        Round(b, c, d, e, f, g, h, a, 0x682e6ff3U, w7);
        w8 += sigma1(w6) + w1 + sigma0(w9);
        Round(a, b, c, d, e, f, g, h, 0x748f82eeU, w8);
        w9 += sigma1(w7) + w2 + sigma0(w10);
        Round(h, a, b, c, d, e, f, g, 0x78a5636fU, w9);
        w10 += sigma1(w8) + w3 + sigma0(w11);
        Round(g, h, a, b, c, d, e, f, 0x84c87814U, w10);
        w11 += sigma1(w9) + w4 + sigma0(w12);
        Round(f, g, h, a, b, c, d, e, 0x8cc70208U, w11);
        w12 += sigma1(w10) + w5 + sigma0(w13);
        Round(e, f, g, h, a, b, c, d, 0x90befffaU, w12);
        w13 += sigma1(w11) + w6 + sigma0(w14);
        Round(d, e, f, g, h, a, b, c, 0xa4506cebU, w13);
        ///////////////////
        //we don't need to do these last 2 rounds as they update F, B, E and A, but we only care about G and H
        w14 += sigma1(w12) + w7 + sigma0(w15);
        Round(c, d, e, f, g, h, a, b, 0xbef9a3f7U, w14);
        w15 += sigma1(w13) + w8 + sigma0(w0);
        Round(b, c, d, e, f, g, h, a, 0xc67178f2U, w15);


        ////////////////
        output[0] = nonce;
        outputHash[0] = bytereverse(a + 0x6a09e667U);
        outputHash[1] = bytereverse(b + 0xbb67ae85U);
        outputHash[2] = bytereverse(c + 0x3c6ef372U);
        outputHash[3] = bytereverse(d + 0xa54ff53aU);
        outputHash[4] = bytereverse(e + 0x510e527fU);
        outputHash[5] = bytereverse(f + 0x9b05688cU);
        outputHash[6] = bytereverse(g + 0x1f83d9abU);
        outputHash[7] = bytereverse(h + 0x5be0cd19U);
    }

    void search_nonce2(uint const* hashState,
        uint const* data,
        ulong startNonce,
        uint iterations,
        uint const* targetHash,
        ulong *output,
        ulong id)
    {
        uint hash[8];
        uint minHash[8];
        uint localHashState[8];
        uint localData[16];
        ulong min_nonce = 0;
        //uint id = get_global_id(0);
        ulong nonce = startNonce + id * iterations;
        /*
        #pragma unroll
                for(uint i = 0; i < 8; ++i)
                {
                    minHash[i] = targetHash[i];
                }
        #pragma unroll
                for(uint i = 0; i < 8; ++i)
                {
                    localHashState[i] = hashState[i];
                }
        #pragma unroll
                for(uint i = 0; i < 14; ++i)
                {
                    localData[i] = data[i];
                }
                for(uint i = 0; i < iterations; ++i)
                {
                    shasha(localHashState, localData, nonce, (uchar*)hash);

                    if(cmphash(hash, minHash) < 0)
                    {
        #pragma unroll
                        for(uint i = 0; i < 8; ++i)
                        {
                            minHash[i] = hash[i];
                        }
                        min_nonce = nonce;
                    }
                    ++nonce;
                }
                if(min_nonce > 0)
                {
                    output[OUTPUT_SIZE] = output[min_nonce & OUTPUT_MASK] = min_nonce;
                }*/
    }

}
