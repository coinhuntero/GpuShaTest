#include "sha256_mod.h"
#include <cstdio>
#include <string.h>

////// SHA-256

#define ulong uint64_t
#define uint uint32_t
#define uchar uint8_t
#define OUTPUT_SIZE 256
#define OUTPUT_MASK 255

int rotate(int x, int n)
{
    return (x << n) | (x >> (32 - n));
}

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
//#define bytereverse(x) ( ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24) )
//#define rot(x, y) rotate(x, (uint)y)
#define R(x) (work[x] = (rot(work[x - 2], 15) ^ rot(work[x - 2], 13) ^ ((work[x - 2] & 0xffffffff) >> 10)) + work[x - 7] + (rot(work[x - 15], 25) ^ rot(work[x - 15], 14) ^ ((work[x - 15] & 0xffffffff) >> 3)) + work[x - 16])
//#define sharound(a, b, c, d, e, f, g, h, x, K) { t1 = h + (rot(e, 26) ^ rot(e, 21) ^ rot(e, 7)) + (g ^ (e&(f^g))) + K + x; t2 = (rot(a, 30) ^ rot(a, 19) ^ rot(a, 10)) + ((a&b) | (c&(a | b))); d += t1; h = t1 + t2; }
    uint inline bytereverse(uint x)
    {
        return (((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24));
    }

    uint rot(uint x, uint y)
    {
        return rotate(x, (uint)y);
    }

    void inline sharound(uint a, uint b, uint c, uint& d, uint e, uint f, uint g, uint& h, uint x, uint K)
    { 
        uint t1 = h + (rot(e, 26) ^ rot(e, 21) ^ rot(e, 7)) + (g ^ (e&(f^g))) + K + x;
        uint t2 = (rot(a, 30) ^ rot(a, 19) ^ rot(a, 10)) + ((a&b) | (c&(a | b)));
        d += t1; 
        h = t1 + t2; 
    }
    

	int cmphash(uint *l, uint *r)
	{
#pragma unroll
		for (int i = 7; i >= 0; --i)
		{
			if (l[i] != r[i])
			{
				return (l[i] < r[i] ? -1 : 1);
			}
		}
		return 0;
	}

	void search_nonce(uint const* state,
		uint const* data,
		ulong startNonce,
		uint iterations,
		uint const* targetHash,
		ulong *output,
		uint *outputHash)
	{
        ulong nonce = startNonce + 0;//get_global_id(0);

        uint work[64];
        uint A, B, C, D, E, F, G, H;
        uint t1, t2;

        A = state[0];
        B = state[1];
        C = state[2];
        D = state[3];
        E = state[4];
        F = state[5];
        G = state[6];
        H = state[7];

        work[0] = data[0];
        work[1] = data[1];
        work[2] = data[2];
        work[3] = data[3];
        work[4] = data[4];
        work[5] = data[5];
        work[6] = data[6];
        work[7] = data[7];
        work[8] = data[8];
        work[9] = data[9];
        work[10] = data[10];
        work[11] = data[11];
        work[12] = data[12];
        work[13] = data[13];
        ((ulong*)work)[7] = nonce;

        sharound(A, B, C, D, E, F, G, H, bytereverse(work[0]), 0x428A2F98);
        sharound(H, A, B, C, D, E, F, G, bytereverse(work[1]), 0x71374491);
        sharound(G, H, A, B, C, D, E, F, bytereverse(work[2]), 0xB5C0FBCF);
        sharound(F, G, H, A, B, C, D, E, bytereverse(work[3]), 0xE9B5DBA5);
        sharound(E, F, G, H, A, B, C, D, bytereverse(work[4]), 0x3956C25B);
        sharound(D, E, F, G, H, A, B, C, bytereverse(work[5]), 0x59F111F1);
        sharound(C, D, E, F, G, H, A, B, bytereverse(work[6]), 0x923F82A4);
        sharound(B, C, D, E, F, G, H, A, bytereverse(work[7]), 0xAB1C5ED5);
        sharound(A, B, C, D, E, F, G, H, bytereverse(work[8]), 0xD807AA98);
        sharound(H, A, B, C, D, E, F, G, bytereverse(work[9]), 0x12835B01);
        sharound(G, H, A, B, C, D, E, F, bytereverse(work[10]), 0x243185BE);
        sharound(F, G, H, A, B, C, D, E, bytereverse(work[11]), 0x550C7DC3);
        sharound(E, F, G, H, A, B, C, D, bytereverse(work[12]), 0x72BE5D74);
        sharound(D, E, F, G, H, A, B, C, bytereverse(work[13]), 0x80DEB1FE);
        sharound(C, D, E, F, G, H, A, B, bytereverse(work[14]), 0x9BDC06A7);
        sharound(B, C, D, E, F, G, H, A, bytereverse(work[15]), 0xC19BF174);
        sharound(A, B, C, D, E, F, G, H, R(16), 0xE49B69C1);
        sharound(H, A, B, C, D, E, F, G, R(17), 0xEFBE4786);
        sharound(G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6);
        sharound(F, G, H, A, B, C, D, E, R(19), 0x240CA1CC);
        sharound(E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F);
        sharound(D, E, F, G, H, A, B, C, R(21), 0x4A7484AA);
        sharound(C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC);
        sharound(B, C, D, E, F, G, H, A, R(23), 0x76F988DA);
        sharound(A, B, C, D, E, F, G, H, R(24), 0x983E5152);
        sharound(H, A, B, C, D, E, F, G, R(25), 0xA831C66D);
        sharound(G, H, A, B, C, D, E, F, R(26), 0xB00327C8);
        sharound(F, G, H, A, B, C, D, E, R(27), 0xBF597FC7);
        sharound(E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3);
        sharound(D, E, F, G, H, A, B, C, R(29), 0xD5A79147);
        sharound(C, D, E, F, G, H, A, B, R(30), 0x06CA6351);
        sharound(B, C, D, E, F, G, H, A, R(31), 0x14292967);
        sharound(A, B, C, D, E, F, G, H, R(32), 0x27B70A85);
        sharound(H, A, B, C, D, E, F, G, R(33), 0x2E1B2138);
        sharound(G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC);
        sharound(F, G, H, A, B, C, D, E, R(35), 0x53380D13);
        sharound(E, F, G, H, A, B, C, D, R(36), 0x650A7354);
        sharound(D, E, F, G, H, A, B, C, R(37), 0x766A0ABB);
        sharound(C, D, E, F, G, H, A, B, R(38), 0x81C2C92E);
        sharound(B, C, D, E, F, G, H, A, R(39), 0x92722C85);
        sharound(A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1);
        sharound(H, A, B, C, D, E, F, G, R(41), 0xA81A664B);
        sharound(G, H, A, B, C, D, E, F, R(42), 0xC24B8B70);
        sharound(F, G, H, A, B, C, D, E, R(43), 0xC76C51A3);
        sharound(E, F, G, H, A, B, C, D, R(44), 0xD192E819);
        sharound(D, E, F, G, H, A, B, C, R(45), 0xD6990624);
        sharound(C, D, E, F, G, H, A, B, R(46), 0xF40E3585);
        sharound(B, C, D, E, F, G, H, A, R(47), 0x106AA070);
        sharound(A, B, C, D, E, F, G, H, R(48), 0x19A4C116);
        sharound(H, A, B, C, D, E, F, G, R(49), 0x1E376C08);
        sharound(G, H, A, B, C, D, E, F, R(50), 0x2748774C);
        sharound(F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5);
        sharound(E, F, G, H, A, B, C, D, R(52), 0x391C0CB3);
        sharound(D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A);
        sharound(C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F);
        sharound(B, C, D, E, F, G, H, A, R(55), 0x682E6FF3);
        sharound(A, B, C, D, E, F, G, H, R(56), 0x748F82EE);
        sharound(H, A, B, C, D, E, F, G, R(57), 0x78A5636F);
        sharound(G, H, A, B, C, D, E, F, R(58), 0x84C87814);
        sharound(F, G, H, A, B, C, D, E, R(59), 0x8CC70208);
        sharound(E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA);
        sharound(D, E, F, G, H, A, B, C, R(61), 0xA4506CEB);
        sharound(C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7);
        sharound(B, C, D, E, F, G, H, A, R(63), 0xC67178F2);

        work[0] = 0x80;
        work[1] = 0;
        work[2] = 0;
        work[3] = 0;
        work[4] = 0;
        work[5] = 0;
        work[6] = 0;
        work[7] = 0;
        work[8] = 0;
        work[9] = 0;
        work[10] = 0;
        work[11] = 0;
        work[12] = 0;
        work[13] = 0;
        work[14] = 0;
        work[15] = 0x00100000;

        sharound(A, B, C, D, E, F, G, H, bytereverse(work[0]), 0x428A2F98);
        sharound(H, A, B, C, D, E, F, G, bytereverse(work[1]), 0x71374491);
        sharound(G, H, A, B, C, D, E, F, bytereverse(work[2]), 0xB5C0FBCF);
        sharound(F, G, H, A, B, C, D, E, bytereverse(work[3]), 0xE9B5DBA5);
        sharound(E, F, G, H, A, B, C, D, bytereverse(work[4]), 0x3956C25B);
        sharound(D, E, F, G, H, A, B, C, bytereverse(work[5]), 0x59F111F1);
        sharound(C, D, E, F, G, H, A, B, bytereverse(work[6]), 0x923F82A4);
        sharound(B, C, D, E, F, G, H, A, bytereverse(work[7]), 0xAB1C5ED5);
        sharound(A, B, C, D, E, F, G, H, bytereverse(work[8]), 0xD807AA98);
        sharound(H, A, B, C, D, E, F, G, bytereverse(work[9]), 0x12835B01);
        sharound(G, H, A, B, C, D, E, F, bytereverse(work[10]), 0x243185BE);
        sharound(F, G, H, A, B, C, D, E, bytereverse(work[11]), 0x550C7DC3);
        sharound(E, F, G, H, A, B, C, D, bytereverse(work[12]), 0x72BE5D74);
        sharound(D, E, F, G, H, A, B, C, bytereverse(work[13]), 0x80DEB1FE);
        sharound(C, D, E, F, G, H, A, B, bytereverse(work[14]), 0x9BDC06A7);
        sharound(B, C, D, E, F, G, H, A, bytereverse(work[15]), 0xC19BF174);
        sharound(A, B, C, D, E, F, G, H, R(16), 0xE49B69C1);
        sharound(H, A, B, C, D, E, F, G, R(17), 0xEFBE4786);
        sharound(G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6);
        sharound(F, G, H, A, B, C, D, E, R(19), 0x240CA1CC);
        sharound(E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F);
        sharound(D, E, F, G, H, A, B, C, R(21), 0x4A7484AA);
        sharound(C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC);
        sharound(B, C, D, E, F, G, H, A, R(23), 0x76F988DA);
        sharound(A, B, C, D, E, F, G, H, R(24), 0x983E5152);
        sharound(H, A, B, C, D, E, F, G, R(25), 0xA831C66D);
        sharound(G, H, A, B, C, D, E, F, R(26), 0xB00327C8);
        sharound(F, G, H, A, B, C, D, E, R(27), 0xBF597FC7);
        sharound(E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3);
        sharound(D, E, F, G, H, A, B, C, R(29), 0xD5A79147);
        sharound(C, D, E, F, G, H, A, B, R(30), 0x06CA6351);
        sharound(B, C, D, E, F, G, H, A, R(31), 0x14292967);
        sharound(A, B, C, D, E, F, G, H, R(32), 0x27B70A85);
        sharound(H, A, B, C, D, E, F, G, R(33), 0x2E1B2138);
        sharound(G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC);
        sharound(F, G, H, A, B, C, D, E, R(35), 0x53380D13);
        sharound(E, F, G, H, A, B, C, D, R(36), 0x650A7354);
        sharound(D, E, F, G, H, A, B, C, R(37), 0x766A0ABB);
        sharound(C, D, E, F, G, H, A, B, R(38), 0x81C2C92E);
        sharound(B, C, D, E, F, G, H, A, R(39), 0x92722C85);
        sharound(A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1);
        sharound(H, A, B, C, D, E, F, G, R(41), 0xA81A664B);
        sharound(G, H, A, B, C, D, E, F, R(42), 0xC24B8B70);
        sharound(F, G, H, A, B, C, D, E, R(43), 0xC76C51A3);
        sharound(E, F, G, H, A, B, C, D, R(44), 0xD192E819);
        sharound(D, E, F, G, H, A, B, C, R(45), 0xD6990624);
        sharound(C, D, E, F, G, H, A, B, R(46), 0xF40E3585);
        sharound(B, C, D, E, F, G, H, A, R(47), 0x106AA070);
        sharound(A, B, C, D, E, F, G, H, R(48), 0x19A4C116);
        sharound(H, A, B, C, D, E, F, G, R(49), 0x1E376C08);
        sharound(G, H, A, B, C, D, E, F, R(50), 0x2748774C);
        sharound(F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5);
        sharound(E, F, G, H, A, B, C, D, R(52), 0x391C0CB3);
        sharound(D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A);
        sharound(C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F);
        sharound(B, C, D, E, F, G, H, A, R(55), 0x682E6FF3);
        sharound(A, B, C, D, E, F, G, H, R(56), 0x748F82EE);
        sharound(H, A, B, C, D, E, F, G, R(57), 0x78A5636F);
        sharound(G, H, A, B, C, D, E, F, R(58), 0x84C87814);
        sharound(F, G, H, A, B, C, D, E, R(59), 0x8CC70208);
        sharound(E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA);
        sharound(D, E, F, G, H, A, B, C, R(61), 0xA4506CEB);
        sharound(C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7);
        sharound(B, C, D, E, F, G, H, A, R(63), 0xC67178F2);

        // hash the hash now

        work[0] = state[0] + A;
        work[1] = state[1] + B;
        work[2] = state[2] + C;
        work[3] = state[3] + D;
        work[4] = state[4] + E;
        work[5] = state[5] + F;
        work[6] = state[6] + G;
        work[7] = state[7] + H;
        work[8] = 0x80000000;
        work[9] = 0x00000000;
        work[10] = 0x00000000;
        work[11] = 0x00000000;
        work[12] = 0x00000000;
        work[13] = 0x00000000;
        work[14] = 0x00000000;
        work[15] = 0x00000100;

        A = 0x6a09e667;
        B = 0xbb67ae85;
        C = 0x3c6ef372;
        D = 0xa54ff53a;
        E = 0x510e527f;
        F = 0x9b05688c;
        G = 0x1f83d9ab;
        H = 0x5be0cd19;

        sharound(A, B, C, D, E, F, G, H, bytereverse(work[0]), 0x428A2F98);
        sharound(H, A, B, C, D, E, F, G, bytereverse(work[1]), 0x71374491);
        sharound(G, H, A, B, C, D, E, F, bytereverse(work[2]), 0xB5C0FBCF);
        sharound(F, G, H, A, B, C, D, E, bytereverse(work[3]), 0xE9B5DBA5);
        sharound(E, F, G, H, A, B, C, D, bytereverse(work[4]), 0x3956C25B);
        sharound(D, E, F, G, H, A, B, C, bytereverse(work[5]), 0x59F111F1);
        sharound(C, D, E, F, G, H, A, B, bytereverse(work[6]), 0x923F82A4);
        sharound(B, C, D, E, F, G, H, A, bytereverse(work[7]), 0xAB1C5ED5);
        sharound(A, B, C, D, E, F, G, H, bytereverse(work[8]), 0xD807AA98);
        sharound(H, A, B, C, D, E, F, G, bytereverse(work[9]), 0x12835B01);
        sharound(G, H, A, B, C, D, E, F, bytereverse(work[10]), 0x243185BE);
        sharound(F, G, H, A, B, C, D, E, bytereverse(work[11]), 0x550C7DC3);
        sharound(E, F, G, H, A, B, C, D, bytereverse(work[12]), 0x72BE5D74);
        sharound(D, E, F, G, H, A, B, C, bytereverse(work[13]), 0x80DEB1FE);
        sharound(C, D, E, F, G, H, A, B, bytereverse(work[14]), 0x9BDC06A7);
        sharound(B, C, D, E, F, G, H, A, bytereverse(work[15]), 0xC19BF174);
        sharound(A, B, C, D, E, F, G, H, R(16), 0xE49B69C1);
        sharound(H, A, B, C, D, E, F, G, R(17), 0xEFBE4786);
        sharound(G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6);
        sharound(F, G, H, A, B, C, D, E, R(19), 0x240CA1CC);
        sharound(E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F);
        sharound(D, E, F, G, H, A, B, C, R(21), 0x4A7484AA);
        sharound(C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC);
        sharound(B, C, D, E, F, G, H, A, R(23), 0x76F988DA);
        sharound(A, B, C, D, E, F, G, H, R(24), 0x983E5152);
        sharound(H, A, B, C, D, E, F, G, R(25), 0xA831C66D);
        sharound(G, H, A, B, C, D, E, F, R(26), 0xB00327C8);
        sharound(F, G, H, A, B, C, D, E, R(27), 0xBF597FC7);
        sharound(E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3);
        sharound(D, E, F, G, H, A, B, C, R(29), 0xD5A79147);
        sharound(C, D, E, F, G, H, A, B, R(30), 0x06CA6351);
        sharound(B, C, D, E, F, G, H, A, R(31), 0x14292967);
        sharound(A, B, C, D, E, F, G, H, R(32), 0x27B70A85);
        sharound(H, A, B, C, D, E, F, G, R(33), 0x2E1B2138);
        sharound(G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC);
        sharound(F, G, H, A, B, C, D, E, R(35), 0x53380D13);
        sharound(E, F, G, H, A, B, C, D, R(36), 0x650A7354);
        sharound(D, E, F, G, H, A, B, C, R(37), 0x766A0ABB);
        sharound(C, D, E, F, G, H, A, B, R(38), 0x81C2C92E);
        sharound(B, C, D, E, F, G, H, A, R(39), 0x92722C85);
        sharound(A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1);
        sharound(H, A, B, C, D, E, F, G, R(41), 0xA81A664B);
        sharound(G, H, A, B, C, D, E, F, R(42), 0xC24B8B70);
        sharound(F, G, H, A, B, C, D, E, R(43), 0xC76C51A3);
        sharound(E, F, G, H, A, B, C, D, R(44), 0xD192E819);
        sharound(D, E, F, G, H, A, B, C, R(45), 0xD6990624);
        sharound(C, D, E, F, G, H, A, B, R(46), 0xF40E3585);
        sharound(B, C, D, E, F, G, H, A, R(47), 0x106AA070);
        sharound(A, B, C, D, E, F, G, H, R(48), 0x19A4C116);
        sharound(H, A, B, C, D, E, F, G, R(49), 0x1E376C08);
        sharound(G, H, A, B, C, D, E, F, R(50), 0x2748774C);
        sharound(F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5);
        sharound(E, F, G, H, A, B, C, D, R(52), 0x391C0CB3);
        sharound(D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A);
        sharound(C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F);
        sharound(B, C, D, E, F, G, H, A, R(55), 0x682E6FF3);
        sharound(A, B, C, D, E, F, G, H, R(56), 0x748F82EE);
        sharound(H, A, B, C, D, E, F, G, R(57), 0x78A5636F);
        sharound(G, H, A, B, C, D, E, F, R(58), 0x84C87814);
        sharound(F, G, H, A, B, C, D, E, R(59), 0x8CC70208);
        sharound(E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA);
        sharound(D, E, F, G, H, A, B, C, R(61), 0xA4506CEB);
        ///////////////////
        //we don't need to do these last 2 rounds as they update F, B, E and A, but we only care about G and H
        sharound(C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7);
        sharound(B, C, D, E, F, G, H, A, R(63), 0xC67178F2);

        ////////////////
		output[0] = nonce;
        outputHash[0] = bytereverse(A);
        outputHash[1] = bytereverse(B);
        outputHash[2] = bytereverse(C);
        outputHash[3] = bytereverse(D);
        outputHash[4] = bytereverse(E);
        outputHash[5] = bytereverse(F);
        outputHash[6] = bytereverse(G);
        outputHash[7] = bytereverse(H);
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
