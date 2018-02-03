#define bytereverse(x) ( ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24) )
#define rot(x, y) rotate(x, (uint)y)
#define R(x) (work[x] = (rot(work[x - 2], 15) ^ rot(work[x - 2], 13) ^ ((work[x - 2] & 0xffffffff) >> 10)) + work[x - 7] + (rot(work[x - 15], 25) ^ rot(work[x - 15], 14) ^ ((work[x - 15] & 0xffffffff) >> 3)) + work[x - 16])
#define sharound(a, b, c, d, e, f, g, h, x, K) { t1 = h + (rot(e, 26) ^ rot(e, 21) ^ rot(e, 7)) + (g ^ (e&(f^g))) + K + x; t2 = (rot(a, 30) ^ rot(a, 19) ^ rot(a, 10)) + ((a&b) | (c&(a | b))); d += t1; h = t1 + t2; }

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

void search_nonce(__constant uint* state,
	__constant uint* data,
	ulong startNonce,
	__constant uint* targetHash,
	__global ulong *output,
	__global uint *outputHash)
{
    ulong nonce = startNonce + (0);

    uint work[64];
    uint A, B, C, D, E, F, G, H;
    uint A2, B2, C2, D2, E2, F2, G2, H2;
    uint t1, t2;

    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    F = state[5];
    G = state[6];
    H = state[7];

    work[0] = bytereverse(data[0]);
    work[1] = bytereverse(data[1]);
    work[2] = bytereverse(data[2]);
    work[3] = bytereverse(data[3]);
    work[4] = bytereverse(data[4]);
    work[5] = bytereverse(data[5]);
    work[6] = bytereverse(data[6]);
    work[7] = bytereverse(data[7]);
    work[8] = bytereverse(data[8]);
    work[9] = bytereverse(data[9]);
    work[10] = bytereverse(data[10]);
    work[11] = bytereverse(data[11]);
    work[12] = bytereverse(data[12]);
    work[13] = bytereverse(data[13]);
    work[14] = bytereverse((uint)nonce);
    work[15] = bytereverse((uint)(nonce >> 32));

    sharound(A, B, C, D, E, F, G, H, work[0], 0x428A2F98);
    sharound(H, A, B, C, D, E, F, G, work[1], 0x71374491);
    sharound(G, H, A, B, C, D, E, F, work[2], 0xB5C0FBCF);
    sharound(F, G, H, A, B, C, D, E, work[3], 0xE9B5DBA5);
    sharound(E, F, G, H, A, B, C, D, work[4], 0x3956C25B);
    sharound(D, E, F, G, H, A, B, C, work[5], 0x59F111F1);
    sharound(C, D, E, F, G, H, A, B, work[6], 0x923F82A4);
    sharound(B, C, D, E, F, G, H, A, work[7], 0xAB1C5ED5);
    sharound(A, B, C, D, E, F, G, H, work[8], 0xD807AA98);
    sharound(H, A, B, C, D, E, F, G, work[9], 0x12835B01);
    sharound(G, H, A, B, C, D, E, F, work[10], 0x243185BE);
    sharound(F, G, H, A, B, C, D, E, work[11], 0x550C7DC3);
    sharound(E, F, G, H, A, B, C, D, work[12], 0x72BE5D74);
    sharound(D, E, F, G, H, A, B, C, work[13], 0x80DEB1FE);
    sharound(C, D, E, F, G, H, A, B, work[14], 0x9BDC06A7);
    sharound(B, C, D, E, F, G, H, A, work[15], 0xC19BF174);
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

    A2 = A = A + state[0];
    B2 = B = B + state[1];
    C2 = C = C + state[2];
    D2 = D = D + state[3];
    E2 = E = E + state[4];
    F2 = F = F + state[5];
    G2 = G = G + state[6];
    H2 = H = H + state[7];

    work[0] = 0x80000000;
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
    work[15] = 0x00001000;

    sharound(A, B, C, D, E, F, G, H, work[0], 0x428A2F98);
    sharound(H, A, B, C, D, E, F, G, work[1], 0x71374491);
    sharound(G, H, A, B, C, D, E, F, work[2], 0xB5C0FBCF);
    sharound(F, G, H, A, B, C, D, E, work[3], 0xE9B5DBA5);
    sharound(E, F, G, H, A, B, C, D, work[4], 0x3956C25B);
    sharound(D, E, F, G, H, A, B, C, work[5], 0x59F111F1);
    sharound(C, D, E, F, G, H, A, B, work[6], 0x923F82A4);
    sharound(B, C, D, E, F, G, H, A, work[7], 0xAB1C5ED5);
    sharound(A, B, C, D, E, F, G, H, work[8], 0xD807AA98);
    sharound(H, A, B, C, D, E, F, G, work[9], 0x12835B01);
    sharound(G, H, A, B, C, D, E, F, work[10], 0x243185BE);
    sharound(F, G, H, A, B, C, D, E, work[11], 0x550C7DC3);
    sharound(E, F, G, H, A, B, C, D, work[12], 0x72BE5D74);
    sharound(D, E, F, G, H, A, B, C, work[13], 0x80DEB1FE);
    sharound(C, D, E, F, G, H, A, B, work[14], 0x9BDC06A7);
    sharound(B, C, D, E, F, G, H, A, work[15], 0xC19BF174);
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

    work[0] = A2 + A;
    work[1] = B2 + B;
    work[2] = C2 + C;
    work[3] = D2 + D;
    work[4] = E2 + E;
    work[5] = F2 + F;
    work[6] = G2 + G;
    work[7] = H2 + H;
    work[8] = 0x80000000;
    work[9] = 0;
    work[10] = 0;
    work[11] = 0;
    work[12] = 0;
    work[13] = 0;
    work[14] = 0;
    work[15] = 0x00000100;

    A = 0x6a09e667;
    B = 0xbb67ae85;
    C = 0x3c6ef372;
    D = 0xa54ff53a;
    E = 0x510e527f;
    F = 0x9b05688c;
    G = 0x1f83d9ab;
    H = 0x5be0cd19;

    sharound(A, B, C, D, E, F, G, H, work[0], 0x428A2F98);
    sharound(H, A, B, C, D, E, F, G, work[1], 0x71374491);
    sharound(G, H, A, B, C, D, E, F, work[2], 0xB5C0FBCF);
    sharound(F, G, H, A, B, C, D, E, work[3], 0xE9B5DBA5);
    sharound(E, F, G, H, A, B, C, D, work[4], 0x3956C25B);
    sharound(D, E, F, G, H, A, B, C, work[5], 0x59F111F1);
    sharound(C, D, E, F, G, H, A, B, work[6], 0x923F82A4);
    sharound(B, C, D, E, F, G, H, A, work[7], 0xAB1C5ED5);
    sharound(A, B, C, D, E, F, G, H, work[8], 0xD807AA98);
    sharound(H, A, B, C, D, E, F, G, work[9], 0x12835B01);
    sharound(G, H, A, B, C, D, E, F, work[10], 0x243185BE);
    sharound(F, G, H, A, B, C, D, E, work[11], 0x550C7DC3);
    sharound(E, F, G, H, A, B, C, D, work[12], 0x72BE5D74);
    sharound(D, E, F, G, H, A, B, C, work[13], 0x80DEB1FE);
    sharound(C, D, E, F, G, H, A, B, work[14], 0x9BDC06A7);
    sharound(B, C, D, E, F, G, H, A, work[15], 0xC19BF174);
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
    outputHash[0] = bytereverse(A + 0x6a09e667);
    outputHash[1] = bytereverse(B + 0xbb67ae85);
    outputHash[2] = bytereverse(C + 0x3c6ef372);
    outputHash[3] = bytereverse(D + 0xa54ff53a);
    outputHash[4] = bytereverse(E + 0x510e527f);
    outputHash[5] = bytereverse(F + 0x9b05688c);
    outputHash[6] = bytereverse(G + 0x1f83d9ab);
    outputHash[7] = bytereverse(H + 0x5be0cd19);
}
