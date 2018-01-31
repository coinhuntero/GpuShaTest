#pragma once
#include <stdint.h>
#include "OpenCL\ClSha256.h"

#define SHA256_SIZE 32

class CTestSha256
{
private:
#if ENABLE_GPU
    ClSha256 _gpuSha;
#endif

    static void DoCpuHash_St(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_St_Ssl(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_Opt(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_Opt_Ssl(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_Btc(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_Modified(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash);
    inline void DoGpuHash(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash);
    static void SimulateGpuSha(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash);

    void CompareHashes(const uint32_t* state, const uint8_t* data, uint64_t nonce);
    size_t TestPerformanceCpu_St(size_t count);
    size_t TestPerformanceCpu_St_Ssl(size_t count);
    size_t TestPerformanceCpu_Opt(size_t count);
    size_t TestPerformanceCpu_Opt_Ssl(size_t count);
    size_t TestPerformanceCpu_Btc(size_t count);
    size_t TestPerformanceCpu_Modified(size_t count);
    size_t TestPerformanceCpuBase(size_t count, const char* message, void doCpuHash(const uint32_t*, const uint8_t*, uint64_t, uint8_t*));

    void CompareMiningResult(const uint32_t* state, const uint8_t* data, const uint32_t* minHash, uint64_t nonce);
    uint64_t DoMiningSt(const uint32_t* state, const uint8_t* data, const uint32_t* minHash, uint64_t nonce, uint32_t* hash);
    uint64_t DoMiningMod(const uint32_t* state, const uint8_t* data, const uint32_t* minHash, uint64_t nonce, uint32_t* hash);
    uint64_t DoMiningGpu(const uint32_t* state, const uint8_t* data, const uint32_t* minHash, uint64_t nonce, uint32_t* hash);
public:
    CTestSha256();
    ~CTestSha256();

    bool InitShaTest();
    bool InitMiningTest();

    void TestHashing();
    void TestPerformance();
    void TestRandomHashing();
    void TestGPU();
    void TestMining();
};

