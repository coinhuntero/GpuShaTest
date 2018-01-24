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

    static void DoCpuHash_St(uint8_t* state, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_St_Ssl(uint8_t* state, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_Opt(uint8_t* state, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_Opt_Ssl(uint8_t* state, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_Btc(uint8_t* state, uint64_t nonce, uint8_t* hash);
    static void DoCpuHash_Modified(uint8_t* state, uint64_t nonce, uint8_t* hash);
#if ENABLE_GPU
    inline void DoGpuHash(uint8_t* data, uint64_t nonce, uint8_t* hash);
#endif
    static void SimulateGpu(uint8_t* data, uint64_t nonce, uint8_t* hash);
    void CompareHashes(const char* state, uint64_t nonce);
    size_t TestPerformanceCpu_St(size_t count);
    size_t TestPerformanceCpu_St_Ssl(size_t count);
    size_t TestPerformanceCpu_Opt(size_t count);
    size_t TestPerformanceCpu_Opt_Ssl(size_t count);
    size_t TestPerformanceCpu_Btc(size_t count);
    size_t TestPerformanceCpu_Modified(size_t count);
    size_t TestPerformanceCpuBase(size_t count, const char* message, void doCpuHash(uint8_t*, uint64_t, uint8_t*));
public:
    CTestSha256();
    ~CTestSha256();

    bool Init();
    void TestHashing();
    void TestPerformance();

    void TestGPU();
};

