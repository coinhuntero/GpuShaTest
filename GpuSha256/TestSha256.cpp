#include "TestSha256.h"
#include "OpenCl\clsha256.h"
#include "Cpu\sha256_st.h"
#include "Cpu\sha256_opt.h"
#include "Cpu\sha256_opt_ssl.h"
#include "Cpu\sha256_mod.h"
#include "Cpu\csha256.h"
#include "Utils\Utils.h"
#include <iostream>

CTestSha256::CTestSha256()
{
}

CTestSha256::~CTestSha256()
{
}

bool CTestSha256::Init()
{
    //TODO: get rid of magic number
#if ENABLE_GPU
    if (!ClSha256::ConfigureGPU(
        1,
        1,
        0))
    {
        std::cout << "Failed to initialize GPU SHA256" << std::endl;
        return false;
    }
    ClSha256::SetNumInstances(1);
    if (!_gpuSha.Init())
    {
        std::cout << "Failed to initialize GPU SHA256" << std::endl;
        return false;
    }
    std::cout << std::endl;
    return true;
#else
    return true;
#endif
}

void CTestSha256::TestHashing()
{
    CompareHashes("589015beeefc8b0e438d47640bab2b36", 18446744073709);
    CompareHashes("8ea5573609bb41e6ce35c51405bffa0a", 654697);
}

void CTestSha256::DoCpuHash_St(uint8_t* state, uint64_t nonce, uint8_t* hash)
{
    st::SHA256_CTX ctx;
    st::set_state(&ctx, (uint32_t*)state, 448);
    st::sha256_update(&ctx, (uint8_t*)&nonce, sizeof(uint64_t));
    st::sha256_final(&ctx, (uint8_t*)hash);
    st::sha256_init(&ctx);
    st::sha256_update(&ctx, hash, 32);
    st::sha256_final(&ctx, hash);
}

void CTestSha256::DoCpuHash_St_Ssl(uint8_t* state, uint64_t nonce, uint8_t* hash)
{
    opt_ssl::_SHA256_CTX ctx;
    opt_ssl::set_state(&ctx, (uint32_t*)state, 448);
    opt_ssl::sha256_update(&ctx, (uint8_t*)&nonce, sizeof(uint64_t));
    opt_ssl::sha256_final(&ctx, (uint8_t*)hash);
    opt_ssl::sha256_init(&ctx);
    opt_ssl::sha256_update(&ctx, hash, 32);
    opt_ssl::sha256_final(&ctx, hash);
}

void CTestSha256::DoCpuHash_Opt(uint8_t* state, uint64_t nonce, uint8_t* hash)
{
    opt::shasha((uint32_t*)state, nonce, hash);
}

void CTestSha256::DoCpuHash_Opt_Ssl(uint8_t* state, uint64_t nonce, uint8_t* hash)
{
    opt_ssl::shasha((uint32_t*)state, nonce, hash);
}

void CTestSha256::DoCpuHash_Btc(uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    CSHA256 sha;
    sha.SetState((uint32_t*)data, 448);
    sha.Write((uint8_t*)&nonce, sizeof(uint64_t));
    sha.Finalize(hash);
    sha.Reset();
    sha.Write(hash, 32);
    sha.Finalize(hash);
}

void CTestSha256::DoCpuHash_Modified(uint8_t* state, uint64_t nonce, uint8_t* hash)
{
    mod::shasha((uint32_t*)state, nonce, hash);
}

#if ENABLE_GPU
inline void CTestSha256::DoGpuHash(uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    _gpuSha.CalcHash((uint32_t*)data, nonce, hash);
}
#endif

void CTestSha256::CompareHashes(const char* state, uint64_t nonce)
{
    uint8_t cpuHash[SHA256_SIZE];
    uint8_t cpuHashSsl[SHA256_SIZE];
    uint8_t cpuHashOpt[SHA256_SIZE];
    uint8_t cpuHashOptSsl[SHA256_SIZE];
    uint8_t cpuHashBtc[SHA256_SIZE];
    uint8_t cpuHashModified[SHA256_SIZE];
#if ENABLE_GPU
    uint8_t gpuHash[SHA256_SIZE];
#endif
    DoCpuHash_St((uint8_t*)state, nonce, cpuHash);
    DoCpuHash_St_Ssl((uint8_t*)state, nonce, cpuHashSsl);
    DoCpuHash_Opt((uint8_t*)state, nonce, cpuHashOpt);
    DoCpuHash_Opt_Ssl((uint8_t*)state, nonce, cpuHashOptSsl);
    DoCpuHash_Btc((uint8_t*)state, nonce, cpuHashBtc);
    DoCpuHash_Modified((uint8_t*)state, nonce, cpuHashModified);

#if ENABLE_GPU
    DoGpuHash((uint8_t*)state, nonce, gpuHash);
#endif

    std::cout << "State: " << state << " nonce: " << nonce << std::endl;
    std::cout << "Cpu hash (default):" << std::endl;
    DumpHex(cpuHash, SHA256_SIZE);
    std::cout << "Cpu hash (ssl):" << std::endl;
    DumpHex(cpuHashSsl, SHA256_SIZE);
    std::cout << "Cpu hash (optimized):" << std::endl;
    DumpHex(cpuHashOpt, SHA256_SIZE);
    std::cout << "Cpu hash (optimized+ssl):" << std::endl;
    DumpHex(cpuHashOptSsl, SHA256_SIZE);
    std::cout << "Cpu hash (btc):" << std::endl;
    DumpHex(cpuHashBtc, SHA256_SIZE);
    std::cout << "Cpu hash (modified):" << std::endl;
    DumpHex(cpuHashModified, SHA256_SIZE);

#if ENABLE_GPU
    std::cout << "Gpu hash:" << std::endl;
    DumpHex(gpuHash, SHA256_SIZE);
#endif
    bool equal = memcmp(cpuHash, cpuHashOpt, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu optimized hash are " << (equal ? "equal" : "not equal") << std::endl;
    bool equal5 = memcmp(cpuHash, cpuHashSsl, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu ssl hash are " << (equal5 ? "equal" : "not equal") << std::endl;
    bool equal4 = memcmp(cpuHash, cpuHashOptSsl, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu optimized+ssl hash are " << (equal4 ? "equal" : "not equal") << std::endl;
    bool equal2 = memcmp(cpuHash, cpuHashBtc, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu btc hash are " << (equal2 ? "equal" : "not equal") << std::endl;
    bool equal3 = memcmp(cpuHash, cpuHashModified, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu modified hash are " << (equal3 ? "equal" : "not equal") << std::endl;
#if ENABLE_GPU
    bool equalG = memcmp(cpuHash, gpuHash, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and gpu hashes are " << (equalG ? "equal" : "not equal") << std::endl << std::endl;
#endif    
    std::cout << std::endl;
}

void CTestSha256::TestPerformance()
{
    std::cout << "Testing performance on 5M hashes" << std::endl;
    size_t count = 5000000;

    size_t cpuStTime = TestPerformanceCpu_St(count);
    size_t cpuStSslTime = TestPerformanceCpu_St_Ssl(count);
    size_t cpuOptTime = TestPerformanceCpu_Opt(count);
    size_t cpuOptSslTime = TestPerformanceCpu_Opt_Ssl(count);
    size_t cpBtcTime = TestPerformanceCpu_Modified(count);
}

size_t CTestSha256::TestPerformanceCpu_St(size_t count)
{
    return TestPerformanceCpuBase(count, "Hashing with CPU (one core, default algo)...", DoCpuHash_St);
}

size_t CTestSha256::TestPerformanceCpu_St_Ssl(size_t count)
{
    return TestPerformanceCpuBase(count, "Hashing with CPU (one core, ssl algo)...", DoCpuHash_St_Ssl);
}

size_t CTestSha256::TestPerformanceCpu_Opt(size_t count)
{
    return TestPerformanceCpuBase(count, "Hashing with CPU (one core, optimized algo)...", DoCpuHash_Opt);
}

size_t CTestSha256::TestPerformanceCpu_Opt_Ssl(size_t count)
{
    return TestPerformanceCpuBase(count, "Hashing with CPU (one core, optimized+ssl algo)...", DoCpuHash_Opt_Ssl);
}

size_t CTestSha256::TestPerformanceCpu_Btc(size_t count)
{
    return TestPerformanceCpuBase(count, "Hashing with CPU (one core, btc algo)...", DoCpuHash_Btc);
}

size_t CTestSha256::TestPerformanceCpu_Modified(size_t count)
{
    return TestPerformanceCpuBase(count, "Hashing with CPU (one core, modified algo)...", DoCpuHash_Modified);
}

size_t CTestSha256::TestPerformanceCpuBase(size_t count, const char* message, void doCpuHash(uint8_t*, uint64_t, uint8_t*))
{
    const size_t length = 32;
    uint8_t *data = (uint8_t*)"989005beeefc8b0e438d47640bab6b36";
    uint8_t hash[length];

    std::cout << message << std::endl;
    size_t startTime = GetTimeMs();
    for (size_t i = 0; i < count; ++i)
    {
        doCpuHash(data, i, hash);
    }
    size_t time = GetTimeMs() - startTime;
    double sec = time / 1000.0;
    double rate = count / sec;
    std::cout << std::fixed << "Time: " << sec << " sec, hashrate: " << rate << std::endl;
    return time;
}

void CTestSha256::TestGPU()
{
    const char* state = "589015beeefc8b0e438d47640bab2b36";
    uint64_t nonce = 18446744073709;
    uint8_t cpuHash[SHA256_SIZE];
    uint8_t cpuHashSim[SHA256_SIZE];
    uint8_t gpuHash[SHA256_SIZE];

    DoCpuHash_St((uint8_t*)state, nonce, cpuHash);
    SimulateGpu((uint8_t*)state, nonce, cpuHashSim);
    DoGpuHash((uint8_t*)state, nonce, gpuHash);

    std::cout << "State: " << state << " nonce: " << nonce << std::endl;
    std::cout << "Cpu hash (default):" << std::endl;
    DumpHex(cpuHash, SHA256_SIZE);
    std::cout << "Cpu hash (sim):" << std::endl;
    DumpHex(cpuHashSim, SHA256_SIZE);
    std::cout << "Gpu hash:" << std::endl;
    DumpHex(gpuHash, SHA256_SIZE);

    bool equal = memcmp(cpuHash, cpuHashSim, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu sim hash are " << (equal ? "equal" : "not equal") << std::endl;
    bool equalG = memcmp(cpuHash, gpuHash, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and gpu hash are " << (equalG ? "equal" : "not equal") << std::endl << std::endl;
 
    std::cout << std::endl;
}

void CTestSha256::SimulateGpu(uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    uint8_t minhash[32];
    memset(minhash, 255, 32);
    uint64_t resultNonce;

    mod::search_nonce((uint32_t*)data, nonce, 1, (uint32_t*)minhash, &resultNonce, (uint32_t*)hash);
}