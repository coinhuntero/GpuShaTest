#include "TestSha256.h"
#include "OpenCl\clsha256.h"
#include "Cpu\sha256_st.h"
#include "Cpu\sha256_opt.h"
#include "Cpu\sha256_opt_ssl.h"
#include "Cpu\sha256_mod.h"
#include "Cpu\sha256_gsim.h"
#include "Cpu\csha256.h"
#include "Utils\Utils.h"
#include "Utils\Random.h"
#include <iostream>

inline int cmphash(uint64_t* l, uint64_t* r)
{
    for(int i = 3; i >= 0; --i)
    {
        if(l[i] != r[i])
        {
            return (l[i] < r[i] ? -1 : 1);
        }
    }
    return 0;
}

CTestSha256::CTestSha256()
{
}

CTestSha256::~CTestSha256()
{
}

bool CTestSha256::InitShaTest()
{
#if ENABLE_GPU
    if(!ClSha256::ConfigureGPU(
        1,
        1,
        0))
    {
        std::cout << "Failed to initialize GPU SHA256" << std::endl;
        return false;
    }
    ClSha256::SetNumInstances(1);
    if(!_gpuSha.InitShaTest())
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

bool CTestSha256::InitMiningTest()
{
#if ENABLE_GPU
    if(!ClSha256::ConfigureGPU(
        ClSha256::_defaultLocalWorkSize,
        ClSha256::_defaultGlobalWorkSizeMultiplier,
        0))
    {
        std::cout << "Failed to initialize GPU SHA256" << std::endl;
        return false;
    }
    ClSha256::SetNumInstances(1);
    if(!_gpuSha.InitMiningTest())
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
    if(!InitShaTest())
    {
        return;
    }
    uint8_t data[56];
    uint32_t state[8];
    CRandom::FillRandomArray((uint8_t*)state, 32);
    CRandom::FillRandomArray(data, 56);

    CompareHashes((uint32_t*)"589015beeefc8b0e438d47640bab2b36", (uint8_t*)"3513d023cf424b5647a7b3c772a5d9ce4c8cca09849793def6435d92", 18446744073709);

    CompareHashes(state, data, 654697);

    uint32_t stateConst[8] =
    {
        4153602721,
        2442630072,
        1449523699,
        1580568866,
        3294848380,
        2151274137,
        1804121806,
        1732303255
    };
    CompareHashes(stateConst, data, 0);

    uint32_t troubleState[8] =
    {
        3029001988,
        2650165609,
        575087044,
        2289375106,
        2813839334,
        1503939311,
        904617444,
        836990999
    };

    uint32_t troubleData[16] =
    {
        2846122656,
        197607875,
        1737332664,
        865912873,
        1146081398,
        2026261649,
        2399814311,
        2133142053,
        162445713,
        1842276601,
        2596906013,
        2120657076,
        292756384,
        3873945249,
        3435973836,
        3435973836
    };
    CompareHashes(troubleState, (uint8_t*)troubleData, 9044172378744161281);
}

void CTestSha256::TestRandomHashing()
{
    if(!InitShaTest())
    {
        return;
    }

    uint8_t data[56];
    uint32_t state[8];
    uint64_t nonce;

    uint8_t cpuHash[SHA256_SIZE];
    uint8_t cpuHashOpt[SHA256_SIZE];
    uint8_t cpuHashModified[SHA256_SIZE];
    uint8_t gpuHash[SHA256_SIZE];

    for(int i = 0; i < 10000; i++)
    {
        CRandom::FillRandomArray((uint8_t*)state, 32);
        CRandom::FillRandomArray(data, 56);
        CRandom::FillRandomArray((uint8_t*)&nonce, 8);

        DoCpuHash_St(state, data, nonce, cpuHash);
        DoCpuHash_Opt(state, data, nonce, cpuHashOpt);
        DoCpuHash_Modified(state, data, nonce, cpuHashModified);
        DoGpuHash(state, data, nonce, gpuHash);

        bool equal = memcmp(cpuHash, cpuHashOpt, SHA256_SIZE) == 0;
        equal = memcmp(cpuHash, cpuHashModified, SHA256_SIZE) == 0 && equal;
        equal = memcmp(cpuHash, gpuHash, SHA256_SIZE) == 0 && equal;

        if(!equal)
        {
            std::cout << "Difference was found" << std::endl;
            std::cout << "State: " << std::endl;
            DumpHex((uint8_t*)state, 32);
            std::cout << "Data: " << std::endl;
            DumpHex((uint8_t*)data, 56);
            std::cout << "Nonce: " << nonce << std::endl;

            std::cout << "Cpu hash (default):" << std::endl;
            DumpHex(cpuHash, SHA256_SIZE);
            std::cout << "Cpu hash (optimized):" << std::endl;
            DumpHex(cpuHashOpt, SHA256_SIZE);
            std::cout << "Cpu hash (modified):" << std::endl;
            DumpHex(cpuHashModified, SHA256_SIZE);
            std::cout << "Gpu hash:" << std::endl;
            DumpHex(gpuHash, SHA256_SIZE);
        }
    }
}

void CTestSha256::DoCpuHash_St(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    st::SHA256_CTX ctx;
    st::set_state(&ctx, (WORD*)state, (BYTE*)data);
    st::sha256_update(&ctx, (uint8_t*)&nonce, sizeof(uint64_t));
    st::sha256_final(&ctx, (uint8_t*)hash);
    st::sha256_init(&ctx);
    st::sha256_update(&ctx, hash, 32);
    st::sha256_final(&ctx, hash);
}

void CTestSha256::DoCpuHash_St_Ssl(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    opt_ssl::_SHA256_CTX ctx;
    opt_ssl::set_state(&ctx, state, data);
    opt_ssl::sha256_update(&ctx, (uint8_t*)&nonce, sizeof(uint64_t));
    opt_ssl::sha256_final(&ctx, (uint8_t*)hash);
    opt_ssl::sha256_init(&ctx);
    opt_ssl::sha256_update(&ctx, hash, 32);
    opt_ssl::sha256_final(&ctx, hash);
}

void CTestSha256::DoCpuHash_Opt(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    opt::shasha((uint32_t*)state, data, nonce, hash);
}

void CTestSha256::DoCpuHash_Opt_Ssl(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    opt_ssl::shasha((uint32_t*)state, data, nonce, hash);
}

void CTestSha256::DoCpuHash_Btc(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    CSHA256 sha;
    sha.SetState(state, data, 56);
    sha.Write((uint8_t*)&nonce, sizeof(uint64_t));
    sha.Finalize(hash);
    sha.Reset();
    sha.Write(hash, 32);
    sha.Finalize(hash);
}

void CTestSha256::DoCpuHash_Modified(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    mod::shasha((uint32_t*)state, (uint32_t*)data, nonce, hash);
}

inline void CTestSha256::DoGpuHash(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    _gpuSha.CalcHash((uint32_t*)state, (uint32_t*)data, nonce, hash);
}

void CTestSha256::CompareHashes(const uint32_t* state, const uint8_t* data, uint64_t nonce)
{
    uint8_t cpuHash[SHA256_SIZE];
    uint8_t cpuHashSsl[SHA256_SIZE];
    uint8_t cpuHashOpt[SHA256_SIZE];
    uint8_t cpuHashOptSsl[SHA256_SIZE];
    //uint8_t cpuHashBtc[SHA256_SIZE];
    uint8_t cpuHashModified[SHA256_SIZE];
    uint8_t gpuHash[SHA256_SIZE];
    DoCpuHash_St(state, data, nonce, cpuHash);
    DoCpuHash_St_Ssl(state, data, nonce, cpuHashSsl);
    DoCpuHash_Opt(state, data, nonce, cpuHashOpt);
    DoCpuHash_Opt_Ssl(state, data, nonce, cpuHashOptSsl);
    //DoCpuHash_Btc(state, data, nonce, cpuHashBtc);
    DoCpuHash_Modified(state, data, nonce, cpuHashModified);
    DoGpuHash(state, data, nonce, gpuHash);

    std::cout << "State: " << std::endl;
    DumpHex((uint8_t*)state, 32);
    std::cout << "Nonce: " << nonce << std::endl;
    std::cout << "Cpu hash (default):" << std::endl;
    DumpHex(cpuHash, SHA256_SIZE);
    std::cout << "Cpu hash (ssl):" << std::endl;
    DumpHex(cpuHashSsl, SHA256_SIZE);
    std::cout << "Cpu hash (optimized):" << std::endl;
    DumpHex(cpuHashOpt, SHA256_SIZE);
    std::cout << "Cpu hash (optimized+ssl):" << std::endl;
    DumpHex(cpuHashOptSsl, SHA256_SIZE);
    //std::cout << "Cpu hash (btc):" << std::endl;
    //DumpHex(cpuHashBtc, SHA256_SIZE);
    std::cout << "Cpu hash (modified):" << std::endl;
    DumpHex(cpuHashModified, SHA256_SIZE);
    std::cout << "Gpu hash:" << std::endl;
    DumpHex(gpuHash, SHA256_SIZE);

    bool equal = memcmp(cpuHash, cpuHashOpt, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu optimized hash are " << (equal ? "equal" : "not equal") << std::endl;
    bool equal5 = memcmp(cpuHash, cpuHashSsl, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu ssl hash are " << (equal5 ? "equal" : "not equal") << std::endl;
    bool equal4 = memcmp(cpuHash, cpuHashOptSsl, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu optimized+ssl hash are " << (equal4 ? "equal" : "not equal") << std::endl;
    //bool equal2 = memcmp(cpuHash, cpuHashBtc, SHA256_SIZE) == 0;
    //std::cout << "Cpu default hash and cpu btc hash are " << (equal2 ? "equal" : "not equal") << std::endl;
    bool equal3 = memcmp(cpuHash, cpuHashModified, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and cpu modified hash are " << (equal3 ? "equal" : "not equal") << std::endl;
    bool equalG = memcmp(cpuHash, gpuHash, SHA256_SIZE) == 0;
    std::cout << "Cpu default hash and gpu hashes are " << (equalG ? "equal" : "not equal") << std::endl << std::endl;
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

size_t CTestSha256::TestPerformanceCpuBase(size_t count, const char* message, void doCpuHash(const uint32_t*, const uint8_t*, uint64_t, uint8_t*))
{
    uint32_t *state = (uint32_t*)"989005beeefc8b0e438d47640bab6b36";
    uint8_t data[56];
    uint8_t hash[32];
    CRandom::FillRandomArray(data, 56);

    std::cout << message << std::endl;
    size_t startTime = GetTimeMs();
    for(size_t i = 0; i < count; ++i)
    {
        doCpuHash(state, data, i, hash);
    }
    size_t time = GetTimeMs() - startTime;
    double sec = time / 1000.0;
    double rate = count / sec;
    std::cout << std::fixed << "Time: " << sec << " sec, hashrate: " << rate << std::endl;
    return time;
}

void CTestSha256::TestGPU()
{
    if(!InitShaTest())
    {
        return;
    }

    const uint32_t* state = (uint32_t*)"589015beeefc8b0e438d47640bab2b36";
    const uint8_t* data = (uint8_t*)"072c0bb2366a14e7685314e66ede2d06b30c55d3b6db42681c71b96d";
    uint64_t nonce = 1;
    uint8_t cpuHash[SHA256_SIZE];
    uint8_t cpuHashmod[SHA256_SIZE];
    uint8_t cpuHashSim[SHA256_SIZE];
    uint8_t gpuHash[SHA256_SIZE];
    //CRandom::FillRandomArray(data, 56);

    DoCpuHash_St((uint32_t*)state, data, nonce, cpuHash);
    DoCpuHash_Modified((uint32_t*)state, data, nonce, cpuHashmod);
    SimulateGpuSha((uint32_t*)state, data, nonce, cpuHashSim);
    DoGpuHash((uint32_t*)state, data, nonce, gpuHash);

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

void CTestSha256::SimulateGpuSha(const uint32_t* state, const uint8_t* data, uint64_t nonce, uint8_t* hash)
{
    uint8_t minhash[32];
    memset(minhash, 255, 32);
    uint64_t resultNonce;

    gsim::search_nonce(state, (uint32_t*)data, nonce, 1, (uint32_t*)minhash, &resultNonce, (uint32_t*)hash);
}

void CTestSha256::TestMining()
{
    if(!InitMiningTest())
    {
        return;
    }
    /*uint32_t troubleState[8] =
    {
        3029001988,
        2650165609,
        575087044,
        2289375106,
        2813839334,
        1503939311,
        904617444,
        836990999
    };

    uint32_t troubleData[16] =
    {
        2846122656,
        197607875,
        1737332664,
        865912873,
        1146081398,
        2026261649,
        2399814311,
        2133142053,
        162445713,
        1842276601,
        2596906013,
        2120657076,
        292756384,
        3873945249,
        3435973836,
        3435973836
    };
    uint64_t minHash[8] =
    {
        4607568685566504850,
        11252627461642971786,
        16632664597846690672,
        141415188692984
    };
    uint64_t startNonce = 9044172378744160000;*/

    std::vector<uint8_t> troubleState = HexToBytes("42b2f3e631378405ea10de893c37d0bf5030145c9a66dbc8d96aea4522eb5a8d");
    std::vector<uint8_t> troubleData = HexToBytes("3aec7e3765c57ccd97a1427cc49fe0d700614dff0444ded5dfbc480da81e3840ca77715f510377860754bd68667b0c6bfc4a91967bddd1fd");
    std::vector<uint8_t> minHash = HexToBytes("7033e352282762462fb351f2d4d4814b195e8cc51e343a6c9df48d03ac70e7bb");
    uint64_t startNonce = 2120951095118342000;

    CompareMiningResult((uint32_t*)troubleState.data(), troubleData.data(), (const uint32_t*)minHash.data(), startNonce);
}

void CTestSha256::CompareMiningResult(const uint32_t* state, const uint8_t* data, const uint32_t* minHash, uint64_t nonce)
{
    uint32_t cpuHash[8];
    uint32_t cpuHashMod[8];
    uint32_t gpuHash[8];

    uint64_t nonceSt = DoMiningSt(state, data, minHash, nonce, cpuHash);
    uint64_t nonceMod = DoMiningMod(state, data, minHash, nonce, cpuHashMod);
    uint64_t nonceGpu = DoMiningGpu(state, data, minHash, nonce, gpuHash);

    if(nonceSt == nonceMod && nonceSt == nonceGpu)
    {
        std::cout << "Nonces are the same" << std::endl;
    }
    else
    {
        std::cout << "Nonces are different" << std::endl;
        std::cout << "Cpu nonce: " << nonceSt << std::endl;
        std::cout << "Cpu hash (default):" << std::endl;
        std::cout << HashToHexString((uint64_t*)cpuHash) << std::endl;

        std::cout << "Cpu nonce mod: " << nonceMod << std::endl;
        std::cout << "Cpu hash mod:" << std::endl;
        std::cout << HashToHexString((uint64_t*)cpuHashMod) << std::endl;

        std::cout << "Gpu nonce: " << nonceGpu << std::endl;
        std::cout << "Gpu hash:" << std::endl;
        std::cout << HashToHexString((uint64_t*)gpuHash) << std::endl;
    }
}

uint64_t CTestSha256::DoMiningSt(const uint32_t* state, const uint8_t* data, const uint32_t* minHash, uint64_t nonce, uint32_t* hash)
{
    st::SHA256_CTX ctx;

    uint32_t currentHash[8];
    memcpy(hash, minHash, 32);

    uint64_t min_nonce = 0;
    for(int i = 0; i < 1048576; ++i)
    {
        st::set_state(&ctx, (WORD*)state, (BYTE*)data);
        st::sha256_update(&ctx, (uint8_t*)&nonce, sizeof(uint64_t));
        st::sha256_final(&ctx, (uint8_t*)currentHash);
        st::sha256_init(&ctx);
        st::sha256_update(&ctx, (uint8_t*)currentHash, 32);
        st::sha256_final(&ctx, (uint8_t*)currentHash);
        if(cmphash((uint64_t*)currentHash, (uint64_t*)hash) < 0)
        {
            memcpy(hash, currentHash, 32);
            min_nonce = nonce;
        }
        ++nonce;
    }
    return min_nonce;
}

uint64_t CTestSha256::DoMiningMod(const uint32_t* state, const uint8_t* data, const uint32_t* minHash, uint64_t startNonce, uint32_t* outputMinHash)
{
    uint64_t results[257];
    uint64_t minNonce = 0;
    memcpy(outputMinHash, minHash, 32);

    for(int i = 0; i < 1048576; ++i)
    {
        gsim::search_nonce2(state, (const uint32_t*)data, startNonce, 1, minHash, results, i);
    }

    if(results[256] > 0)
    {
        uint32_t currentHash[8];
        for(int i = 0; i <= 256; i++)
        {
            uint64_t nonce = results[i];
            if(nonce == 0)
            {
                continue;
            }
            mod::shasha((uint32_t*)state, (uint32_t*)data, nonce, (uint8_t*)currentHash);
            if(cmphash((uint64_t*)currentHash, (uint64_t*)outputMinHash) < 0)
            {
                memcpy(outputMinHash, currentHash, 32);
                minNonce = nonce;
            }
        }
    }
    return minNonce;
}

uint64_t CTestSha256::DoMiningGpu(const uint32_t* state, const uint8_t* data, const uint32_t* minHash, uint64_t nonce, uint32_t* hash)
{
    return _gpuSha.DoMining(state, (const uint32_t*)data, minHash, nonce, hash);
}