#pragma once


#define CL_USE_DEPRECATED_OPENCL_1_2_APIS true
#define CL_HPP_ENABLE_EXCEPTIONS true
#define CL_HPP_CL_1_2_DEFAULT_BUILD true
#define CL_HPP_TARGET_OPENCL_VERSION 120
#define CL_HPP_MINIMUM_OPENCL_VERSION 120

#include "CL/cl2.hpp"

// macOS OpenCL fix:
#ifndef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
#define CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV       0x4000
#endif

#ifndef CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV
#define CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV       0x4001
#endif

#define OPENCL_PLATFORM_UNKNOWN 0
#define OPENCL_PLATFORM_NVIDIA  1
#define OPENCL_PLATFORM_AMD     2
#define OPENCL_PLATFORM_CLOVER  3

class ClSha256
{
public:
    /* -- default values -- */
    /// Default value of the local work size. Also known as workgroup size.
    static const unsigned _defaultLocalWorkSize = 128;
    /// Default value of the global work size as a multiplier of the local work size
    //static const unsigned _defaultGlobalWorkSizeMultiplier = 8192;
    //TODO: 
    static const unsigned _defaultGlobalWorkSizeMultiplier = 1024;

    ClSha256();
    virtual ~ClSha256();

    static unsigned Instances() { return _numInstances > 0 ? _numInstances : 1; }
    static unsigned GetNumDevices();
    static void ListDevices();
    static bool ConfigureGPU(
        unsigned _localWorkSize,
        unsigned _globalWorkSizeMultiplier,
        unsigned _platformId
    );
    bool Init();
    uint64_t CalcHash(uint32_t *state, uint64_t nonce, uint8_t* hash);

    static void SetNumInstances(unsigned _instances) { _numInstances = std::min<unsigned>(_instances, GetNumDevices()); }
    static void SetDevices(unsigned * _devices, unsigned _selectedDeviceCount)
    {
        for(unsigned i = 0; i < _selectedDeviceCount; i++)
        {
            _devices[i] = _devices[i];
        }
    }
protected:

private:
    bool LoadKernel();

    cl::Context _context;
    cl::CommandQueue _queue;
    cl::Kernel _searchKernel;
    cl::Buffer _stateBuffer;
    cl::Buffer _minHashBuffer;
    cl::Buffer _searchBuffer;
    cl::Buffer _outputHashBuffer;
    unsigned _globalWorkSize = 0;
    unsigned _workgroupSize = 0;
    std::string _kernelCode;

    static unsigned _platformId;
    static unsigned _numInstances;
    static std::string _clKernelName;
    static int _devices[16];

    /// The local work size for the search
    static unsigned _sWorkgroupSize;
    /// The initial global work size for the searches
    static unsigned _sInitialGlobalWorkSize;
};
