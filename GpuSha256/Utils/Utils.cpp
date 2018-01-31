#include "Utils.h"
#include <memory>
#include <iostream>
#include <string>
#include <cstdio>
#include <sstream>
#include <iomanip>
#if _WIN32
#include <windows.h>
#endif

template<typename ... Args>
std::string string_format(const std::string& format, Args ... args)
{
    size_t size = snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
    std::unique_ptr<char[]> buf(new char[size]);
    snprintf(buf.get(), size, format.c_str(), args ...);
    return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}

void DumpHex(const uint8_t* byteArray, int length, bool oneLine)
{
    int width = 0;
    for (const unsigned char* p = byteArray; length > 0; ++p)
    {
        if (!oneLine && width >= 16)
        {
            putchar('\n');
            width = 0;
        }
        printf("%02x", *p);
		if (!oneLine)
		{
			putchar(' ');
		}
        --length;
        ++width;
    }
    putchar('\n');
}

std::string ToHexString(const unsigned char *byteArray, int length)
{
    std::stringstream ss;
    ss << std::hex;
    for(int i(0); i < length; ++i)
    {
        ss << (int)byteArray[i];
    }
    return ss.str();
}

std::string HashToHexString(const uint64_t* hash)
{
    std::string hex = string_format("%016llx%016llx%016llx%016llx", hash[3], hash[2], hash[1], hash[0]);
    return hex;
}

unsigned int GetTimeMs()
{
#if _WIN32
    return GetTickCount();
#else
    //TODO: adapt for Linux
    struct timeval tv;
    gettimeofday(&tv, 0);
    return unsigned((tv.tv_sec * 1000) + (tv.tv_usec / 1000));
#endif
}

std::vector<uint8_t> HexToBytes(const std::string& hex)
{
    std::vector<uint8_t> bytes;

    for(unsigned int i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}