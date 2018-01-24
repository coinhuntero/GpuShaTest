#include "Utils.h"
#include <stdio.h>
#include <sstream>
#include <iomanip>
#if _WIN32
#include <windows.h>
#endif

void DumpHex(const unsigned char *byteArray, int length, bool oneLine)
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