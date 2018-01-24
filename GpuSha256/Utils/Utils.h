#pragma once
#include <string>

void DumpHex(const unsigned char *byteArray, int lenght, bool oneLine = true);
std::string ToHexString(const unsigned char *byteArray, int length);
unsigned int GetTimeMs();