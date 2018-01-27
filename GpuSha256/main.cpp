#include "TestSha256.h"
#include <conio.h>
#include <iostream>

int main()
{
    printf("Choose mode:\n");
    printf("1 - test different hashes\n");
    printf("2 - test 1M random hashes\n");
    printf("3 - simulate and test gpu hashing\n");
    printf("4 - simulate mining\n\n");

    int mode;
    do
    {
        mode = _getch();
    }
    while(mode < '1' && mode > '4');
    CTestSha256 test;
    switch(mode)
    {
        case '1':
            test.TestHashing();
            test.TestPerformance();
            break;
        case '2':
            test.TestRandomHashing();
            break;
        case '3':
            test.TestGPU();
            break;
        case '4':
            test.TestMining();
            break;
        default:
            break;
    }

    std::cout << "Press any key to exit";
    _getch();
    return 0;
}