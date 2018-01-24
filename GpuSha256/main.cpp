#include "TestSha256.h"
#include <conio.h>


int main()
{
    printf("Choose mode:\n");
    printf("1 - test different hashes\n");
    printf("2 - simulate and test gpu hashing\n\n");

    int mode;
    do
    {
        mode = _getch();
    }
    while(mode != '1' && mode != '2');
    CTestSha256 test;
    if(test.Init())
    {
        if(mode == '1')
        {
            test.TestHashing();
            test.TestPerformance();
        }
        else
        {
            test.TestGPU();
        }
    }

    _getch();
    return 0;
}