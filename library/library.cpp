#include "library.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	printf("[library] DLL initialized :)\n");
}

void test()
{
	printf("[library] Test succeeded!\n");
}

void test2()
{
	char buffer[5];
	buffer[0] = 0xEF;
	buffer[1] = 0xEF;
	buffer[2] = 0xEF;
	buffer[3] = 0xEF;
	buffer[4] = 0xEF;
	printf("[library] Test2 succeeded: %d, %d!\n", buffer[0], buffer[4]);
}