#include "library.h"

using namespace std;
using namespace chrono;

HMODULE ownHModule;
MODULEINFO ownModuleInfo;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	//printf("[library] Resuming execution in 2s...\n");
	//this_thread::sleep_for(milliseconds(2000));
	//Sleep(2000);

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		onDLLAttached();
		break;
	case DLL_PROCESS_DETACH:
		printf("[library] DLL_PROCESS_DETACH\n");
		break;
	case DLL_THREAD_ATTACH:
		printf("[library] DLL_THREAD_ATTACH\n");
		break;
	case DLL_THREAD_DETACH:
		printf("[library] DLL_THREAD_DETACH\n");
		break;
	default:
		printf("[library] DllMain invoked, reason unknown\n");
		break;
	}

	/*ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch());
	printf("[library] Time: %d\n", ms);*/

	return true;
}

void onDLLAttached()
{
	bool success;

	printf("[library] DLL_PROCESS_ATTACH\n");

	ownHModule = GetModuleHandle("paquet.dll");

	printf("[library] Module handle:        0x%08x\n", ownHModule);

	success = GetModuleInformation(GetCurrentProcess(), ownHModule, &ownModuleInfo, sizeof(ownModuleInfo));

	if (!success)
	{
		printf("[library] - Failed to retrieve the module info\n");
		return;
	}

	printf("[library] Module base:          0x%08x\n", ownModuleInfo.lpBaseOfDll);
	printf("[library] Module entry point:   0x%08x\n", ownModuleInfo.EntryPoint);
	printf("[library] Module size:          0x%08x\n", ownModuleInfo.SizeOfImage);
}

void onNtCreateFile()
{
	printf("[library] File creation intercepted!\n");
}

void test()
{
	printf("[library] Test succeeded\n");
}

HMODULE dummyResult;

void test2()
{
	char buffer[5];
	buffer[0] = 0xEF;
	buffer[1] = 0xEF;
	buffer[2] = 0xEF;
	buffer[3] = 0xEF;
	buffer[4] = 0xEF;
	printf("[library] Test2 succeeded: %d, %d\n", buffer[0], buffer[4]);
	dummyResult = LoadLibrary("paquet.dll");

	if (!dummyResult)
		dummyResult = GetModuleHandle("paquet.dll");

	HMODULE hModule = 0x0;
	bool success;

	success = GetModuleHandleEx(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)&DllMain, &hModule);
}