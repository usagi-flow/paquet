#include <iostream>
#include "supervisor/process.h"

using namespace std;

typedef unsigned char byte;

int run(int argc, char* argv[]);
bool spawnProcess(const char * name, PROCESS_INFORMATION * processInfo);
bool analyzeChild(const PROCESS_INFORMATION * processInfo);
void dumpRegisters(const CONTEXT * threadContext);
void * allocateMemory(const PROCESS_INFORMATION * processInfo, size_t size);
bool copyMemory(const PROCESS_INFORMATION * processInfo,
	void * source, void * destination, size_t size);
bool writeMemory(const PROCESS_INFORMATION * processInfo,
	void * buffer, size_t size, void * destination);

void dummyFunction()
{
	unsigned int a = 0x12345678;
	unsigned int b = 0x12345678;
	unsigned int c = 0x12345678;
	/*asm volatile(".intel_syntax noprefix;"
		"push rax;"
		"mov rax, 12345678;"
		"mov rax, 12345678;"
		"mov rax, 12345678;"
		"mov rax, 12345678;"
		"pop rax;");*/
}

int main(int argc, char* argv[])
{
	DWORD errorCode;

	try
	{
		return run(argc, argv);
	}
	catch (std::exception &e)
	{
		cerr << "[parent] An unhandled exception occurred: " << e.what() << endl;
		if (errorCode = GetLastError())
			cerr << "[parent] Win32 error code: " << errorCode << endl;
		return 1;
	}
}

int run(int argc, char* argv[])
{
	DWORD pid = GetCurrentProcessId();
	Process process = Process(".\\child.exe");

	cout << "[parent] PID: " << pid << " (0x" << hex << uppercase << pid << ")" << endl;

	process.start(true);
	Sleep(500);
	process.resume();
	Sleep(500);

	return 0;
}

int run0(int argc, char* argv[])
{
	DWORD pid = GetCurrentProcessId();
	PROCESS_INFORMATION processInfo;

	cout << "[parent] PID: " << pid << "(0x" << hex << uppercase << pid << ")" << endl;

	dummyFunction();

	if (!spawnProcess(".\\child.exe", &processInfo))
		return 1;

	Sleep(500);

	if (!analyzeChild(&processInfo))
	{
		/*cout << "[parent] Resuming child thread" << endl;

		if (ResumeThread(processInfo.hThread) == -1)
		{
			cerr << "[parent] Could not resume the child thread" << endl;
			cerr << "[parent] Error: " << GetLastError() << endl;
			return 1;
		}

		Sleep(1000);
		return 1;*/
	}

	cout << "[parent] About to resume child thread... Press Enter to continue." << endl;
	cin.get();

	cout << "[parent] Resuming child thread" << endl;

	if (ResumeThread(processInfo.hThread) == -1)
	{
		cerr << "[parent] Could not resume the child thread" << endl;
		cerr << "[parent] Error: " << GetLastError() << endl;
		return 1;
	}

	Sleep(500);
	return 0;
}

bool spawnProcess(const char * name, PROCESS_INFORMATION * processInfo)
{
	bool createProcResult;

	bool inheritHandles = false;
	WORD creationFlags = 0x0 | CREATE_SUSPENDED;
	char ** environment = 0x0;
	char * currentDirectory = 0x0;
	STARTUPINFO startupInfo;
	HANDLE openProcessHandle;

	cout << "[parent] Spawning child..." << endl;
	//MessageBox(0x0, "Message", "Title", MB_OK);

	createProcResult = CreateProcess(".\\child.exe", 0x0, 0x0, 0x0,
		inheritHandles, creationFlags, environment, currentDirectory,
		&startupInfo, processInfo);

	if (!createProcResult)
	{
		cerr << "[parent] Could not create the child process" << endl;
		cerr << "[parent] Error: " << GetLastError() << endl;
		return false;
	}

	cout << "[parent] Child spawned" << endl;

	return true;
}

bool analyzeChild(const PROCESS_INFORMATION * processInfo)
{
	const size_t codeCaveSize = 512;
	const size_t functionSize = 48;
	bool success;
	CONTEXT threadContext;
	void * pCodeCave;

	cout << "[parent] - Analyzing child (#" << processInfo->dwProcessId << " / 0x" <<
		hex << uppercase << processInfo->dwProcessId << ")" << endl;

	memset(&threadContext, 0, sizeof(threadContext));
	threadContext.ContextFlags = CONTEXT_ALL;
	//Util::printHexDump("threadcontext.ContextFlags", &threadContext.ContextFlags, sizeof(threadContext.ContextFlags));
	success = GetThreadContext(processInfo->hThread, &threadContext);

	if (success)
	{
		cout << "[parent] - Retrieved the child thread context" << endl;
		//Util::printHexDump("threadcontext", &threadContext, sizeof(threadContext));
		dumpRegisters(&threadContext);
	}
	else
	{
		cerr << "[parent] - Could not retrieve the child thread context" << endl;
		cerr << "[parent] - Error: " << GetLastError() << endl;
		return false;
	}

	cout << "[parent] - Allocating " << dec << codeCaveSize << " bytes" << endl;
 
	pCodeCave = allocateMemory(processInfo, codeCaveSize);

	if (pCodeCave)
	{
		cout << "[parent] - Successfully prepared code cave at " <<
			hex << setw(8) << setfill('0') << uppercase << pCodeCave << endl;
	}
	else
	{
		cerr << "[parent] - Could not prepare the code cave" << endl;
		cerr << "[parent] - Error: " << GetLastError() << endl;
		return false;
	}

	// Expectation: threadContext.Rip == 0x774DC520 (ntdll.RtlUserThreadStart)
	/*success = copyMemory(processInfo, (void*)threadContext.Rip,
		(void*)((size_t)pCodeCave + codeCaveSize / 2), functionSize);

	if (success)
	{
		cout << "[parent] - Function copied to code cave :)" << endl;
	}
	else
	{
		cerr << "[parent] - Could not copy the function to the code cave" << endl;
		cerr << "[parent] - Error: " << GetLastError() << endl;
		return false;
	}*/

	//byte buffer[] = {0x90, 0xC3};
	// RIP 774DC520
	/*byte * RIP = (byte*)(&threadContext.Rip);
	Util::printHexDump("RIP", RIP, 4);
	byte buffer[] = {
		//MOV EAX, {pCodeCave}
		0xB8, RIP[0], RIP[1], RIP[2], RIP[3],
		// JMP EAX
		0xFF, 0xE0};*/
	byte buffer[] = {
		// JMP 774DC520
		0xE9, 0x1B, 0xC5, 0x27, 0x77};
	success = writeMemory(processInfo, buffer, sizeof(buffer), pCodeCave);

	/*byte buffer[] = {0xE9, 0xDB, 0x3A, 0xD8, 0x88, 0x90, 0x90};
	success = writeMemory(processInfo, buffer, sizeof(buffer), (void*)threadContext.Rip);*/

	//threadContext.Rip = 0x7733A4AB; // ExitProcess()
	//threadContext.Rip = 0x7733A977; // RtlZeroMemory()
	threadContext.Rip = (DWORD64)pCodeCave;

	/*success = SetThreadContext(processInfo->hThread, &threadContext);

	if (success)
	{
		cout << "[parent] - Child thread context set" << endl;
	}
	else
	{
		cerr << "[parent] - Could not set the child thread context" << endl;
		cerr << "[parent] - Error: " << GetLastError() << endl;
		return false;
	}*/

	cout << "[parent] - Child analyzed" << endl;

	return true;
}

void dumpRegisters(const CONTEXT * threadContext)
{
	cout << "[parent]   - RAX: 0x" << hex << setw(8) << setfill('0') << uppercase << threadContext->Rax << endl;
	cout << "[parent]   - RCX: 0x" << hex << setw(8) << setfill('0') << uppercase << threadContext->Rcx << endl;
	cout << "[parent]   - RDX: 0x" << hex << setw(8) << setfill('0') << uppercase << threadContext->Rdx << endl;
	cout << "[parent]   - RBX: 0x" << hex << setw(8) << setfill('0') << uppercase << threadContext->Rbx << endl;
	cout << "[parent]   - RSP: 0x" << hex << setw(8) << setfill('0') << uppercase << threadContext->Rsp << endl;
	cout << "[parent]   - RBP: 0x" << hex << setw(8) << setfill('0') << uppercase << threadContext->Rbp << endl;
	cout << "[parent]   - RSI: 0x" << hex << setw(8) << setfill('0') << uppercase << threadContext->Rsi << endl;
	cout << "[parent]   - RDI: 0x" << hex << setw(8) << setfill('0') << uppercase << threadContext->Rdi << endl;
	cout << "[parent]   - RIP: 0x" << hex << setw(8) << setfill('0') << uppercase << threadContext->Rip << endl;
}

void * allocateMemory(const PROCESS_INFORMATION * processInfo, size_t size)
{
	return VirtualAllocEx(processInfo->hProcess, 0x0, size,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

bool copyMemory(const PROCESS_INFORMATION * processInfo,
	void * source, void * destination, size_t size)
{
	bool success;
	byte * buffer = new byte[size];

	cout << "Copying " << dec << size << " bytes from " <<
		hex << setw(8) << setfill('0') << uppercase << source;
	cout << " to " << hex << setw(8) << setfill('0') << uppercase << destination << endl;
	
	success = ReadProcessMemory(processInfo->hProcess, source, buffer, size, 0x0);

	if (success)
		Util::printHexDump("copyMemory() buffer", buffer, size);

	if (success)
		//success = writeMemory(processInfo, buffer, size, destination);
		success = WriteProcessMemory(processInfo->hProcess, destination, buffer, size, 0x0);

	delete[] buffer;

	return success;
}

bool writeMemory(const PROCESS_INFORMATION * processInfo,
	void * buffer, size_t size, void * destination)
{
	bool success = WriteProcessMemory(processInfo->hProcess, destination, buffer, size, 0x0);

	if (success)
		Util::printHexDump("writeMemory() buffer", buffer, size);

	return success;
}

bool analyzeChild0(const PROCESS_INFORMATION * processInfo)
{
	bool enumResult;
	HMODULE modules[256];
	unsigned int moduleByteCount;

	cout << "[parent] Analyzing child (#" << processInfo->dwProcessId << ")" << endl;

	enumResult = EnumProcessModules(processInfo->hProcess, modules, sizeof(modules), &moduleByteCount);

	cout << "[parent] Size of HMODULE: " << sizeof(HMODULE) << endl;
	cout << "[parent] moduleByteCount: " << moduleByteCount << endl;

	if (!enumResult)
	{
		cerr << "[parent] Could not enumerate the child process modules" << endl;
		cerr << "[parent] Error: " << GetLastError() << endl;
		return false;
	}

	return true;
}