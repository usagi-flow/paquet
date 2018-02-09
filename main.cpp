#include <iostream>
#include <chrono>
#include <thread>
#include "supervisor/injector.h"
#include "supervisor/process.h"

using namespace std;

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

	cout << "[parent] PID: " << pid << " (0x" << hex << uppercase << pid << ")" << endl;

	//Process process = Process(".\\child.exe");
	shared_ptr<Process> process = make_shared<Process>(".\\child.exe");
	Injector injector = Injector(process);
	void * pCodeCave;
	DWORD64 rip;
	byte * pRIP = (byte*)&rip;

	process->start(true);
	this_thread::sleep_for(chrono::milliseconds(250));

	injector.performInjections();

	// Test code: create minimal code cave and invoke it before RtlUserThreadStart
	/*rip = process->getMainThreadContext()->Rip;

	byte codeCave[] = {
		// MOV EAX, 00260000 => B8 00 00 26 00 (Endian!)
		0xB8, pRIP[0], pRIP[1], pRIP[2], pRIP[3],

		// JMP EAX => FF E0
		0xFF, 0xE0
	};

	// Allocate memory for the code cave
	pCodeCave = process->allocateMemory(sizeof(codeCave));

	// Write the code cave
	process->writeMemory(codeCave, sizeof(codeCave), pCodeCave);

	// Set the IP to point to the code cave
	process->setRIP(pCodeCave);*/

	cin.get();
	this_thread::sleep_for(chrono::milliseconds(250));

	process->resume();
	this_thread::sleep_for(chrono::milliseconds(250));

	return 0;
}