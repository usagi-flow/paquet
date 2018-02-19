#include <iostream>
#include <chrono>
#include <thread>
#include "supervisor/interceptor.h"
#include "supervisor/process.h"

using namespace std;

int run(int argc, char* argv[]);

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
	catch (exception &e)
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

	shared_ptr<Process> process = make_shared<Process>(".\\child.exe");
	Interceptor interceptor = Interceptor(process);

	process->start(true);
	//this_thread::sleep_for(chrono::milliseconds(250));

	interceptor.run();

	//this_thread::sleep_for(chrono::milliseconds(250));

	process->resume();
	this_thread::sleep_for(chrono::milliseconds(250));

	return 0;
}