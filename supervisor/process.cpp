#include "process.h"

#define COUT_HEX hex << uppercase 
#define COUT_HEX_32 hex << setw(8) << setfill('0') << uppercase 

using namespace std;

Process::Process(const char * name)
{
	this->name = name;
	memset(&(this->processInfo), 0, sizeof(this->processInfo));
}

Process::~Process() noexcept(false)
{
	if (this->processInfo.hProcess)
	{
		cout << "[parent] Performing destruction" << endl;
		if (!CloseHandle(this->processInfo.hProcess))
		{
			cerr << "[parent] Destruction failed" << endl;
			throw RuntimeException("Could not close the child process handle");
		}

		cout << "[parent] Destruction succeeded" << endl;

		memset(&(this->processInfo), 0, sizeof(this->processInfo));
		this->threadContext.reset();
	}
}

void Process::start()
{
	this->start(false);
}

void Process::start(bool startSuspended)
{
	bool success;

	bool inheritHandles = false;
	DWORD creationFlags = 0x0;
	char ** environment = 0x0;
	char * currentDirectory = 0x0;
	STARTUPINFO startupInfo;

	memset(&startupInfo, 0, sizeof(startupInfo));

	if (startSuspended)
		creationFlags |= CREATE_SUSPENDED;

	cout << "[parent] Spawning child... (flags: 0x" << COUT_HEX << creationFlags << ")" << endl;

	success = CreateProcess(this->name, 0x0, 0x0, 0x0,
		inheritHandles, creationFlags, environment, currentDirectory,
		&startupInfo, &(this->processInfo));

	if (!success)
		throw RuntimeException("Could not create the child process");

	cout << "[parent] Child spawned" << endl;

	cout << COUT_HEX;
	cout << "[parent] - Process handle: " << this->processInfo.hProcess << endl;
	cout << "[parent] - Process ID:     0x" << this->processInfo.dwProcessId << endl;
	cout << "[parent] - Thread handle:  " << this->processInfo.hThread << endl;
	cout << "[parent] - Thread ID:      0x" << this->processInfo.dwThreadId << endl;
	cout << dec;

	if (startSuspended)
	{
		cout << "[parent] Process started in suspended mode" << endl;
		this->readMainThreadContext();
		this->dumpRegisters();
	}
}

void Process::resume()
{
	cout << "[parent] Resuming child thread" << endl;

	this->threadContext.reset();
	//memset(&(this->threadContext), 0, sizeof(this->threadContext));

	if (ResumeThread(processInfo.hThread) == -1)
		throw RuntimeException("Could not resume the child thread");
}

void * Process::allocateMemory(size_t size)
{
	return VirtualAllocEx(this->processInfo.hProcess, 0x0, size,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

void Process::copyMemory(void * source, void * destination, size_t size)
{
	bool success;
	byte * buffer = new byte[size];

	cout << "Copying " << dec << size << " bytes from " <<
		hex << setw(8) << setfill('0') << uppercase << source;
	cout << " to " << hex << setw(8) << setfill('0') << uppercase << destination << endl;
	
	success = ReadProcessMemory(this->processInfo.hProcess, source, buffer, size, 0x0);

	if (!success)
		throw new RuntimeException("Could not read child memory");

	Util::printHexDump("copyMemory() buffer", buffer, size);

	success = WriteProcessMemory(this->processInfo.hProcess, destination, buffer, size, 0x0);

	if (!success)
		throw new RuntimeException("Could not write child memory");

	delete[] buffer;
}

void Process::writeMemory(void * buffer, size_t size, void * destination)
{
	bool success = WriteProcessMemory(this->processInfo.hProcess, destination, buffer, size, 0x0);

	if (!success)
		throw new RuntimeException("Could not write child memory");

	Util::printHexDump("writeMemory() buffer", buffer, size);
}

void Process::readMainThreadContext()
{
	/*CONTEXT context;

	GetThreadContext(this->processInfo.hThread, &context);
	cout << "[parent] - RIP: 0x" << COUT_HEX_32 << context.Rip << endl;*/

	this->threadContext = make_shared<CONTEXT>();

	if (GetThreadContext(this->processInfo.hThread, this->threadContext.get()))
		cout << "[parent] - Retrieved the child thread context" << endl;
	else
		throw RuntimeException("Could not retrieve the child thread context");
	/*cout << "[parent] - RIP: 0x" << COUT_HEX_32 << this->threadContext.get()->Rip << endl;
	this->threadContext.get()->Rip = 0xABC123;
	(&(*this->threadContext))->Rip = 0xABC124;
	cout << "[parent] - RIP: 0x" << COUT_HEX_32 << this->threadContext.get()->Rip << endl;*/
}

shared_ptr<CONTEXT> Process::getMainThreadContext() const
{
	return this->threadContext;
}

void Process::dumpRegisters() const
{
	this->dumpRegisters(0x0);
}

void Process::dumpRegisters(const CONTEXT * threadContext) const
{
	const CONTEXT * context = threadContext ?
		threadContext : (this->threadContext.use_count() ? this->threadContext.get(): 0x0);

	if (!context)
	{
		cerr << "[parent] No context available. Is the thread suspended?" << endl;
		return;
	}

	cout << "[parent]   - RAX: 0x" << hex << setw(8) << setfill('0') << uppercase << context->Rax << endl;
	cout << "[parent]   - RCX: 0x" << hex << setw(8) << setfill('0') << uppercase << context->Rcx << endl;
	cout << "[parent]   - RDX: 0x" << hex << setw(8) << setfill('0') << uppercase << context->Rdx << endl;
	cout << "[parent]   - RBX: 0x" << hex << setw(8) << setfill('0') << uppercase << context->Rbx << endl;
	cout << "[parent]   - RSP: 0x" << hex << setw(8) << setfill('0') << uppercase << context->Rsp << endl;
	cout << "[parent]   - RBP: 0x" << hex << setw(8) << setfill('0') << uppercase << context->Rbp << endl;
	cout << "[parent]   - RSI: 0x" << hex << setw(8) << setfill('0') << uppercase << context->Rsi << endl;
	cout << "[parent]   - RDI: 0x" << hex << setw(8) << setfill('0') << uppercase << context->Rdi << endl;
	cout << "[parent]   - RIP: 0x" << hex << setw(8) << setfill('0') << uppercase << context->Rip << endl;
}