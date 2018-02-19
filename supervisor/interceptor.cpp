#include "interceptor.h"

using namespace std;

Interceptor::Interceptor(shared_ptr<Process> process)
{
	this->process = process;
	this->injector = make_shared<Injector>(process);
}

Interceptor::~Interceptor() noexcept(false)
{
}

void Interceptor::run()
{
	this->injector->prepare();

	this->dll_ntdll = this->injector->getRemoteDLL("ntdll.dll");
	this->dll_kernel32 = this->injector->getRemoteDLL("kernel32.dll");
	this->dll_paquet = this->injector->injectDLL("paquet.dll");

	cout << "[parent] ntdll.dll present at base address:    0x" <<
		this->dll_ntdll->getBaseAddress() << endl;
	cout << "[parent] kernel32.dll present at base address: 0x" <<
		this->dll_kernel32->getBaseAddress() << endl;
	cout << "[parent] paquet.dll injected at base address:  0x" <<
		COUT_HEX_32 << this->dll_paquet->getBaseAddress() << endl;

	/*cout << "[parent] Function address: 0x" <<
		this->injector->getRemoteFunctionAddress(dll, "onNtCreateFile") << endl;*/
	cout << "[parent] Function address: 0x" <<
		this->injector->getRemoteFunctionAddress(this->dll_paquet, "onNtWriteFile") << endl;

	this->interceptSyscall("NtCreateFile", "onNtCreateFile");
	this->interceptSyscall("NtWriteFile", "onNtWriteFile");
	this->interceptSyscall("NtClose", "onNtClose");
}

void Interceptor::interceptSyscall(const string & syscallName, const string & callbackName)
{
	// Default ntdll.dll syscall function layout (16 bytes):
	// 4C 8B D1			- mov r10, rcx
	// B8 xx000000		- mov eax, 000000xx		- Syscall number
	// 0F05				- syscall
	// C3				- ret
	// 0F1F 44 00 00	- nop[rax + rax + 00]


	const size_t caveSize = 64;
	const size_t sourceBytes = 16;
	void * syscallAddress = this->injector->getRemoteFunctionAddress(this->dll_ntdll, syscallName);
	void * callbackAddress = this->injector->getRemoteFunctionAddress(this->dll_paquet, callbackName);

	shared_ptr<CodeCave> cave = this->injector->createCodeCave(syscallAddress, caveSize, sourceBytes);
	size_t i = 0;

	byte subRSP30[] = { 0x48, 0x83, 0xEC, 0x30 };
	byte addRSP30[] = { 0x48, 0x83, 0xC4, 0x30 };

	i += Assembler::writePush(cave->getRawData(), i, Assembler::RAX);
	cave->getRawData()[i++] = subRSP30[0];
	cave->getRawData()[i++] = subRSP30[1];
	cave->getRawData()[i++] = subRSP30[2];
	cave->getRawData()[i++] = subRSP30[3];
	i += Assembler::writeMovReg(cave->getRawData(), i, Assembler::RAX, (size_t)callbackAddress);
	i += Assembler::writeCallReg(cave->getRawData(), i, Assembler::RAX);
	cave->getRawData()[i++] = addRSP30[0];
	cave->getRawData()[i++] = addRSP30[1];
	cave->getRawData()[i++] = addRSP30[2];
	cave->getRawData()[i++] = addRSP30[3];
	i += Assembler::writePop(cave->getRawData(), i, Assembler::RAX);

	// TODO: unstable call near implementation
	//Assembler::writeCallNear(cave->getRawData(), 0x0, cave->getCaveAddress(), callbackAddress);

	this->injector->injectCodeCave(cave);

	//cout << "[parent] Code cave address: 0x" << COUT_HEX_32 << cave->getCaveAddress() << endl;
	cout << "[parent] Installed interception for \"" << syscallName <<
		"\", redirecting to \"" << callbackName << "\"" << endl;

	//cin.get();
}