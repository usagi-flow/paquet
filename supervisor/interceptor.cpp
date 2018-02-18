#include "interceptor.h"

using namespace std;

Interceptor::Interceptor(std::shared_ptr<Process> process)
{
	injector = make_shared<Injector>(process);
}

Interceptor::~Interceptor() noexcept(false)
{
}

void Interceptor::run()
{
	shared_ptr<DLL> dll;

	this->injector->prepare();
	dll = this->injector->injectDLL("paquet.dll");

	cout << "[parent] paquet.dll injected at base address 0x" <<
		COUT_HEX_32 << dll->getBaseAddress() << endl;

	cout << "[parent] Function address: 0x" <<
		this->injector->getRemoteFunctionAddress(dll, "onNtCreateFile") << endl;
}