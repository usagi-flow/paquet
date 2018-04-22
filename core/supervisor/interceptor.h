#ifndef _INTERCEPTOR_H_
#define _INTERCEPTOR_H_

#include <iostream>
#include <string>
#include <memory>
#include "process.h"
#include "injector.h"

class Interceptor
{
public:
	Interceptor(std::shared_ptr<Process> process);
	virtual ~Interceptor() noexcept(false);

	virtual void run();

protected:
	std::shared_ptr<Process> process;
	std::shared_ptr<Injector> injector;
	std::shared_ptr<DLL> dll_ntdll;
	std::shared_ptr<DLL> dll_kernel32;
	std::shared_ptr<DLL> dll_paquet;

	virtual void interceptSyscall(const std::string & syscallName, const std::string & callbackName);
};

#endif