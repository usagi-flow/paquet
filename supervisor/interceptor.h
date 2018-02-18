#ifndef _INTERCEPTOR_H_
#define _INTERCEPTOR_H_

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
	std::shared_ptr<Injector> injector;
};

#endif