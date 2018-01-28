#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <iostream>
#include <iomanip>
#include <windows.h>
#include <psapi.h>
#include "runtime-exception.h"
#include "util.h"

class Process
{
	public:
		Process(const char * name);
		virtual ~Process();

		virtual void start();
		virtual void start(bool startSuspended);

		virtual void resume();

		void * allocateMemory(size_t size);

		void copyMemory(void * source, void * destination, size_t size);

		void writeMemory(void * buffer, size_t size, void * destination);

		CONTEXT GetMainThreadContext();

	protected:
		const char * name;
		PROCESS_INFORMATION processInfo;

		void dumpRegisters(const CONTEXT * threadContext);
};

#endif