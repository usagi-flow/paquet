#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <iostream>
#include <iomanip>
#include <memory>
#include <windows.h>
#include <psapi.h>
#include "macros.h"
#include "typedef.h"
#include "runtime-exception.h"
#include "util.h"

class Process
{
	public:
		Process(const char * name);
		virtual ~Process() noexcept(false);

		virtual const char * getName() const;

		virtual void start();
		virtual void start(bool startSuspended);

		virtual void resume();

		virtual void * allocateMemory(size_t size);

		virtual void copyMemory(void * source, void * destination, size_t size);

		virtual void writeMemory(const void * buffer, size_t size, void * destination);

		/**
		 * Retrieves the thread context of the main process thread. Requires the main thread to be suspended.
		 */
		virtual std::shared_ptr<CONTEXT> getMainThreadContext() const;

		/**
		 * Sets the instruction pointer. Requires the main thread to be suspended.
		 */
		virtual void setRIP(void * rip);

	protected:
		const char * name;
		PROCESS_INFORMATION processInfo;
		std::shared_ptr<CONTEXT> threadContext;
		std::shared_ptr<MEMORY_BASIC_INFORMATION> memoryInfo;

		virtual void analyzeMemory();

		virtual void readMainThreadContext();

		virtual void dumpRegisters() const;
		virtual void dumpRegisters(const CONTEXT * threadContext) const;
};

#endif