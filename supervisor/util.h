#ifndef _UTIL_H_
#define _UTIL_H_

#include <cstdio>

class Util
{
	public:
		static void printHexDump(const char * description, void * address, int length);
};

#endif