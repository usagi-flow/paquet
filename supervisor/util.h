#ifndef _UTIL_H_
#define _UTIL_H_

#include <cstdio>

class Util
{
	public:
		static void printHexDump(const char * description, const void * address, int length);
};

#endif