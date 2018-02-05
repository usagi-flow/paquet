#ifndef _CODE_CAVE_H_
#define _CODE_CAVE_H_

#include <iostream>
#include <memory>
#include <vector>
#include "typedef.h"

class CodeCave
{
	public:
		CodeCave(size_t size);
		CodeCave(void * address, size_t size);
		virtual ~CodeCave() noexcept(false);

		byte& operator[](int i);

		virtual const byte * getRawData() const;

		virtual void * getAddress() const;
		virtual void setAddress(void * address);

		virtual size_t getSize() const;
	
	protected:
		void * address;
		size_t size;
		std::shared_ptr<std::vector<byte>> data;
};

#endif