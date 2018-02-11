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
		virtual ~CodeCave() noexcept(false);

		virtual void initialize(size_t size);

		byte& operator[](int i);

		virtual byte * getRawData();

		virtual void * getCaveAddress() const;
		virtual void setCaveAddress(void * address);

		virtual void * getCallAddress() const;
		virtual void setCallAddress(void * address);

		virtual void * getReturnAddress() const;
		virtual void setReturnAddress(void * address);

		virtual size_t getSize() const;

		virtual size_t getSourceBytesToMove() const;
		virtual void setSourceBytesToMove(size_t sourceBytesToMove);
	
	protected:
		void * caveAddress;
		void * callAddress;
		void * returnAddress;
		size_t size;
		size_t sourceBytesToMove;
		std::shared_ptr<std::vector<byte>> data;
};

#endif