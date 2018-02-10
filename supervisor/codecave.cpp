#include "codecave.h"

using namespace std;

CodeCave::CodeCave(size_t size)
{
	this->caveAddress = 0x0;
	this->callAddress = 0x0;
	this->returnAddress = 0x0;
	this->size = size;
	this->sourceBytesToMove = 0x0;
	this->data = make_shared<vector<byte>>(size);

	cout << "[parent] * Initialized CodeCave instance with " << dec << this->data->size() << " elements" << endl;
}

CodeCave::CodeCave(void * address, size_t size)
{
	this->caveAddress = 0x0;
	this->callAddress = 0x0;
	this->returnAddress = 0x0;
	this->size = size;
	this->sourceBytesToMove = 0x0;
	this->data = make_shared<vector<byte>>(size);

	cout << "[parent] * Initialized CodeCave instance with " << dec << this->data->size() << " elements" << endl;
}

CodeCave::~CodeCave() noexcept(false)
{
}

byte& CodeCave::operator[](int i)
{
	return (*this->data)[i];
}

byte * CodeCave::getRawData()
{
	return this->data->data();
}

void * CodeCave::getCaveAddress() const
{
	return this->caveAddress;
}

void CodeCave::setCaveAddress(void * address)
{
	this->caveAddress = address;
}

void * CodeCave::getCallAddress() const
{
	return this->callAddress;
}

void CodeCave::setCallAddress(void * address)
{
	this->callAddress = address;
}

void * CodeCave::getReturnAddress() const
{
	return this->returnAddress;
}

void CodeCave::setReturnAddress(void * address)
{
	this->returnAddress = address;
}

size_t CodeCave::getSize() const
{
	return this->size;
}

size_t CodeCave::getSourceBytesToMove() const
{
	return this->sourceBytesToMove;
}

void CodeCave::setSourceBytesToMove(size_t sourceBytesToMove)
{
	this->sourceBytesToMove = sourceBytesToMove;
}