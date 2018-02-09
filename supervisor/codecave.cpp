#include "codecave.h"

using namespace std;

CodeCave::CodeCave(size_t size)
{
	this->address = 0x0;
	this->size = size;
	this->data = make_shared<vector<byte>>(size);

	cout << "[parent] * Initialized CodeCave instance with " << dec << this->data->size() << " elements" << endl;
}

CodeCave::CodeCave(void * address, size_t size)
{
	this->address = address;
	this->size = size;
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

void * CodeCave::getAddress() const
{
	return this->address;
}

void CodeCave::setAddress(void * address)
{
	this->address = address;
}

size_t CodeCave::getSize() const
{
	return this->size;
}