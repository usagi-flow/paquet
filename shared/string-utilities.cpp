#include "string-utilities.h"

using namespace std;

StringUtilities::~StringUtilities()
{
}

StringUtilities::StringUtilities()
{
}

bool StringUtilities::startsWith(const string & value, const string & prefix)
{
	return value.size() >= prefix.size() &&
		value.compare(0, prefix.size(), prefix) == 0;
}

bool StringUtilities::endsWith(const string & value, const string & suffix)
{
	return value.size() >= suffix.size() &&
		value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool StringUtilities::startsWith(const std::wstring & value, const std::wstring & prefix)
{
	return value.size() >= prefix.size() &&
		value.compare(0, prefix.size(), prefix) == 0;
}

bool StringUtilities::endsWith(const std::wstring & value, const std::wstring & suffix)
{
	return value.size() >= suffix.size() &&
		value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

shared_ptr<wstring> StringUtilities::toWString(const string & source)
{
	shared_ptr<wstring> result = make_shared<wstring>(source.size(), L' ');
	result->resize(mbstowcs(&(*result)[0], source.c_str(), source.size()));
	return result;
}

void StringUtilities::toWCString(const char * source, wchar_t * destination, size_t stringLength)
{
	mbstowcs(destination, source, stringLength + 1);
}