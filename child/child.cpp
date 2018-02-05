#include <iostream>
#include <fstream>
//#include <cstdio>
#include <windows.h>

using namespace std;

int main(int argcv, char* argv[])
{
	DWORD pid = GetCurrentProcessId();
	char buffer[512];
	ofstream ofile;

	cout << "[child] PID: " << pid << " (0x" << hex << uppercase << pid << ")" << endl;

	//printf("Press enter to continue\n");
	//cin >> buffer;
	//cin.get();

	cout << "[child] Writing to file" << endl;

	cout << "[child] - open()" << endl;
	ofile.open("file.txt");
	cout << "[child] - write()" << endl;
	ofile << "File written by process #" << GetCurrentProcessId() << endl;
	cout << "[child] - close()" << endl;
	ofile.close();

	cout << "[child] Writing process terminated" << endl;

	return 0;
}