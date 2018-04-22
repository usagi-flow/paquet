#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <windows.h>

using namespace std;

int main(int argcv, char* argv[])
{
	DWORD pid = GetCurrentProcessId();
	char buffer[512];
	ofstream ofile;

	cout << "[child] PID: " << pid << " (0x" << hex << uppercase << pid << ")" << endl;

	/*cout << "[child] Resuming execution in 3s..." << endl;
	this_thread::sleep_for(chrono::milliseconds(1000));
	cout << "[child] Resuming execution in 2s..." << endl;
	this_thread::sleep_for(chrono::milliseconds(1000));
	cout << "[child] Resuming execution in 1s..." << endl;
	this_thread::sleep_for(chrono::milliseconds(1000));*/

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