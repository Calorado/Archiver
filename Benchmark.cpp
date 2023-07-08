#include <iostream>
#include <chrono>
#include <string>

#include <Windows.h>
#include <Psapi.h>

size_t execute_command(std::string command) {

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char* command_cstring = new char[command.size() + 1];
    memcpy(command_cstring, command.c_str(), command.size());
    command_cstring[command.size()] = 0;

    // Start the child process. 
    CreateProcessA(NULL,   // No module name (use command line)
        command_cstring,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Working directory
        &si,            // Pointer to STARTUPINFO structure
        &pi);           // Pointer to PROCESS_INFORMATION structure

    size_t maxMemory = 0;
    while (true) {
        int waitResult = WaitForSingleObject(pi.hProcess, 2 * 1000);
        if (waitResult != WAIT_TIMEOUT)
            break;
        PROCESS_MEMORY_COUNTERS pmc;
        GetProcessMemoryInfo(pi.hProcess, &pmc, sizeof(pmc));
        maxMemory = max(maxMemory, pmc.PeakWorkingSetSize);
    }

    unsigned long exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return maxMemory;
}

int main(int argc, char* argv[])
{
    std::string command = std::string("\"") + argv[1] + "\"";
    for (int i = 2; i < argc; i++)
        command += std::string(" \"") + argv[i] + "\"";

    auto timeStart = std::chrono::high_resolution_clock::now();
    size_t memory = execute_command(command);
    std::cout << "\n Time: " << (std::chrono::high_resolution_clock::now() - timeStart).count() / 1e9 << "s";
    std::cout << "\n Peak memory: " << memory;
}