#include <iostream>
#include <Windows.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <FullDLLPath.dll>" << std::endl;
        return 1;
    }

    // Get the full path to the DLL from the command-line argument
    const char* dllFullPath = argv[1];

    // Load the specified DLL
    HMODULE hDll = LoadLibraryA(dllFullPath);

    if (hDll != NULL) {
        // Get a function pointer
        FARPROC pTestFunc = GetProcAddress(hDll, "test");

        if (pTestFunc != NULL) {
            // Define a function prototype that matches the DLL function
            typedef void (*tTest)();

            // Cast the function pointer to the correct type
            tTest pTest = reinterpret_cast<tTest>(pTestFunc);

            // Call the function
            pTest();

            std::cout << "Function executed successfully" << std::endl;
        }
        else {
            std::cerr << "Failed to get function address." << std::endl;
        }

        // Unload the DLL
        FreeLibrary(hDll);
    }
    else {
        std::cerr << "Failed to load the specified DLL." << std::endl;
    }

    return 0;
}