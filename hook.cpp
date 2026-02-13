#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <fstream>
#include <ctime>
#include <MinHook.h>

void LogToFile(const char* message) {
    std::ofstream logFile("hook_log.txt", std::ios::app);
    if (logFile.is_open()) {
        time_t now = time(0);
        char timestamp[26];
        ctime_s(timestamp, sizeof(timestamp), &now);
        timestamp[24] = '\0';

        logFile << "[" << timestamp << "] " << message << std::endl;
        logFile.close();
    }
}

typedef HANDLE(WINAPI* CreateFileAFunc_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileAFunc_t pOriginalCreateFileA = nullptr;

typedef HANDLE(WINAPI* CreateFileWFunc_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileWFunc_t pOriginalCreateFileW = nullptr;

typedef BOOL(WINAPI* ReadFileFunc_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
ReadFileFunc_t pOriginalReadFile = nullptr;

typedef BOOL(WINAPI* CloseHandleFunc_t)(HANDLE);
CloseHandleFunc_t pOriginalCloseHandle = nullptr;

typedef DWORD(WINAPI* GetFileSizeFunc_t)(HANDLE, LPDWORD);
GetFileSizeFunc_t pOriginalGetFileSize = nullptr;

#include <set>
#include <map>
#include <vector>
#include <sstream>
std::set<HANDLE> catnameFileHandles;
std::map<HANDLE, std::string> catnameDataCache;
std::map<HANDLE, size_t> catnameReadOffset;

std::string g_sharedCatnameList;
bool g_catnameListGenerated = false;

#define SHARED_MEM_NAME "MewgenicsTwitchNames"
#define MAX_NAMES 1000
#define MAX_NAME_LENGTH 50
#define RECENT_BUFFER_SIZE 20
#define RECENCY_PENALTY 10  // Divide score by this if recently used

struct NameEntry {
    char name[MAX_NAME_LENGTH];
    int score;
};

struct SharedTwitchData {
    int nameCount;
    NameEntry names[MAX_NAMES];
    int recentIndex;
    char recentNames[RECENT_BUFFER_SIZE][MAX_NAME_LENGTH];
};

HANDLE hSharedMemory = NULL;
SharedTwitchData* pSharedData = NULL;

void InitSharedMemory() {
    hSharedMemory = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHARED_MEM_NAME);
    if (hSharedMemory) {
        pSharedData = (SharedTwitchData*)MapViewOfFile(hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedTwitchData));
        if (pSharedData) {
            char logBuffer[256];
            sprintf_s(logBuffer, "Connected to shared memory - %d Twitch names available", pSharedData->nameCount);
            LogToFile(logBuffer);

            bool dataValid = true;
            if (pSharedData->nameCount > MAX_NAMES) {
                sprintf_s(logBuffer, "ERROR: nameCount (%d) exceeds MAX_NAMES (%d)", pSharedData->nameCount, MAX_NAMES);
                LogToFile(logBuffer);
                dataValid = false;
            }

            if (dataValid) {
                sprintf_s(logBuffer, "Twitch names with scores (total: %d):", pSharedData->nameCount);
                LogToFile(logBuffer);
                for (int i = 0; i < pSharedData->nameCount; i++) {
                    sprintf_s(logBuffer, "  [%d] %s (score: %d)", i + 1, pSharedData->names[i].name, pSharedData->names[i].score);
                    LogToFile(logBuffer);
                }
            }
        } else {
            LogToFile("Failed to map shared memory view");
        }
    } else {
        LogToFile("Shared memory not found - using default names");
    }
}

bool IsNameRecent(const char* name) {
    if (!pSharedData) return false;

    for (int i = 0; i < RECENT_BUFFER_SIZE; i++) {
        if (strcmp(pSharedData->recentNames[i], name) == 0) {
            return true;
        }
    }
    return false;
}

void AddToRecentNames(const char* name) {
    if (!pSharedData) return;

    strncpy_s(pSharedData->recentNames[pSharedData->recentIndex], MAX_NAME_LENGTH, name, _TRUNCATE);
    pSharedData->recentIndex = (pSharedData->recentIndex + 1) % RECENT_BUFFER_SIZE;
}

// Priority-based selection with recency penalty
// Picks highest-priority names first, then falls back to lower priorities
std::string SelectWeightedName() {
    if (!pSharedData || pSharedData->nameCount == 0 || pSharedData->nameCount > MAX_NAMES) {
        LogToFile("ERROR: Invalid name count in SelectWeightedName");
        return "sublimnl";
    }

    int maxScore = 0;
    for (int i = 0; i < pSharedData->nameCount; i++) {
        if (pSharedData->names[i].score > 0 && pSharedData->names[i].score <= 10000) {
            if (pSharedData->names[i].score > maxScore) {
                maxScore = pSharedData->names[i].score;
            }
        }
    }

    if (maxScore == 0) {
        LogToFile("ERROR: No valid scores found");
        return "sublimnl";
    }

    // Try progressively lower score thresholds until we find non-recent candidates
    // Start at 80% of max, then 60%, 40%, 20%, then any score
    const int thresholdPercents[] = { 80, 60, 40, 20, 0 };

    for (int percent : thresholdPercents) {
        int scoreThreshold = (maxScore * percent) / 100;
        std::vector<int> candidates;

        // First try: non-recent names at this threshold
        for (int i = 0; i < pSharedData->nameCount; i++) {
            if (pSharedData->names[i].score >= scoreThreshold &&
                pSharedData->names[i].name[0] != '\0' &&
                !IsNameRecent(pSharedData->names[i].name)) {
                candidates.push_back(i);
            }
        }

        // If we found non-recent candidates, use them
        if (!candidates.empty()) {
            int selectedIndex = candidates[rand() % candidates.size()];
            AddToRecentNames(pSharedData->names[selectedIndex].name);
            return std::string(pSharedData->names[selectedIndex].name);
        }
    }

    // Last resort: allow recent names (all thresholds exhausted)
    std::vector<int> candidates;
    for (int i = 0; i < pSharedData->nameCount; i++) {
        if (pSharedData->names[i].name[0] != '\0') {
            candidates.push_back(i);
        }
    }

    if (candidates.empty()) {
        LogToFile("ERROR: No candidates found at all");
        return "sublimnl";
    }

    int selectedIndex = candidates[rand() % candidates.size()];
    AddToRecentNames(pSharedData->names[selectedIndex].name);
    return std::string(pSharedData->names[selectedIndex].name);
}

// Generate catname data from shared memory with weighted selection
std::string GenerateCatnameData() {
    if (g_catnameListGenerated) {
        LogToFile("Using cached catname list");
        return g_sharedCatnameList;
    }

    std::ostringstream oss;

    if (pSharedData && pSharedData->nameCount > 0 && pSharedData->nameCount <= MAX_NAMES) {
        char logBuffer[256];
        sprintf_s(logBuffer, "Generating catname list with %d unique names", pSharedData->nameCount);
        LogToFile(logBuffer);

        int numEntries = 20;
        for (int i = 0; i < numEntries; i++) {
            std::string name = SelectWeightedName();
            if (!name.empty() && name.length() < MAX_NAME_LENGTH) {
                oss << name << "\n";
            } else {
                LogToFile("WARNING: Invalid name selected, using fallback");
                oss << "sublimnl\n";
            }
        }

        sprintf_s(logBuffer, "Generated %d catname entries (will be reused for all files)", numEntries);
        LogToFile(logBuffer);
    } else {
        LogToFile("ERROR: Invalid shared data, using fallback names");
        for (int i = 0; i < 20; i++) {
            oss << "sublimnl\n";
        }
    }

    // Cache the list
    g_sharedCatnameList = oss.str();
    g_catnameListGenerated = true;

    return g_sharedCatnameList;
}

// Hook for CreateFileA - intercept when game opens catname files
HANDLE WINAPI HookedCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    // Call original
    HANDLE hFile = pOriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    // Check if this is a catname file and store the handle
    if (lpFileName && strstr(lpFileName, "catname")) {
        char logBuffer[512];
        sprintf_s(logBuffer, "=== CATNAME FILE OPENED: %s (handle=%p) ===", lpFileName, hFile);
        LogToFile(logBuffer);

        if (hFile != INVALID_HANDLE_VALUE) {
            catnameFileHandles.insert(hFile);
        }
    }

    return hFile;
}

// Hook for CreateFileW (wide char version)
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    if (lpFileName && wcsstr(lpFileName, L"catname")) {
        char logBuffer[512];
        char narrowPath[256];
        wcstombs_s(nullptr, narrowPath, lpFileName, sizeof(narrowPath) - 1);
        sprintf_s(logBuffer, "=== CATNAME FILE REQUESTED: %s ===", narrowPath);
        LogToFile(logBuffer);

        // Generate the catname data
        std::string catnameData = GenerateCatnameData();

        // Create a real temporary file and write our data to it
        char tempPath[MAX_PATH];
        char tempFile[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        GetTempFileNameA(tempPath, "cat", 0, tempFile);

        // Write data to temp file
        HANDLE hTempFile = CreateFileA(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (hTempFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hTempFile, catnameData.c_str(), (DWORD)catnameData.size(), &written, NULL);
            CloseHandle(hTempFile);
        }

        // Now open it for reading
        HANDLE hRealFile = CreateFileA(tempFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);

        if (hRealFile != INVALID_HANDLE_VALUE) {
            catnameFileHandles.insert(hRealFile);

            return hRealFile;
        } else {
            LogToFile("Failed to create temp file!");
        }
    }

    return pOriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// Hook for ReadFile - log when catname files are read
BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                           LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    BOOL result = pOriginalReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

    if (catnameFileHandles.count(hFile) > 0 && result && lpNumberOfBytesRead && *lpNumberOfBytesRead > 0) {
        char logBuffer[256];
        sprintf_s(logBuffer, "=== CATNAME FILE READ: %d bytes (handle=%p) ===", *lpNumberOfBytesRead, hFile);
        LogToFile(logBuffer);

        if (lpBuffer) {
            char preview[100] = {0};
            memcpy(preview, lpBuffer, min(*lpNumberOfBytesRead, (DWORD)99));
            preview[99] = '\0';
            sprintf_s(logBuffer, "Preview: %.60s", preview);
            LogToFile(logBuffer);
        }
    }

    return result;
}

// Hook for CloseHandle - clean up our tracking
BOOL WINAPI HookedCloseHandle(HANDLE hObject) {
    if (catnameFileHandles.count(hObject) > 0) {
        catnameFileHandles.erase(hObject);
    }

    // Always call original CloseHandle
    return pOriginalCloseHandle(hObject);
}

// Hook for GetFileSize - return size of our generated data
DWORD WINAPI HookedGetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh) {
    // Check if this is one of our fake catname handles
    if (catnameFileHandles.count(hFile) > 0 && catnameDataCache.count(hFile) > 0) {
        DWORD fileSize = (DWORD)catnameDataCache[hFile].size();

        if (lpFileSizeHigh) {
            *lpFileSizeHigh = 0;
        }

        return fileSize;
    }

    // For real files, call original
    return pOriginalGetFileSize(hFile, lpFileSizeHigh);
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        LogToFile("=== Hook DLL loaded ===");

        srand((unsigned int)time(NULL));

        if (MH_Initialize() != MH_OK) {
            LogToFile("ERROR: MinHook initialization failed!");
            return FALSE;
        }
        LogToFile("MinHook initialized");

        HMODULE hModule = GetModuleHandleA(NULL);
        if (!hModule) {
            LogToFile("ERROR: Failed to get module handle!");
            return FALSE;
        }

        char logBuffer[256];
        LogToFile("Hooking Windows API functions for file reading...");

        InitSharedMemory();

        // Hook CreateFileA to detect catname file opens
        MH_STATUS status = MH_CreateHookApi(L"kernel32.dll", "CreateFileA", &HookedCreateFileA, (LPVOID*)&pOriginalCreateFileA);
        if (status == MH_OK) {
            LogToFile("CreateFileA hook created");
        } else {
            sprintf_s(logBuffer, "ERROR: CreateFileA hook failed (status=%d)", status);
            LogToFile(logBuffer);
        }

        // Hook CreateFileW (wide char version)
        status = MH_CreateHookApi(L"kernel32.dll", "CreateFileW", &HookedCreateFileW, (LPVOID*)&pOriginalCreateFileW);
        if (status == MH_OK) {
            LogToFile("CreateFileW hook created");
        } else {
            sprintf_s(logBuffer, "ERROR: CreateFileW hook failed (status=%d)", status);
            LogToFile(logBuffer);
        }

        // Hook ReadFile to intercept catname data
        status = MH_CreateHookApi(L"kernel32.dll", "ReadFile", &HookedReadFile, (LPVOID*)&pOriginalReadFile);
        if (status == MH_OK) {
            LogToFile("ReadFile hook created");
        } else {
            sprintf_s(logBuffer, "ERROR: ReadFile hook failed (status=%d)", status);
            LogToFile(logBuffer);
        }

        // Hook CloseHandle to clean up tracking
        status = MH_CreateHookApi(L"kernel32.dll", "CloseHandle", &HookedCloseHandle, (LPVOID*)&pOriginalCloseHandle);
        if (status == MH_OK) {
            LogToFile("CloseHandle hook created");
        } else {
            sprintf_s(logBuffer, "ERROR: CloseHandle hook failed (status=%d)", status);
            LogToFile(logBuffer);
        }

        // Hook GetFileSize so our fake files have a size
        status = MH_CreateHookApi(L"kernel32.dll", "GetFileSize", &HookedGetFileSize, (LPVOID*)&pOriginalGetFileSize);
        if (status == MH_OK) {
            LogToFile("GetFileSize hook created");
        } else {
            sprintf_s(logBuffer, "ERROR: GetFileSize hook failed (status=%d)", status);
            LogToFile(logBuffer);
        }

        // Enable all hooks at once
        MH_EnableHook(MH_ALL_HOOKS);
        LogToFile("API hooks enabled - watching for catname file reads!");
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        LogToFile("=== Hook DLL unloading ===");
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }

    return TRUE;
}
