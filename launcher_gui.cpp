#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

#define TWITCH_CLIENT_ID "lh44mtruf0fm0xda9depv077kbqx87"
#define TWITCH_REDIRECT_URI "http://localhost:7877"
#define TWITCH_AUTH_URL "https://id.twitch.tv/oauth2/authorize"

#define CURRENT_VERSION "1.0.0"
#define GITHUB_REPO "sublimnl/mewnomics"
#define GITHUB_API_URL "https://api.github.com/repos/" GITHUB_REPO "/releases/latest"
#define GITHUB_RELEASES_URL "https://github.com/" GITHUB_REPO "/releases"

#define SHARED_MEM_NAME "MewgenicsTwitchNames"
#define MAX_NAMES 1000
#define MAX_NAME_LENGTH 50
#define RECENT_BUFFER_SIZE 20

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

HWND g_hWnd = NULL;
HWND g_hStatusText = NULL;
HWND g_hAuthButton = NULL;
HWND g_hLaunchButton = NULL;

HWND g_hCheckViewers = NULL;
HWND g_hCheckSubscribers = NULL;
HWND g_hCheckFollowers = NULL;
HWND g_hCheckModerators = NULL;
HWND g_hCheckVIPs = NULL;
HWND g_hCheckBitGivers = NULL;

bool g_useViewers = true;
bool g_useSubscribers = true;
bool g_useFollowers = false;
bool g_useModerators = true;
bool g_useVIPs = true;
bool g_useBitGivers = true;

std::string g_latestVersion;
bool g_updateAvailable = false;

std::string g_accessToken;
std::string g_channelName;
HANDLE g_hMapFile = NULL;
HANDLE g_hServerThread = NULL;
bool g_serverRunning = false;
HANDLE g_hGameProcess = NULL;
HANDLE g_hMonitorThread = NULL;
std::set<std::string> g_botList;

#define REGISTRY_KEY "SOFTWARE\\Mewnomics"

static bool RegReadString(const char* valueName, std::string& out) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    char buffer[512];
    DWORD bufSize = sizeof(buffer);
    DWORD type = 0;
    bool ok = (RegQueryValueExA(hKey, valueName, NULL, &type, (BYTE*)buffer, &bufSize) == ERROR_SUCCESS && type == REG_SZ);
    if (ok) out.assign(buffer, bufSize > 0 ? bufSize - 1 : 0);  // exclude null terminator
    RegCloseKey(hKey);
    return ok;
}

static bool RegWriteString(const char* valueName, const std::string& value) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    bool ok = (RegSetValueExA(hKey, valueName, 0, REG_SZ, (const BYTE*)value.c_str(), (DWORD)(value.size() + 1)) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return ok;
}

static bool RegReadDword(const char* valueName, DWORD& out) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD bufSize = sizeof(DWORD);
    DWORD type = 0;
    bool ok = (RegQueryValueExA(hKey, valueName, NULL, &type, (BYTE*)&out, &bufSize) == ERROR_SUCCESS && type == REG_DWORD);
    RegCloseKey(hKey);
    return ok;
}

static bool RegWriteDword(const char* valueName, DWORD value) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    bool ok = (RegSetValueExA(hKey, valueName, 0, REG_DWORD, (const BYTE*)&value, sizeof(DWORD)) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return ok;
}

bool SavePreferences() {
    DWORD flags = 0;
    if (g_useViewers)     flags |= (1 << 0);
    if (g_useSubscribers) flags |= (1 << 1);
    if (g_useFollowers)   flags |= (1 << 2);
    if (g_useModerators)  flags |= (1 << 3);
    if (g_useVIPs)        flags |= (1 << 4);
    if (g_useBitGivers)   flags |= (1 << 5);
    return RegWriteDword("NamePoolFlags", flags);
}

bool LoadPreferences() {
    DWORD flags = 0;
    if (!RegReadDword("NamePoolFlags", flags)) return false;

    g_useViewers     = (flags & (1 << 0)) != 0;
    g_useSubscribers = (flags & (1 << 1)) != 0;
    g_useFollowers   = (flags & (1 << 2)) != 0;
    g_useModerators  = (flags & (1 << 3)) != 0;
    g_useVIPs        = (flags & (1 << 4)) != 0;
    g_useBitGivers   = (flags & (1 << 5)) != 0;
    return true;
}

bool InjectDLL(DWORD processId, const char* dllPath);
DWORD FindProcessId(const char* processName);
void UpdateStatus(const char* status);
bool AuthenticateWithTwitch();
std::string GetAuthenticatedUserInfo(const std::string& accessToken);
bool FetchTwitchViewers(std::vector<std::string>& names);
bool FetchTwitchSubscribers(std::vector<std::string>& names);
bool FetchTwitchFollowers(std::vector<std::string>& names);
bool FetchTwitchModerators(std::vector<std::string>& names);
bool FetchTwitchVIPs(std::vector<std::string>& names);
bool FetchTopBitGivers(std::vector<std::string>& names);
void FetchBotList();
void RefreshTwitchData();
bool SaveNamesToSharedMemory(const std::vector<NameEntry>& nameEntries);
void LaunchGame();
bool SaveTokens();
bool LoadTokens();
bool ValidateToken();
void DisconnectFromTwitch();
bool CheckForUpdates();
int CompareVersions(const std::string& v1, const std::string& v2);
void OpenGitHubReleases();

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HBRUSH hbrBackground = NULL;

    switch (uMsg) {
        case WM_CREATE:
            hbrBackground = CreateSolidBrush(RGB(240, 240, 245));
            break;

        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            SetBkMode(hdcStatic, TRANSPARENT);
            SetTextColor(hdcStatic, RGB(40, 40, 40));
            return (LRESULT)hbrBackground;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);

            if (wmId == 100) {  // File -> Exit
                PostMessage(hwnd, WM_CLOSE, 0, 0);
            } else if (wmId == 101) {  // Help -> About
                char aboutText[1024];
                sprintf_s(aboutText,
                    "Mewnomics v%s\n\n"
                    "Created by: sublimnl\n"
                    "Repository: github.com/sublimnl/mewnomics\n\n"
                    "Acknowledgements:\n"
                    " - MinHook by Tsuda Kageyu\n"
                    " - Mewgenics (c) Edmund McMillen & Tyler Glaiel",
                    CURRENT_VERSION);
                MessageBoxA(hwnd, aboutText, "About Mewnomics", MB_OK | MB_ICONINFORMATION);
            } else if (wmId == 1) {  // Auth button
                if (!g_accessToken.empty()) {
                    DisconnectFromTwitch();
                } else {
                    AuthenticateWithTwitch();
                }
            } else if (wmId == 2) {  // Launch button
                LaunchGame();
            } else if (wmId >= 10 && wmId <= 15 && wmEvent == BN_CLICKED) {
                g_useViewers = (SendMessage(g_hCheckViewers, BM_GETCHECK, 0, 0) == BST_CHECKED);
                g_useSubscribers = (SendMessage(g_hCheckSubscribers, BM_GETCHECK, 0, 0) == BST_CHECKED);
                g_useFollowers = (SendMessage(g_hCheckFollowers, BM_GETCHECK, 0, 0) == BST_CHECKED);
                g_useModerators = (SendMessage(g_hCheckModerators, BM_GETCHECK, 0, 0) == BST_CHECKED);
                g_useVIPs = (SendMessage(g_hCheckVIPs, BM_GETCHECK, 0, 0) == BST_CHECKED);
                g_useBitGivers = (SendMessage(g_hCheckBitGivers, BM_GETCHECK, 0, 0) == BST_CHECKED);
                SavePreferences();
            }
            break;
        }

        case WM_DESTROY:
            if (hbrBackground) {
                DeleteObject(hbrBackground);
            }

            if (g_hMapFile) {
                CloseHandle(g_hMapFile);
            }

            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

bool CreateGUI() {
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "MewgenicsTwitchLauncher";
    wc.hbrBackground = CreateSolidBrush(RGB(240, 240, 245));
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(1));
    wc.hIconSm = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(1));

    if (!RegisterClassEx(&wc)) {
        return false;
    }

    HMENU hMenuBar = CreateMenu();
    HMENU hFileMenu = CreateMenu();
    HMENU hHelpMenu = CreateMenu();

    AppendMenuA(hFileMenu, MF_STRING, 100, "Exit");
    AppendMenuA(hHelpMenu, MF_STRING, 101, "About");

    AppendMenuA(hMenuBar, MF_POPUP, (UINT_PTR)hFileMenu, "File");
    AppendMenuA(hMenuBar, MF_POPUP, (UINT_PTR)hHelpMenu, "Help");

    char windowTitle[256];
    sprintf_s(windowTitle, "Mewnomics v%s", CURRENT_VERSION);

    g_hWnd = CreateWindowEx(
        0, "MewgenicsTwitchLauncher", windowTitle,
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 540,  // Taller to account for menu
        NULL, hMenuBar, GetModuleHandle(NULL), NULL
    );

    if (!g_hWnd) {
        return false;
    }

    HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

    HFONT hTitleFont = CreateFont(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

    HWND hTitle = CreateWindow("STATIC", "Mewnomics Launcher",
        WS_VISIBLE | WS_CHILD | SS_CENTER,
        0, 15, 500, 30, g_hWnd, NULL, NULL, NULL);
    SendMessage(hTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    g_hAuthButton = CreateWindow("BUTTON", "Connect with Twitch",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        30, 60, 440, 40, g_hWnd, (HMENU)1, NULL, NULL);
    SendMessage(g_hAuthButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    CreateWindow("STATIC", "",
        WS_VISIBLE | WS_CHILD | SS_ETCHEDHORZ,
        20, 115, 460, 2, g_hWnd, NULL, NULL, NULL);

    HWND hStatusLabel = CreateWindow("STATIC", "Status:",
        WS_VISIBLE | WS_CHILD,
        30, 130, 60, 22, g_hWnd, NULL, NULL, NULL);
    SendMessage(hStatusLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    g_hStatusText = CreateWindow("STATIC", "Not authenticated",
        WS_VISIBLE | WS_CHILD,
        100, 130, 370, 22, g_hWnd, NULL, NULL, NULL);
    SendMessage(g_hStatusText, WM_SETFONT, (WPARAM)hFont, TRUE);

    CreateWindow("STATIC", "",
        WS_VISIBLE | WS_CHILD | SS_ETCHEDHORZ,
        20, 165, 460, 2, g_hWnd, NULL, NULL, NULL);

    HWND hPoolsLabel = CreateWindow("STATIC", "Name Pools (check to include):",
        WS_VISIBLE | WS_CHILD,
        30, 180, 440, 22, g_hWnd, NULL, NULL, NULL);
    SendMessage(hPoolsLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    LoadPreferences();

    HFONT hCheckFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

    g_hCheckViewers = CreateWindow("BUTTON", "Current Viewers",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        40, 210, 220, 22, g_hWnd, (HMENU)10, NULL, NULL);
    SendMessage(g_hCheckViewers, WM_SETFONT, (WPARAM)hCheckFont, TRUE);
    SendMessage(g_hCheckViewers, BM_SETCHECK, g_useViewers ? BST_CHECKED : BST_UNCHECKED, 0);

    g_hCheckSubscribers = CreateWindow("BUTTON", "Subscribers",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        40, 240, 220, 22, g_hWnd, (HMENU)11, NULL, NULL);
    SendMessage(g_hCheckSubscribers, WM_SETFONT, (WPARAM)hCheckFont, TRUE);
    SendMessage(g_hCheckSubscribers, BM_SETCHECK, g_useSubscribers ? BST_CHECKED : BST_UNCHECKED, 0);

    g_hCheckFollowers = CreateWindow("BUTTON", "Followers",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        40, 270, 220, 22, g_hWnd, (HMENU)12, NULL, NULL);
    SendMessage(g_hCheckFollowers, WM_SETFONT, (WPARAM)hCheckFont, TRUE);
    SendMessage(g_hCheckFollowers, BM_SETCHECK, g_useFollowers ? BST_CHECKED : BST_UNCHECKED, 0);

    g_hCheckModerators = CreateWindow("BUTTON", "Moderators",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        260, 210, 220, 22, g_hWnd, (HMENU)13, NULL, NULL);
    SendMessage(g_hCheckModerators, WM_SETFONT, (WPARAM)hCheckFont, TRUE);
    SendMessage(g_hCheckModerators, BM_SETCHECK, g_useModerators ? BST_CHECKED : BST_UNCHECKED, 0);

    g_hCheckVIPs = CreateWindow("BUTTON", "VIPs",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        260, 240, 220, 22, g_hWnd, (HMENU)14, NULL, NULL);
    SendMessage(g_hCheckVIPs, WM_SETFONT, (WPARAM)hCheckFont, TRUE);
    SendMessage(g_hCheckVIPs, BM_SETCHECK, g_useVIPs ? BST_CHECKED : BST_UNCHECKED, 0);

    g_hCheckBitGivers = CreateWindow("BUTTON", "Bit Givers",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        260, 270, 220, 22, g_hWnd, (HMENU)15, NULL, NULL);
    SendMessage(g_hCheckBitGivers, WM_SETFONT, (WPARAM)hCheckFont, TRUE);
    SendMessage(g_hCheckBitGivers, BM_SETCHECK, g_useBitGivers ? BST_CHECKED : BST_UNCHECKED, 0);

    g_hLaunchButton = CreateWindow("BUTTON", "Launch Mewgenics",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        30, 320, 440, 50, g_hWnd, (HMENU)2, NULL, NULL);
    SendMessage(g_hLaunchButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    EnableWindow(g_hLaunchButton, FALSE);

    ShowWindow(g_hWnd, SW_SHOW);
    UpdateWindow(g_hWnd);

    CheckForUpdates();

    return true;
}

void UpdateStatus(const char* status) {
    SetWindowTextA(g_hStatusText, status);
}

bool SaveTokens() {
    return RegWriteString("AccessToken", g_accessToken)
        && RegWriteString("ChannelName", g_channelName);
}

bool LoadTokens() {
    RegReadString("AccessToken", g_accessToken);
    RegReadString("ChannelName", g_channelName);
    return !g_accessToken.empty();
}

bool ValidateToken() {
    if (g_accessToken.empty()) return false;
    std::string broadcasterID = GetAuthenticatedUserInfo(g_accessToken);
    return !broadcasterID.empty();
}

// Local HTTP server on port 7877 to catch the OAuth implicit flow callback.
// First GET serves JS that extracts the token from the URL fragment and POSTs it back.
DWORD WINAPI OAuthServerThread(LPVOID lpParam) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr("127.0.0.1");
    service.sin_port = htons(7877);

    if (bind(listenSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    if (listen(listenSocket, 5) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    UpdateStatus("Waiting for authorization...");

    bool tokenReceived = false;
    while (!tokenReceived && g_serverRunning) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) break;

        char recvbuf[4096];
        int bytesReceived = recv(clientSocket, recvbuf, sizeof(recvbuf) - 1, 0);

        if (bytesReceived > 0) {
            recvbuf[bytesReceived] = '\0';
            std::string request(recvbuf);

            if (request.find("GET") != std::string::npos && request.find("POST") == std::string::npos) {
                const char* response =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "<html><head><title>Twitch Authorization</title></head><body>"
                    "<h1>Processing...</h1>"
                    "<script>"
                    "var hash = window.location.hash.substring(1);"
                    "var params = new URLSearchParams(hash);"
                    "var token = params.get('access_token');"
                    "if (token) {"
                    "  fetch('http://localhost:7877/token', {"
                    "    method: 'POST',"
                    "    headers: {'Content-Type': 'application/x-www-form-urlencoded'},"
                    "    body: 'token=' + encodeURIComponent(token)"
                    "  }).then(function(res) {"
                    "    return res.text();"
                    "  }).then(function(html) {"
                    "    document.body.innerHTML = html;"
                    "  }).catch(function(err) {"
                    "    document.body.innerHTML = '<h1>Error</h1><p>' + err + '</p>';"
                    "  });"
                    "} else {"
                    "  document.body.innerHTML = '<h1>Error</h1><p>No access token found in URL.</p>';"
                    "}"
                    "</script>"
                    "</body></html>";
                send(clientSocket, response, strlen(response), 0);
            } else if (request.find("POST /token") != std::string::npos) {
                size_t bodyPos = request.find("\r\n\r\n");
                if (bodyPos != std::string::npos) {
                    std::string body = request.substr(bodyPos + 4);
                    size_t tokenPos = body.find("token=");
                    if (tokenPos != std::string::npos) {
                        tokenPos += 6;
                        size_t endPos = body.find("&", tokenPos);
                        if (endPos == std::string::npos) endPos = body.length();
                        g_accessToken = body.substr(tokenPos, endPos - tokenPos);

                        // URL decode the token (%XX -> char, + -> space)
                        std::string decoded;
                        for (size_t i = 0; i < g_accessToken.length(); i++) {
                            if (g_accessToken[i] == '%' && i + 2 < g_accessToken.length()) {
                                int value;
                                sscanf_s(g_accessToken.substr(i + 1, 2).c_str(), "%x", &value);
                                decoded += (char)value;
                                i += 2;
                            } else if (g_accessToken[i] == '+') {
                                decoded += ' ';
                            } else {
                                decoded += g_accessToken[i];
                            }
                        }
                        g_accessToken = decoded;

                        UpdateStatus("Fetching user info...");
                        std::string broadcasterID = GetAuthenticatedUserInfo(g_accessToken);

                        const char* response =
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/html\r\n"
                            "Connection: close\r\n"
                            "Access-Control-Allow-Origin: *\r\n"
                            "\r\n"
                            "<html><body><h1>Authentication Successful!</h1>"
                            "<p>You can close this window and return to the launcher.</p>"
                            "<script>setTimeout(function(){window.close();},1000);</script></body></html>";
                        send(clientSocket, response, strlen(response), 0);

                        if (!broadcasterID.empty() && !g_channelName.empty()) {
                            char statusBuf[256];
                            sprintf_s(statusBuf, "Authenticated as %s", g_channelName.c_str());
                            UpdateStatus(statusBuf);
                            SetWindowTextA(g_hAuthButton, "Disconnect from Twitch");
                            EnableWindow(g_hLaunchButton, TRUE);
                            SaveTokens();

                            SetForegroundWindow(g_hWnd);
                            BringWindowToTop(g_hWnd);
                            SetWindowPos(g_hWnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
                        } else {
                            UpdateStatus("Failed to get user info");
                        }
                        tokenReceived = true;
                    }
                }
            } else if (request.find("GET") != std::string::npos) {
                const char* response =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "<html><head><title>Twitch Authorization</title></head><body>"
                    "<h1>Processing...</h1>"
                    "<script>"
                    "var hash = window.location.hash.substring(1);"
                    "var params = new URLSearchParams(hash);"
                    "var token = params.get('access_token');"
                    "if (token) {"
                    "  fetch('http://localhost:7877/token', {"
                    "    method: 'POST',"
                    "    headers: {'Content-Type': 'application/x-www-form-urlencoded'},"
                    "    body: 'token=' + encodeURIComponent(token)"
                    "  }).then(function(res) {"
                    "    return res.text();"
                    "  }).then(function(html) {"
                    "    document.body.innerHTML = html;"
                    "  }).catch(function(err) {"
                    "    document.body.innerHTML = '<h1>Error</h1><p>' + err + '</p>';"
                    "  });"
                    "} else {"
                    "  document.body.innerHTML = '<h1>Error</h1><p>No access token found in URL.</p>';"
                    "}"
                    "</script>"
                    "</body></html>";
                send(clientSocket, response, strlen(response), 0);
            }
        }

        closesocket(clientSocket);
    }

    closesocket(listenSocket);
    WSACleanup();
    g_serverRunning = false;
    return 0;
}

void DisconnectFromTwitch() {
    g_accessToken.clear();
    g_channelName.clear();

    // Only delete token values, preserve preferences
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "AccessToken");
        RegDeleteValueA(hKey, "ChannelName");
        RegCloseKey(hKey);
    }

    // Reset UI
    SetWindowTextA(g_hAuthButton, "Connect with Twitch");
    EnableWindow(g_hLaunchButton, FALSE);
    UpdateStatus("Disconnected from Twitch");
}

// Authenticate with Twitch
bool AuthenticateWithTwitch() {
    // Start OAuth callback server
    if (!g_serverRunning) {
        g_serverRunning = true;
        g_hServerThread = CreateThread(NULL, 0, OAuthServerThread, NULL, 0, NULL);
        if (!g_hServerThread) {
            UpdateStatus("Failed to start callback server");
            g_serverRunning = false;
            return false;
        }
    }

    // Give server a moment to start
    Sleep(500);

    UpdateStatus("Opening browser for authentication...");

    // Build OAuth URL for implicit flow with all needed scopes
    char authUrl[2048];
    sprintf_s(authUrl, "%s?client_id=%s&redirect_uri=%s&response_type=token&scope=user:read:email%%20channel:read:subscriptions%%20moderator:read:chatters%%20moderator:read:followers%%20moderation:read%%20channel:read:vips%%20bits:read",
              TWITCH_AUTH_URL, TWITCH_CLIENT_ID, TWITCH_REDIRECT_URI);

    // Open browser
    ShellExecuteA(NULL, "open", authUrl, NULL, NULL, SW_SHOWNORMAL);

    return false; // Button will be enabled by server thread when token received
}

// Fetch a remote text file of bot usernames (one per line) and insert into g_botList
static void FetchRemoteBotList(HINTERNET hConnect, const wchar_t* path) {
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) return;

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {

        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &statusCode, &statusCodeSize, NULL);

        if (statusCode == 200) {
            std::string response;
            DWORD dwSize = 0, dwDownloaded = 0;
            char buffer[4096];
            do {
                dwSize = 0;
                if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
                    if (WinHttpReadData(hRequest, buffer, min(dwSize, sizeof(buffer)), &dwDownloaded)) {
                        response.append(buffer, dwDownloaded);
                    }
                }
            } while (dwSize > 0);

            std::istringstream stream(response);
            std::string line;
            while (std::getline(stream, line)) {
                line.erase(0, line.find_first_not_of(" \t\r\n"));
                line.erase(line.find_last_not_of(" \t\r\n") + 1);
                if (!line.empty()) {
                    std::transform(line.begin(), line.end(), line.begin(), ::tolower);
                    g_botList.insert(line);
                }
            }
        }
    }

    WinHttpCloseHandle(hRequest);
}

void FetchBotList() {
    g_botList.clear();

    HINTERNET hSession = WinHttpOpen(L"MewgenicsTwitchLauncher/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    HINTERNET hConnect = WinHttpConnect(hSession, L"raw.githubusercontent.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return;
    }

    // Known bot accounts
    FetchRemoteBotList(hConnect, L"/isdsdataarchive/twitch_ban_lists/refs/heads/main/whitelisted_bots.txt");

    // Follower bots - only worth filtering if followers pool is enabled
    if (g_useFollowers) {
        FetchRemoteBotList(hConnect, L"/isdsdataarchive/twitch_ban_lists/refs/heads/main/follower_bot_list.txt");
    }

    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

// Helper function to get authenticated user info (returns broadcaster ID and sets g_channelName)
std::string GetAuthenticatedUserInfo(const std::string& accessToken) {
    HINTERNET hSession = WinHttpOpen(L"MewgenicsTwitchLauncher/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.twitch.tv", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Call /helix/users without parameters to get authenticated user
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/helix/users",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Add headers
    std::wstring authHeader = L"Authorization: Bearer " + std::wstring(accessToken.begin(), accessToken.end());
    std::string clientIdStr(TWITCH_CLIENT_ID);
    std::wstring clientHeader = L"Client-Id: " + std::wstring(clientIdStr.begin(), clientIdStr.end());
    WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, clientHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Read response
    std::string response;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    char buffer[4096];
    do {
        dwSize = 0;
        if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
            if (WinHttpReadData(hRequest, buffer, min(dwSize, sizeof(buffer)), &dwDownloaded)) {
                response.append(buffer, dwDownloaded);
            }
        }
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    // Simple parsing to extract login and ID
    size_t loginPos = response.find("\"login\":\"");
    if (loginPos != std::string::npos) {
        loginPos += 9;
        size_t endPos = response.find("\"", loginPos);
        if (endPos != std::string::npos) {
            g_channelName = response.substr(loginPos, endPos - loginPos);
        }
    }

    size_t idPos = response.find("\"id\":\"");
    if (idPos != std::string::npos) {
        idPos += 6;
        size_t endPos = response.find("\"", idPos);
        if (endPos != std::string::npos) {
            return response.substr(idPos, endPos - idPos);
        }
    }

    return "";
}

// Fetch viewers from Twitch API (with pagination for 100+ viewer streams)
bool FetchTwitchViewers(std::vector<std::string>& names) {
    if (g_accessToken.empty()) return false;

    // Get broadcaster ID
    std::string broadcasterID = GetAuthenticatedUserInfo(g_accessToken);
    if (broadcasterID.empty()) {
        UpdateStatus("Failed to get broadcaster ID");
        return false;
    }

    std::string cursor = "";
    int pageCount = 0;
    const int MAX_PAGES = 10; // Up to 1000 concurrent viewers

    // Paginate through all results
    do {
        HINTERNET hSession = WinHttpOpen(L"MewgenicsTwitchLauncher/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) break;

        HINTERNET hConnect = WinHttpConnect(hSession, L"api.twitch.tv", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            break;
        }

        // Build path with cursor if we have one
        std::wstring broadcasterId_w(broadcasterID.begin(), broadcasterID.end());
        std::wstring path = L"/helix/chat/chatters?broadcaster_id=" + broadcasterId_w + L"&moderator_id=" + broadcasterId_w + L"&first=100";
        if (!cursor.empty()) {
            std::wstring cursor_w(cursor.begin(), cursor.end());
            path += L"&after=" + cursor_w;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            break;
        }

        // Add headers
        std::wstring authHeader = L"Authorization: Bearer " + std::wstring(g_accessToken.begin(), g_accessToken.end());
        std::string clientIdStr(TWITCH_CLIENT_ID);
        std::wstring clientHeader = L"Client-Id: " + std::wstring(clientIdStr.begin(), clientIdStr.end());
        WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
        WinHttpAddRequestHeaders(hRequest, clientHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(hRequest, NULL)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            break;
        }

        // Read response
        std::string response;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        char buffer[4096];
        do {
            dwSize = 0;
            if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
                if (WinHttpReadData(hRequest, buffer, min(dwSize, sizeof(buffer)), &dwDownloaded)) {
                    response.append(buffer, dwDownloaded);
                }
            }
        } while (dwSize > 0);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        // Parse usernames from this page
        size_t pos = 0;
        while ((pos = response.find("\"user_login\":\"", pos)) != std::string::npos) {
            pos += 14;
            size_t endPos = response.find("\"", pos);
            if (endPos != std::string::npos) {
                names.push_back(response.substr(pos, endPos - pos));
                pos = endPos;
            }
        }

        // Check for pagination cursor
        cursor = "";
        size_t cursorPos = response.find("\"cursor\":\"");
        if (cursorPos != std::string::npos) {
            cursorPos += 10;
            size_t endPos = response.find("\"", cursorPos);
            if (endPos != std::string::npos) {
                cursor = response.substr(cursorPos, endPos - cursorPos);
            }
        }

        pageCount++;
    } while (!cursor.empty() && pageCount < MAX_PAGES);

    return !names.empty();
}

// Fetch subscribers from Twitch API (with pagination)
bool FetchTwitchSubscribers(std::vector<std::string>& names) {
    if (g_accessToken.empty()) return false;

    // Get broadcaster ID
    std::string broadcasterID = GetAuthenticatedUserInfo(g_accessToken);
    if (broadcasterID.empty()) {
        return false;
    }

    std::string cursor = "";
    int pageCount = 0;
    const int MAX_PAGES = 10; // Limit to 1000 subscribers max

    // Paginate through all results
    do {
        HINTERNET hSession = WinHttpOpen(L"MewgenicsTwitchLauncher/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) break;

        HINTERNET hConnect = WinHttpConnect(hSession, L"api.twitch.tv", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            break;
        }

        // Build path with cursor if we have one
        std::wstring broadcasterId_w(broadcasterID.begin(), broadcasterID.end());
        std::wstring path = L"/helix/subscriptions?broadcaster_id=" + broadcasterId_w + L"&first=100";
        if (!cursor.empty()) {
            std::wstring cursor_w(cursor.begin(), cursor.end());
            path += L"&after=" + cursor_w;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            break;
        }

        // Add headers
        std::wstring authHeader = L"Authorization: Bearer " + std::wstring(g_accessToken.begin(), g_accessToken.end());
        std::string clientIdStr(TWITCH_CLIENT_ID);
        std::wstring clientHeader = L"Client-Id: " + std::wstring(clientIdStr.begin(), clientIdStr.end());
        WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
        WinHttpAddRequestHeaders(hRequest, clientHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(hRequest, NULL)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            break;
        }

        // Read response
        std::string response;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        char buffer[4096];
        do {
            dwSize = 0;
            if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
                if (WinHttpReadData(hRequest, buffer, min(dwSize, sizeof(buffer)), &dwDownloaded)) {
                    response.append(buffer, dwDownloaded);
                }
            }
        } while (dwSize > 0);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        // Parse usernames from this page
        size_t pos = 0;
        while ((pos = response.find("\"user_login\":\"", pos)) != std::string::npos) {
            pos += 14;
            size_t endPos = response.find("\"", pos);
            if (endPos != std::string::npos) {
                names.push_back(response.substr(pos, endPos - pos));
                pos = endPos;
            }
        }

        // Check for pagination cursor
        cursor = "";
        size_t cursorPos = response.find("\"cursor\":\"");
        if (cursorPos != std::string::npos) {
            cursorPos += 10;
            size_t endPos = response.find("\"", cursorPos);
            if (endPos != std::string::npos) {
                cursor = response.substr(cursorPos, endPos - cursorPos);
            }
        }

        pageCount++;
    } while (!cursor.empty() && pageCount < MAX_PAGES);

    return !names.empty();
}

// Fetch followers from Twitch API (with pagination)
bool FetchTwitchFollowers(std::vector<std::string>& names) {
    if (g_accessToken.empty()) return false;

    // Get broadcaster ID
    std::string broadcasterID = GetAuthenticatedUserInfo(g_accessToken);
    if (broadcasterID.empty()) {
        return false;
    }

    std::string cursor = "";
    int pageCount = 0;
    const int MAX_PAGES = 10; // Limit to 1000 followers max (10 pages * 100)

    // Paginate through all results
    do {
        HINTERNET hSession = WinHttpOpen(L"MewgenicsTwitchLauncher/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) break;

        HINTERNET hConnect = WinHttpConnect(hSession, L"api.twitch.tv", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            break;
        }

        // Build path with cursor if we have one
        std::wstring broadcasterId_w(broadcasterID.begin(), broadcasterID.end());
        std::wstring path = L"/helix/channels/followers?broadcaster_id=" + broadcasterId_w + L"&first=100";
        if (!cursor.empty()) {
            std::wstring cursor_w(cursor.begin(), cursor.end());
            path += L"&after=" + cursor_w;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            break;
        }

        // Add headers
        std::wstring authHeader = L"Authorization: Bearer " + std::wstring(g_accessToken.begin(), g_accessToken.end());
        std::string clientIdStr(TWITCH_CLIENT_ID);
        std::wstring clientHeader = L"Client-Id: " + std::wstring(clientIdStr.begin(), clientIdStr.end());
        WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
        WinHttpAddRequestHeaders(hRequest, clientHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(hRequest, NULL)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            break;
        }

        // Read response
        std::string response;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        char buffer[4096];
        do {
            dwSize = 0;
            if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
                if (WinHttpReadData(hRequest, buffer, min(dwSize, sizeof(buffer)), &dwDownloaded)) {
                    response.append(buffer, dwDownloaded);
                }
            }
        } while (dwSize > 0);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        // Parse usernames from this page
        size_t pos = 0;
        while ((pos = response.find("\"user_login\":\"", pos)) != std::string::npos) {
            pos += 14;
            size_t endPos = response.find("\"", pos);
            if (endPos != std::string::npos) {
                names.push_back(response.substr(pos, endPos - pos));
                pos = endPos;
            }
        }

        // Check for pagination cursor
        cursor = "";
        size_t cursorPos = response.find("\"cursor\":\"");
        if (cursorPos != std::string::npos) {
            cursorPos += 10;
            size_t endPos = response.find("\"", cursorPos);
            if (endPos != std::string::npos) {
                cursor = response.substr(cursorPos, endPos - cursorPos);
            }
        }

        pageCount++;
    } while (!cursor.empty() && pageCount < MAX_PAGES);

    return !names.empty();
}

// Fetch moderators from Twitch API
bool FetchTwitchModerators(std::vector<std::string>& names) {
    if (g_accessToken.empty()) return false;

    std::string broadcasterID = GetAuthenticatedUserInfo(g_accessToken);
    if (broadcasterID.empty()) return false;

    HINTERNET hSession = WinHttpOpen(L"MewgenicsTwitchLauncher/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.twitch.tv", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring broadcasterId_w(broadcasterID.begin(), broadcasterID.end());
    std::wstring path = L"/helix/moderation/moderators?broadcaster_id=" + broadcasterId_w + L"&first=100";
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring authHeader = L"Authorization: Bearer " + std::wstring(g_accessToken.begin(), g_accessToken.end());
    std::string clientIdStr(TWITCH_CLIENT_ID);
    std::wstring clientHeader = L"Client-Id: " + std::wstring(clientIdStr.begin(), clientIdStr.end());
    WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, clientHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::string response;
    DWORD dwSize = 0, dwDownloaded = 0;
    char buffer[4096];
    do {
        dwSize = 0;
        if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
            if (WinHttpReadData(hRequest, buffer, min(dwSize, sizeof(buffer)), &dwDownloaded)) {
                response.append(buffer, dwDownloaded);
            }
        }
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    size_t pos = 0;
    while ((pos = response.find("\"user_login\":\"", pos)) != std::string::npos) {
        pos += 14;
        size_t endPos = response.find("\"", pos);
        if (endPos != std::string::npos) {
            names.push_back(response.substr(pos, endPos - pos));
            pos = endPos;
        }
    }

    return !names.empty();
}

// Fetch VIPs from Twitch API
bool FetchTwitchVIPs(std::vector<std::string>& names) {
    if (g_accessToken.empty()) return false;

    std::string broadcasterID = GetAuthenticatedUserInfo(g_accessToken);
    if (broadcasterID.empty()) return false;

    HINTERNET hSession = WinHttpOpen(L"MewgenicsTwitchLauncher/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.twitch.tv", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring broadcasterId_w(broadcasterID.begin(), broadcasterID.end());
    std::wstring path = L"/helix/channels/vips?broadcaster_id=" + broadcasterId_w + L"&first=100";
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring authHeader = L"Authorization: Bearer " + std::wstring(g_accessToken.begin(), g_accessToken.end());
    std::string clientIdStr(TWITCH_CLIENT_ID);
    std::wstring clientHeader = L"Client-Id: " + std::wstring(clientIdStr.begin(), clientIdStr.end());
    WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, clientHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::string response;
    DWORD dwSize = 0, dwDownloaded = 0;
    char buffer[4096];
    do {
        dwSize = 0;
        if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
            if (WinHttpReadData(hRequest, buffer, min(dwSize, sizeof(buffer)), &dwDownloaded)) {
                response.append(buffer, dwDownloaded);
            }
        }
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    size_t pos = 0;
    while ((pos = response.find("\"user_login\":\"", pos)) != std::string::npos) {
        pos += 14;
        size_t endPos = response.find("\"", pos);
        if (endPos != std::string::npos) {
            names.push_back(response.substr(pos, endPos - pos));
            pos = endPos;
        }
    }

    return !names.empty();
}

// Fetch top bit givers from Twitch API
bool FetchTopBitGivers(std::vector<std::string>& names) {
    if (g_accessToken.empty()) return false;

    std::string broadcasterID = GetAuthenticatedUserInfo(g_accessToken);
    if (broadcasterID.empty()) return false;

    HINTERNET hSession = WinHttpOpen(L"MewgenicsTwitchLauncher/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.twitch.tv", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring path = L"/helix/bits/leaderboard?count=100";  // Top 100 bit givers
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring authHeader = L"Authorization: Bearer " + std::wstring(g_accessToken.begin(), g_accessToken.end());
    std::string clientIdStr(TWITCH_CLIENT_ID);
    std::wstring clientHeader = L"Client-Id: " + std::wstring(clientIdStr.begin(), clientIdStr.end());
    WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, clientHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::string response;
    DWORD dwSize = 0, dwDownloaded = 0;
    char buffer[4096];
    do {
        dwSize = 0;
        if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
            if (WinHttpReadData(hRequest, buffer, min(dwSize, sizeof(buffer)), &dwDownloaded)) {
                response.append(buffer, dwDownloaded);
            }
        }
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    size_t pos = 0;
    while ((pos = response.find("\"user_login\":\"", pos)) != std::string::npos) {
        pos += 14;
        size_t endPos = response.find("\"", pos);
        if (endPos != std::string::npos) {
            names.push_back(response.substr(pos, endPos - pos));
            pos = endPos;
        }
    }

    return !names.empty();
}

// Save names with scores to shared memory
bool SaveNamesToSharedMemory(const std::vector<NameEntry>& nameEntries) {
    g_hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
        sizeof(SharedTwitchData), SHARED_MEM_NAME);

    if (!g_hMapFile) return false;

    SharedTwitchData* pData = (SharedTwitchData*)MapViewOfFile(
        g_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedTwitchData));

    if (!pData) {
        CloseHandle(g_hMapFile);
        return false;
    }

    // Initialize
    memset(pData, 0, sizeof(SharedTwitchData));
    pData->nameCount = min((int)nameEntries.size(), MAX_NAMES);
    pData->recentIndex = 0;

    // Copy name entries with scores
    for (int i = 0; i < pData->nameCount; i++) {
        pData->names[i] = nameEntries[i];
    }

    UnmapViewOfFile(pData);
    return true;
}

// Refresh Twitch data and update shared memory
void RefreshTwitchData() {
    // Fetch Twitch data based on user preferences
    std::vector<std::string> viewers, subscribers, followers, moderators, vips, bitGivers;

    if (g_useViewers) FetchTwitchViewers(viewers);
    if (g_useSubscribers) FetchTwitchSubscribers(subscribers);
    if (g_useFollowers) FetchTwitchFollowers(followers);
    if (g_useModerators) FetchTwitchModerators(moderators);
    if (g_useVIPs) FetchTwitchVIPs(vips);
    if (g_useBitGivers) FetchTopBitGivers(bitGivers);

    // Build scored name list with ADDITIVE priorities (and bot filtering)
    std::map<std::string, int> scoredNames;

    // Helper lambda to add name if not a bot
    auto addIfNotBot = [&](const std::string& name, int score) {
        std::string lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        if (g_botList.find(lowerName) == g_botList.end()) {
            scoredNames[name] += score;
        }
    };

    // Add names from enabled pools only
    if (g_useFollowers) {
        for (const auto& name : followers) addIfNotBot(name, 10);
    }
    if (g_useBitGivers) {
        for (const auto& name : bitGivers) addIfNotBot(name, 25);
    }
    if (g_useSubscribers) {
        for (const auto& name : subscribers) addIfNotBot(name, 50);
    }
    if (g_useModerators) {
        for (const auto& name : moderators) addIfNotBot(name, 75);
    }
    if (g_useVIPs) {
        for (const auto& name : vips) addIfNotBot(name, 75);
    }
    if (g_useViewers) {
        for (const auto& name : viewers) addIfNotBot(name, 100);
    }

    // Easter egg: Always add mod creator with special score
    scoredNames["sublimnl"] = 69420;

    // Convert to vector
    std::vector<NameEntry> nameEntries;
    for (const auto& pair : scoredNames) {
        NameEntry entry;
        strncpy_s(entry.name, MAX_NAME_LENGTH, pair.first.c_str(), _TRUNCATE);
        entry.score = pair.second;
        nameEntries.push_back(entry);
    }

    // Update status
    char statusBuf[512];
    sprintf_s(statusBuf, "Found %d names (%dv %ds %df %dm %dvip %dbit | %d bots filtered)",
              (int)nameEntries.size(), (int)viewers.size(), (int)subscribers.size(),
              (int)followers.size(), (int)moderators.size(), (int)vips.size(),
              (int)bitGivers.size(), (int)g_botList.size());
    UpdateStatus(statusBuf);

    // Warn if pool is small
    if (nameEntries.size() < 20) {
        char warningBuf[512];
        sprintf_s(warningBuf,
            "Only %d unique names found!\n\n"
            "Recommended: At least 20 names for best variety.\n\n"
            "The game uses 20 names for all gender types (male, female, neutral).\n"
            "Some names will appear multiple times to fill the list.\n\n"
            "Tip: Enable more name pools (Followers, Subscribers, etc.) in the launcher.",
            (int)nameEntries.size());
        MessageBoxA(g_hWnd, warningBuf, "Small Name Pool Warning", MB_OK | MB_ICONWARNING);
    }

    // Save to shared memory
    SaveNamesToSharedMemory(nameEntries);
}

// Monitor game process and close launcher when game exits
DWORD WINAPI GameMonitorThread(LPVOID lpParam) {
    if (!g_hGameProcess) return 1;

    // Wait for game process to exit
    WaitForSingleObject(g_hGameProcess, INFINITE);

    // Game exited - close launcher
    PostMessage(g_hWnd, WM_CLOSE, 0, 0);

    return 0;
}

// Launch the game with injection
void LaunchGame() {
    // Validate at least one pool is selected
    if (!g_useViewers && !g_useSubscribers && !g_useFollowers &&
        !g_useModerators && !g_useVIPs && !g_useBitGivers) {
        MessageBoxA(g_hWnd, "Please select at least one name pool!", "No Pools Selected", MB_OK | MB_ICONWARNING);
        UpdateStatus("ERROR: No name pools selected");
        return;
    }

    UpdateStatus("Fetching bot list...");
    FetchBotList();
    UpdateStatus("Fetching Twitch data...");
    RefreshTwitchData();

    UpdateStatus("Starting game...");

    // Get paths
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    std::string dllPath = std::string(currentDir) + "\\hook.dll";
    std::string exePath = std::string(currentDir) + "\\Mewgenics.exe";

    // Check files exist
    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxA(g_hWnd, "hook.dll not found!", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Start game
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        MessageBoxA(g_hWnd, "Failed to start Mewgenics.exe!", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Keep process handle for monitoring
    g_hGameProcess = pi.hProcess;
    CloseHandle(pi.hThread);  // Thread handle not needed

    // Wait for game to start (retry for up to 20 seconds)
    UpdateStatus("Waiting for game to start...");
    Sleep(3000);  // Initial wait

    DWORD processId = 0;
    for (int i = 0; i < 20; i++) {
        processId = FindProcessId("Mewgenics.exe");
        if (processId != 0) break;
        Sleep(1000);
    }

    if (processId == 0) {
        UpdateStatus("ERROR: Game process not found after 20 seconds");
        return;
    }

    // Wait for game to initialize before injecting
    UpdateStatus("Game found! Waiting for initialization...");
    Sleep(3000);

    // Inject DLL with retry logic (up to 3 attempts)
    bool injected = false;
    for (int attempt = 1; attempt <= 3; attempt++) {
        char statusMsg[256];
        if (attempt == 1) {
            UpdateStatus("Injecting hook...");
        } else {
            sprintf_s(statusMsg, "Injection failed, retrying (%d/3)...", attempt);
            UpdateStatus(statusMsg);
            Sleep(2000);  // Wait 2 seconds between retries
        }

        if (InjectDLL(processId, dllPath.c_str())) {
            injected = true;
            break;
        }

        // Check if game is still running before retrying
        if (attempt < 3) {
            DWORD checkPid = FindProcessId("Mewgenics.exe");
            if (checkPid == 0) {
                UpdateStatus("Game process terminated, cannot retry injection");
                return;
            }
        }
    }

    if (injected) {
        UpdateStatus("Success! Game running with Twitch names!");

        // Start game monitor thread to auto-close launcher when game exits
        g_hMonitorThread = CreateThread(NULL, 0, GameMonitorThread, NULL, 0, NULL);
    } else {
        UpdateStatus("ERROR: Failed to inject hook after 3 attempts");
        MessageBoxA(g_hWnd, "Failed to inject hook after 3 attempts.\nTry running as Administrator.",
                    "Injection Failed", MB_OK | MB_ICONERROR);
    }
}

// DLL injection code (same as before)
bool InjectDLL(DWORD processId, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return false;

    size_t pathLen = strlen(dllPath) + 1;
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemotePath) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemotePath, dllPath, pathLen, NULL)) {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemotePath, 0, NULL);

    if (!hThread) {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

DWORD FindProcessId(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// Compare two semantic versions (returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2)
int CompareVersions(const std::string& v1, const std::string& v2) {
    int major1 = 0, minor1 = 0, patch1 = 0;
    int major2 = 0, minor2 = 0, patch2 = 0;

    sscanf_s(v1.c_str(), "%d.%d.%d", &major1, &minor1, &patch1);
    sscanf_s(v2.c_str(), "%d.%d.%d", &major2, &minor2, &patch2);

    if (major1 != major2) return (major1 > major2) ? 1 : -1;
    if (minor1 != minor2) return (minor1 > minor2) ? 1 : -1;
    if (patch1 != patch2) return (patch1 > patch2) ? 1 : -1;
    return 0;
}

// Open GitHub releases page in browser
void OpenGitHubReleases() {
    ShellExecuteA(NULL, "open", GITHUB_RELEASES_URL, NULL, NULL, SW_SHOW);
}

// Check for updates from GitHub
bool CheckForUpdates() {
    HINTERNET hSession = WinHttpOpen(L"Mewnomics/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.github.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Convert repo path to wide string
    std::string apiPath = "/repos/" + std::string(GITHUB_REPO) + "/releases/latest";
    std::wstring wApiPath(apiPath.begin(), apiPath.end());

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wApiPath.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Add User-Agent header (required by GitHub API)
    std::wstring headers = L"User-Agent: Mewnomics\r\n";
    WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Read response
    std::string response;
    DWORD dwSize = 0, dwDownloaded = 0;
    char buffer[4096];
    do {
        dwSize = 0;
        if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
            if (WinHttpReadData(hRequest, buffer, min(dwSize, sizeof(buffer)), &dwDownloaded)) {
                response.append(buffer, dwDownloaded);
            }
        }
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    // Parse "tag_name" from JSON (simple parsing - looks for "tag_name":"vX.Y.Z")
    size_t tagPos = response.find("\"tag_name\":");
    if (tagPos != std::string::npos) {
        tagPos = response.find("\"v", tagPos);
        if (tagPos != std::string::npos) {
            tagPos += 2;  // Skip "v
            size_t endPos = response.find("\"", tagPos);
            if (endPos != std::string::npos) {
                g_latestVersion = response.substr(tagPos, endPos - tagPos);

                // Compare versions
                if (CompareVersions(g_latestVersion, CURRENT_VERSION) > 0) {
                    g_updateAvailable = true;

                    // Show update dialog
                    char updateMsg[512];
                    sprintf_s(updateMsg,
                        "A new version of Mewnomics is available!\n\n"
                        "Current version: v%s\n"
                        "Latest version: v%s\n\n"
                        "Would you like to download the new version now?",
                        CURRENT_VERSION, g_latestVersion.c_str());

                    int result = MessageBoxA(g_hWnd, updateMsg, "Update Available",
                        MB_YESNO | MB_ICONINFORMATION);

                    if (result == IDYES) {
                        OpenGitHubReleases();
                    }

                    return true;
                }
            }
        }
    }

    return false;
}

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!CreateGUI()) {
        MessageBoxA(NULL, "Failed to create GUI!", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Try to load saved tokens
    if (LoadTokens()) {
        UpdateStatus("Validating saved token...");

        if (ValidateToken()) {
            char statusBuf[256];
            sprintf_s(statusBuf, "Authenticated as %s", g_channelName.c_str());
            UpdateStatus(statusBuf);
            SetWindowTextA(g_hAuthButton, "Disconnect from Twitch");
            EnableWindow(g_hLaunchButton, TRUE);
        } else {
            g_accessToken.clear();
            g_channelName.clear();
            HKEY hKey;
            if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                RegDeleteValueA(hKey, "AccessToken");
                RegDeleteValueA(hKey, "ChannelName");
                RegCloseKey(hKey);
            }
            UpdateStatus("Saved token expired - please re-authenticate");
        }
    } else {
        UpdateStatus("Not authenticated");
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
