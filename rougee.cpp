#include <string>
#include <windows.h>
// Ensure `windows.h` is included before `detours.h`.
#include <detours.h>

#pragma comment(linker, "/MERGE:.detourd=.data")
#pragma comment(linker, "/MERGE:.detourc=.rdata")

using std::string;
using std::wstring;

int  wmain() {
    wchar_t *buffer = new wchar_t[MAX_PATH]();
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0";
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFile = buffer;
    ofn.lpstrTitle = L"Select Game";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) {
        ExitProcess(56);
    }
    wstring game = ofn.lpstrFile;
    wstring dir = game.substr(0, game.find_last_of(L"\\/"));
    string path(MAX_PATH, '\0');
    DWORD len = GetModuleFileNameA(0, path.data(), path.size());
    path.resize(len);
    string dll = path.substr(0, path.find_last_of("\\")) + "\\rougee.dll";
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    wchar_t cmd[] = L"";
    BOOL ok =
        DetourCreateProcessWithDllW(game.c_str(), cmd, 0, 0, 0, 0, 0,
                                    dir.c_str(), &si, &pi, dll.c_str(), 0);
    if (!ok) {
        wprintf(L"DetourCreateProcessWithDllW failed: %lu\n", GetLastError());
        return 56;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
