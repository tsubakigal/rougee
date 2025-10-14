#include <cassert>       // assert
#include <cstdint>       // uint8_t ...
#include <format>        // format
#include <fstream>       // wofstream
#include <string>        // string | wstring
#include <unordered_set> // unordered_set
#include <vector>
#include <windows.h>
// Ensure `windows.h` is included before `detours.h`.
#include <detours.h>

#pragma warning(push)
#pragma warning(disable : 4819)
#include "tp_stub.h"
#pragma warning(pop)

#ifdef _DEBUG
#include <cstdio>
#include <ctime>
#endif

#pragma comment(linker, "/MERGE:.detourd=.data")
#pragma comment(linker, "/MERGE:.detourc=.rdata")

// Just for code folding :(
namespace {

using std::format;
using std::string;
using std::wstring;

static HMODULE exe;         // game.exe
static HMODULE dll;         // rougee.dll
static wstring log_file;    // rougee.txt
static std::wofstream wof;  // rougee.txt
static wstring log_file2;   // index.txt
static std::wofstream wof2; // index.txt
static std::unordered_set<wstring> dir_hash_set;
static std::unordered_set<wstring> file_hash_set;

static bool has_init = false;
static bool load_index = true;
static bool load_hash = true;

inline namespace detour {

#define FORDETOUR(a, b) ((PVOID *)&(a)), ((PVOID)(b))

void Attach(PVOID *ppPointer, PVOID pDetour) {
    DetourUpdateThread(GetCurrentThread());
    DetourTransactionBegin();
    DetourAttach(ppPointer, pDetour);
    DetourTransactionCommit();
}

void Detach(PVOID *ppPointer, PVOID pDetour) {
    DetourUpdateThread(GetCurrentThread());
    DetourTransactionBegin();
    DetourDetach(ppPointer, pDetour);
    DetourTransactionCommit();
}

} // namespace detour

inline namespace some_util {

BOOL WriteMemory(PVOID lpAddress, PVOID lpBuffer, DWORD nSize) {
    DWORD dwProtect;
    if (VirtualProtect(lpAddress, nSize, PAGE_EXECUTE_READWRITE, &dwProtect)) {
        memcpy(lpAddress, lpBuffer, nSize);
        VirtualProtect(lpAddress, nSize, dwProtect, &dwProtect);
        return TRUE;
    }
    return FALSE;
}

wstring GetModuleFilePath(HMODULE hModule) {
    DWORD size = MAX_PATH;
    wstring buffer;
    for (;;) {
        buffer.resize(size);
        DWORD len = GetModuleFileNameW(hModule, &buffer[0], size);
        if (len < size) {
            buffer.resize(len);
            return buffer;
        }
        size *= 2;
        if (size > 32768) {
            return L"";
        }
    }
}

PVOID SearchPattern(PVOID lpStartSearch, DWORD dwSearchLen,
                    const uint8_t *lpPattern, DWORD dwPatternLen) {
    ULONG_PTR dwStartAddr = (ULONG_PTR)lpStartSearch;
    ULONG_PTR dwEndAddr = dwStartAddr + dwSearchLen - dwPatternLen;
    while (dwStartAddr < dwEndAddr) {
        bool found = true;
        for (DWORD i = 0; i < dwPatternLen; i++) {
            uint8_t code = *(uint8_t *)(dwStartAddr + i);
            if (lpPattern[i] != 0x2A /* char '*' */ && lpPattern[i] != code) {
                found = false;
                break;
            }
        }
        if (found)
            return (PVOID)dwStartAddr;
        dwStartAddr++;
    }
    return 0;
}

const tjs_char *GetTJSString(tTJSString *s) {
    if (!s)
        return L"";
    tTJSVariantString_S *v = *(tTJSVariantString_S **)s;
    if (!v)
        return L"";
    if (v->LongString)
        return v->LongString;
    return v->ShortString;
}

wstring GetHexString(const uint8_t *ptr, size_t len) {
    static const wchar_t hex_digits[] = L"0123456789ABCDEF";
    wstring result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = ptr[i];
        result.push_back(hex_digits[byte >> 4]);
        result.push_back(hex_digits[byte & 0x0F]);
    }
    return result;
}

} // namespace some_util

inline namespace about_hash {

/*
55 8B EC 83 EC 50 FF 71 08 C7 45 ?? ?? ?? ?? ?? FF 71 04 8D 4D B0
*/
const uint8_t DIR_HASH_SIGNATURE[] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x50, 0xFF, 0x71, 0x08, 0xC7, 0x45,
    '*',  '*',  '*',  '*',  '*',  0xFF, 0x71, 0x04, 0x8D, 0x4D, 0xB0};
/*
55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ??
33 C5 89 45 FC 8B 45 08 56 8B 75 10 57
*/
const uint8_t FILE_HASH_SIGNATURE[] = {0x55, 0x8B, 0xEC, 0x81, 0xEC, '*',  '*',
                                       '*',  '*',  0xA1, '*',  '*',  '*',  '*',
                                       0x33, 0xC5, 0x89, 0x45, 0xFC, 0x8B, 0x45,
                                       0x08, 0x56, 0x8B, 0x75, 0x10, 0x57};
// Original
using tComputeHash = int(__thiscall *)(PVOID /* _this */, tTJSVariant *,
                                       tTJSString *, tTJSString *);
// Hooked
tComputeHash OriginComputeDirName;
tComputeHash OriginComputeFileName;

int __fastcall HookComputeDirName(PVOID _this /* ecx */, PVOID /* edx */,
                                  tTJSVariant *hash, tTJSString *input,
                                  tTJSString *salt) {
    int result = OriginComputeDirName(_this, hash, input, salt);

    if (has_init && hash && hash->Type() == tvtOctet) {
        tTJSVariantOctet *octet = hash->AsOctetNoAddRef();
        if (octet) {
            wstring hex = GetHexString(octet->GetData(), octet->GetLength());
            auto ret = dir_hash_set.insert(hex);
            if (ret.second) {
                wof << format(L"dir  hash: \"{}\" \"{}\" \"{}\"\n",
                              salt->c_str(), hex, input->c_str());
            }
        }
    }
    return result;
}
int __fastcall HookComputeFileName(PVOID _this /* ecx */, PVOID /* edx */,
                                   tTJSVariant *hash, tTJSString *input,
                                   tTJSString *salt) {
    int result = OriginComputeFileName(_this, hash, input, salt);
    if (has_init && hash && hash->Type() == tvtOctet) {
        tTJSVariantOctet *octet = hash->AsOctetNoAddRef();
        if (octet) {
            wstring hex = GetHexString(octet->GetData(), octet->GetLength());
            auto ret = file_hash_set.insert(hex);
            if (ret.second) {
                wof << format(L"file hash: \"{}\" \"{}\" \"{}\"\n",
                              salt->c_str(), hex, input->c_str());
            }
        }
    }
    return result;
}

bool IsArrayObject(iTJSDispatch2 *obj) {
    if (obj) {
        tTJSVariant val;
        if (TJS_SUCCEEDED(obj->ClassInstanceInfo(TJS_CII_GET, 0, &val))) {
            tTJSString classname = val;
            if (classname == L"Array") {
                return true;
            }
        }
    }
    return false;
}
tjs_int64 GetArrayLength(iTJSDispatch2 *obj) {
    tTJSVariant count;
    if (TJS_FAILED(
            obj->PropGet(TJS_MEMBERMUSTEXIST, L"count", NULL, &count, obj))) {
        return 0;
    }
    if (count.Type() != tvtInteger) {
        return 0;
    }
    return count.AsInteger();
}
void LoadArchiveIndex(tTJSString *path, tTJSVariant *index) {
    if (index->Type() != tvtObject) {
        return;
    }
    iTJSDispatch2 *dirArrayObj = index->AsObjectNoAddRef();
    if (!IsArrayObject(dirArrayObj))
        return;
    tjs_int64 dirArrayLength = GetArrayLength(dirArrayObj);
    if (dirArrayLength & 1) {
        return;
    }
    wstring archive = path->c_str();
    for (tjs_int64 i = 0; i < dirArrayLength; i += 2) {
        tTJSVariant dirHashV;

        if (TJS_FAILED(dirArrayObj->PropGetByNum(
                TJS_MEMBERMUSTEXIST, (tjs_int)i, &dirHashV, dirArrayObj))) {
            return;
        }
        if (dirHashV.Type() != tvtOctet) {
            return;
        }
        tTJSVariantOctet *dirHashOctet = dirHashV.AsOctetNoAddRef();
        wstring dir_hash =
            GetHexString(dirHashOctet->GetData(), dirHashOctet->GetLength());
        tTJSVariant entryArrayV;
        dirArrayObj->PropGetByNum(TJS_MEMBERMUSTEXIST, (tjs_int)(i + 1),
                                  &entryArrayV, dirArrayObj);
        if (entryArrayV.Type() != tvtObject) {
            return;
        }
        iTJSDispatch2 *entryArrayObj = entryArrayV.AsObjectNoAddRef();
        if (!IsArrayObject(entryArrayObj)) {
            return;
        }
        tjs_int64 entryArrayLength = GetArrayLength(entryArrayObj);
        if (entryArrayLength & 1)
            return;
        for (tjs_int64 j = 0; j < entryArrayLength; j += 2) {
            tTJSVariant nameHashV;
            entryArrayObj->PropGetByNum(TJS_MEMBERMUSTEXIST, (tjs_int)j,
                                        &nameHashV, entryArrayObj);
            if (nameHashV.Type() != tvtOctet) {
                return;
            }
            tTJSVariantOctet *nameHashOctet = nameHashV.AsOctetNoAddRef();
            wstring name_hash = GetHexString(nameHashOctet->GetData(),
                                             nameHashOctet->GetLength());

            tTJSVariant entryInfoArrayV;
            entryArrayObj->PropGetByNum(TJS_MEMBERMUSTEXIST, (tjs_int)(j + 1),
                                        &entryInfoArrayV, entryArrayObj);
            if (!IsArrayObject(entryInfoArrayV))
                return;
            iTJSDispatch2 *entryInfoArrayObj =
                entryInfoArrayV.AsObjectNoAddRef();
            if (GetArrayLength(entryInfoArrayObj) < 2)
                return;
            tTJSVariant entryId;
            entryInfoArrayObj->PropGetByNum(TJS_MEMBERMUSTEXIST, 0, &entryId,
                                            entryInfoArrayObj);

            assert(entryId.Type() == tvtInteger);
            uint64_t ordinal = entryId.AsInteger();
            tTJSVariant entryKey;
            entryInfoArrayObj->PropGetByNum(TJS_MEMBERMUSTEXIST, 1, &entryKey,
                                            entryInfoArrayObj);
            assert(entryKey.Type() == tvtInteger);
            uint64_t key = entryKey.AsInteger();
            wof2 << format(L"{} {} {:016X} {:06}\n", dir_hash, name_hash, key,
                           ordinal);
        }
    }
    return;
}

/*
55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 5C A1 ?? ?? ?? ?? 33
C5 89 45 F0 53 56 57 50 8D 45 F4 64 A3 00 00 00 00 89 4D B8 8B 45 0C 8B 75 08
89 45 BC C7 45
*/
const uint8_t PARSE_INDEX[] = {
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, '*',  '*',  '*',  '*',  0x64, 0xA1,
    0x00, 0x00, 0x00, 0x00, 0x50, 0x83, 0xEC, 0x5C, 0xA1, '*',  '*',  '*',
    '*',  0x33, 0xC5, 0x89, 0x45, 0xF0, 0x53, 0x56, 0x57, 0x50, 0x8D, 0x45,
    0xF4, 0x64, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x89, 0x4D, 0xB8, 0x8B, 0x45,
    0x0C, 0x8B, 0x75, 0x08, 0x89, 0x45, 0xBC, 0xC7, 0x45};
// Original
using tOriginParseIndex = tTJSVariant *(__fastcall *)(PVOID, PVOID, PVOID,
                                                      tTJSString *);
tOriginParseIndex OriginParseIndex;
// Hooked
tTJSVariant *__fastcall HookParseIndex(PVOID a1, PVOID a2, PVOID a3,
                                       tTJSString *a4) {
    // Detach(FORDETOUR(OriginParseIndex, HookParseIndex));
    const tjs_char *path = GetTJSString(a4);
    const tjs_char *name = wcsrchr(path, L'/');
    name = name ? name + 1 : path;
    wof << format(L"parse archive: {}\n", name);
    wof2 << format(L"parse archive: {}\n", name);
    tTJSVariant *index = OriginParseIndex(a1, a2, a3, a4);
    if (load_index && index) {
        LoadArchiveIndex(a4, index);
    }
    return index;
}

} // namespace about_hash

inline namespace about_key {

void WriteOrder(const uint8_t *ptr, size_t len, wstring tips) {
    wof << tips;
    for (size_t i = 0; i < len; ++i) {
        wof << ptr[i] << L',';
    }
    wof << L'\n';
}

struct Info {
    uint32_t unknown;
    uint32_t unknown2;
    uint64_t filter_key;
    uint32_t mask;
    uint32_t pos;
    uint32_t random_type;
    uint32_t unknown3;
    uint32_t cxdec_table[0x400];
    uint32_t unknown4[0x400];
    uint32_t unknown5[0x400];
    uint8_t order_8[8];
    uint8_t order_6[6];
    uint8_t order_3[3];
};
static_assert(sizeof Info == 0x3038, "o.O?");
/*
55 8B EC 83 EC 34 A1 ?? ?? ?? ?? 33 C5 89 45 FC 80 7D 10 00 53 56 8B 75 08 57
8B 7D 0C 8B D9 75 06 33 73 08 33 7B 0C 8B C7 F7 D0
*/
const uint8_t CREATEFILTER[] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x34, 0xA1, '*',  '*',  '*',  '*',
    0x33, 0xC5, 0x89, 0x45, 0xFC, 0x80, 0x7D, 0x10, 0x00, 0x53, 0x56,
    0x8B, 0x75, 0x08, 0x57, 0x8B, 0x7D, 0x0C, 0x8B, 0xD9, 0x75, 0x06,
    0x33, 0x73, 0x08, 0x33, 0x7B, 0x0C, 0x8B, 0xC7, 0xF7, 0xD0};
// Original
using tOriginCreateFilter = PVOID(__fastcall *)(PVOID, PVOID, ULONGLONG, BYTE);
tOriginCreateFilter OriginCreateFilter;
// Hooked
PVOID __fastcall HookCreateFilter(Info *info, PVOID a2, ULONGLONG a3, BYTE a4) {

#ifdef _DEBUG
    wof << format(L"unknown: 0x{:X} --- 0x{:X} ---0x{:X}\n", info->unknown,
                  info->unknown2, info->unknown3);
#endif
    wof << format(
        L"filter key: 0x{:X}\nmask: 0x{:X}\npos: 0x{:X}\nrandom type: {:X}\n",
        info->filter_key, info->mask, info->pos, info->random_type);
    WriteOrder(info->order_8, 8, L"order 8: ");
    WriteOrder(info->order_6, 6, L"order 6: ");
    WriteOrder(info->order_3, 3, L"order 3: ");
    PVOID result = OriginCreateFilter(info, a2, a3, a4);
    Detach(FORDETOUR(OriginCreateFilter, HookCreateFilter));
    return result;
}

void PrintIndexKey(const uint8_t *key, const uint8_t *nonce) {
    wof << format(L"index key: {}\nindex nonce: {}\n", GetHexString(key, 32),
                  GetHexString(nonce, 16));
}
/*
E8 ?? ?? ?? ?? 83 C4 1C 33 C0 8D A4 24 00 00 00 00 C6 44 05 CC 00 40 83 F8 20
*/
const uint8_t DECINDEX[] = {0xE8, '*',  '*',  '*',  '*',  0x83, 0xC4,
                            0x1C, 0x33, 0xC0, 0x8D, 0xA4, 0x24, 0x00,
                            0x00, 0x00, 0x00, 0xC6, 0x44, 0x05, 0xCC,
                            0x00, 0x40, 0x83, 0xF8, 0x20};
// Original
PVOID OriginDecIndex;
// Hooked
_declspec(naked) void HookDecIndex() {
    // Detach(FORDETOUR(OriginDecIndex, HookDecIndex));
    _asm
    {
        pushad
        mov eax, [esp+0x2C] // a4 0x20+0xC
        mov edx, [esp+0x30] // a5 0x20+0x10
        push edx
        push eax
        call PrintIndexKey
        add esp, 8
        popad
        jmp OriginDecIndex;
    }
}
} // namespace about_key

inline namespace about_v2link {

using tTVPV2LinkProc = HRESULT(__stdcall *)(iTVPFunctionExporter *);
using tTVPV2UnlinkProc = HRESULT(__stdcall *)();
iTVPFunctionExporter *TVPFunctionExporter;
// Original
tTVPV2LinkProc OriginV2Link;
// Hooked
HRESULT __stdcall HookV2Link(iTVPFunctionExporter *exporter) {

    TVPFunctionExporter = exporter;

    TVPInitImportStub(exporter);
    has_init = true;
    PVOID TVPCreateIStream = TVPGetImportFuncPtr(
        "IStream * ::TVPCreateIStream(const ttstr &,tjs_uint32)");

    wof << format(
        L"iTVPFunctionExporter at: 0x{:08X}\nTVPCreateIStream at: 0x{:08X}\n",
        (uint32_t)exporter, (uint32_t)TVPCreateIStream);

    HRESULT result = OriginV2Link(exporter);
    Detach(FORDETOUR(OriginV2Link, HookV2Link));

    return result;
}
} // namespace about_v2link

inline namespace about_stream {

void ProcessStream(tTJSBinaryStream *stream, ttstr *name, tjs_uint32 flags) {
    if (stream && flags == TJS_BS_READ) {
        const tjs_char *psz = GetTJSString(name);
        wstring path = psz;
        size_t pos = path.find_last_of(L">");
        if (pos == -1) {
            wof << format(L"ProcessStream: {}\n", path);
        } else {
            wof << format(L"ProcessStream: {} \n", path.substr(0, pos + 1));
        }
    }
}

/*
55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC 5C 53 56 57 A1 ??
?? ?? ?? 33 C5 50 8D 45 F4 64 A3 ?? ?? ?? ?? 89 65 F0 89 4D EC C7 45 ?? ??
?? ?? ?? E8 ?? ?? ?? ?? 8B 4D F4 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B E5 5D
C3
*/
const uint8_t KRKRZ_TVPCREATESTREAM[] = {
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, '*',  '*',  '*',  '*',  0x64, 0xA1, '*',
    '*',  '*',  '*',  0x50, 0x83, 0xEC, 0x5C, 0x53, 0x56, 0x57, 0xA1, '*',  '*',
    '*',  '*',  0x33, 0xC5, 0x50, 0x8D, 0x45, 0xF4, 0x64, 0xA3, '*',  '*',  '*',
    '*',  0x89, 0x65, 0xF0, 0x89, 0x4D, 0xEC, 0xC7, 0x45, '*',  '*',  '*',  '*',
    '*',  0xE8, '*',  '*',  '*',  '*',  0x8B, 0x4D, 0xF4, 0x64, 0x89, 0x0D, '*',
    '*',  '*',  '*',  0x59, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D, 0xC3};
// Original
using tKrkrzTVPCreateStreamProc = tTJSBinaryStream *(__fastcall *)(ttstr *,
                                                                   tjs_uint32);
tKrkrzTVPCreateStreamProc OriginKrkrzTVPCreateStream;
// Hooked
tTJSBinaryStream *__fastcall HookKrkrzTVPCreateStream(ttstr *name,
                                                      tjs_uint32 flags) {

    tTJSBinaryStream *stream = OriginKrkrzTVPCreateStream(name, flags);
    ProcessStream(stream, name, flags);
    return stream;
}

} // namespace about_stream

// Original
auto *OriginGetProcAddress = GetProcAddress;
// Hooked
FARPROC WINAPI HookGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    FARPROC result = OriginGetProcAddress(hModule, lpProcName);
    if (result && HIWORD(lpProcName) != 0 &&
        strcmp(lpProcName, "V2Link") == 0) {
        Detach(FORDETOUR(OriginGetProcAddress, HookGetProcAddress));

#ifdef _DEBUG
        MessageBoxW(0, L"For Debug, For Attach.", L"useless", MB_OK);
#endif
        OriginV2Link = (tTVPV2LinkProc)result;
        Attach(FORDETOUR(OriginV2Link, HookV2Link));

        wstring krkr_dll_path = GetModuleFilePath(hModule);

        wof << format(L"krkr dll path: \"{}\"\nkrkr dll base: 0x{:08X}\nV2Link "
                      L"at 0x{:08X}\n",
                      krkr_dll_path, (uint32_t)hModule, (uint32_t)result);

        if (krkr_dll_path.find(L"krkr_") != -1) {

            DWORD size =
                ((PIMAGE_NT_HEADERS)((uint32_t)hModule +
                                     ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))
                    ->OptionalHeader.SizeOfImage;
            int need = MessageBoxW(0, L"do you need bypass detect?", L"tips",
                                   MB_YESNO | MB_ICONQUESTION);
            if (need == IDYES) {
#ifdef _DEBUG
                // 55 8B EC 83 7D 08 00 53 56 8B F1
                const uint8_t CHECKSIGNATURE[] = {0x55, 0x8B, 0xEC, 0x83,
                                                  0x7D, 0x08, 0x00, 0x53,
                                                  0x56, 0x8B, 0xF1};
                PVOID signature_pos = SearchPattern(
                    hModule, size, CHECKSIGNATURE, sizeof(CHECKSIGNATURE));
                if (signature_pos) {
                    // B0 01    | mov al,1
                    // C2 0800  | ret 8
                    BYTE patch_data[] = {0xB0, 0x01, 0xC2, 0x08, 0x00};
                    WriteMemory(signature_pos, patch_data, sizeof(patch_data));
                }
#else
                // 55 8B EC 8B 4D ?? 85 C9 74 ?? FF 75
                const uint8_t CHECKSIGNATURE[] = {0x55, 0x8B, 0xEC, 0x8B,
                                                  0x4D, '*',  0x85, 0xC9,
                                                  0x74, '*',  0xFF, 0x75};
                uint64_t signature_pos = (uint64_t)SearchPattern(
                    hModule, size, CHECKSIGNATURE, sizeof(CHECKSIGNATURE));
                if (signature_pos) {
                    // EB 0F | jmp
                    BYTE patch_data[] = {0xEB, 0x0F};
                    WriteMemory(PVOID(signature_pos + 8), patch_data,
                                sizeof(patch_data));
                }
#endif
            }

            if (load_hash) {
                OriginComputeDirName = (tComputeHash)SearchPattern(
                    hModule, size, DIR_HASH_SIGNATURE,
                    sizeof(DIR_HASH_SIGNATURE));
                if (OriginComputeDirName) {
                    Attach(FORDETOUR(OriginComputeDirName, HookComputeDirName));
                }
                OriginComputeFileName = (tComputeHash)SearchPattern(
                    hModule, size, FILE_HASH_SIGNATURE,
                    sizeof(FILE_HASH_SIGNATURE));
                if (OriginComputeFileName) {
                    Attach(
                        FORDETOUR(OriginComputeFileName, HookComputeFileName));
                }
            }

            OriginParseIndex = (tOriginParseIndex)SearchPattern(
                hModule, size, PARSE_INDEX, sizeof(PARSE_INDEX));
            if (OriginParseIndex) {
                Attach(FORDETOUR(OriginParseIndex, HookParseIndex));
            }

            OriginDecIndex =
                SearchPattern(hModule, size, DECINDEX, sizeof(DECINDEX));
            if (OriginDecIndex) {
                Attach(FORDETOUR(OriginDecIndex, HookDecIndex));
            }

            OriginCreateFilter = (tOriginCreateFilter)SearchPattern(
                hModule, size, CREATEFILTER, sizeof(CREATEFILTER));
            if (OriginCreateFilter) {
                Attach(FORDETOUR(OriginCreateFilter, HookCreateFilter));
            }
        }
    }
    return result;
}

} // namespace

void StartStartStart() {
    wstring rougee = GetModuleFilePath(dll);
    wstring dir = rougee.substr(0, rougee.find_last_of(L"\\"));

    log_file = dir + L"\\rougee.txt";
    wof.open(log_file, 0x20); // std::ios::binary
    wof.imbue(std::locale("Japanese_Japan.932"));

    log_file2 = dir + L"\\index.txt";
    wof2.open(log_file2, 0x20); // std::ios::binary
    wof2.imbue(std::locale("Japanese_Japan.932"));
    wof2 << L"dir_hash(hex) , file_hash(hex) , key(hex) , ordinal(decimal)\n";

    DWORD size = ((PIMAGE_NT_HEADERS)((ULONG_PTR)exe +
                                      ((PIMAGE_DOS_HEADER)exe)->e_lfanew))
                     ->OptionalHeader.SizeOfImage;
    if (false) {
        PVOID TVPCreateStream = SearchPattern(exe, size, KRKRZ_TVPCREATESTREAM,
                                              sizeof(KRKRZ_TVPCREATESTREAM));
        if (TVPCreateStream) {
            OriginKrkrzTVPCreateStream =
                (tKrkrzTVPCreateStreamProc)TVPCreateStream;
            Attach(FORDETOUR(OriginKrkrzTVPCreateStream,
                             HookKrkrzTVPCreateStream));
            wof << L"Krkrz .\n";
        }
    }

#ifdef _DEBUG
    AllocConsole();
    FILE *fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
// echo | gcc -E -dM - | grep __VERSION__
// echo | clang -E -dM -
#if defined _MSC_VER
    printf_s("%d", _MSC_FULL_VER);
#elif defined __GNUC__
    printf_s("%d", __VERSION__);
#elif defined __clang__
    printf_s("%d", __clang_version__);
#else
    printf_s("rougee ! ");
#endif
    std::time_t t = std::time(nullptr);
    std::tm tm;
    localtime_s(&tm, &t);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    printf_s("\nthe current local time is:%s\n", buf);
#endif

    wof << format(L"log file path: \"{}\"\n", log_file);
    Attach(FORDETOUR(OriginGetProcAddress, HookGetProcAddress));
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH: {
        exe = GetModuleHandle(0);
        dll = hModule;
        StartStartStart();
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH: {
        wof.flush();
        wof.close();
        wof2.flush();
        wof2.close();
        break;
    }
    }
    return TRUE;
}

#ifndef ROUGEE
#define ROUGEE void
#endif
constexpr size_t operator"" _rougee(const char *, size_t rougee) {
    return rougee;
}
//  necessary
extern "C" __declspec(dllexport) ROUGEE Rougee() {}
