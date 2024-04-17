#pragma once

#define _CRT_SECURE_NO_WARNINGS

#define _ATL_XP_TARGETING

#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>

#include <ntdll.h>
#include <atlbase.h>

#include "shared.h"

#pragma comment(lib, "shlwapi.lib")

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _PEB_LDR_DATA64
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList; 			  // Points to the loaded modules (main EXE usually)
    LIST_ENTRY64 InMemoryOrderModuleList;   		  // Points to all modules (EXE and all DLLs)
    LIST_ENTRY64 InInitializationOrderModuleList;
    PVOID64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

struct LDR_MODULE64
{
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    PVOID64 DllBase;
    PVOID64 DllEntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY64 HashTableEntry;
};

typedef struct _PEB64
{
    BOOLEAN InheritedAddressSpace;  	// These four fields cannot change unless the
    BOOLEAN ReadImageFileExecOptions;   //
    BOOLEAN BeingDebugged;  			//
    BOOLEAN SpareBool;  				//
    PVOID64 Mutant; 					 // INITIAL_PEB structure is also updated.

    PVOID64 ImageBaseAddress;
    PVOID64 Ldr;
    PVOID64 ProcessParameters;
} PEB64, * PPEB64;


// end_ntddk end_ntifs 
typedef struct _PROCESS_BASIC_INFORMATION64
{
    PVOID64 Reserved1;
    PVOID64 PebBaseAddress;
    PVOID64 Reserved2[2];
    PVOID64 UniqueProcessId;
    PVOID64 Reserved3;
} PROCESS_BASIC_INFORMATION64, * PPROCESS_BASIC_INFORMATION64;

static DWORD_PTR FindProcessModule(HANDLE hProcess, LPCWSTR lpModuleName /*= NULL*/ OPTIONAL, HMODULE hModule /*= NULL*/ OPTIONAL, OUT LPWSTR lpModuleFullPath /*= NULL*/ OPTIONAL, DWORD nModuleFullPathLen /*= 0*/ OPTIONAL)
{
    ATLASSERT(hProcess);
    ATLASSERT(lpModuleName || hModule);
    if (!hProcess || (!lpModuleName && !hModule))
    {
        return NULL;
    }

    DWORD dwProcessId = GetProcessId(hProcess);

    DWORD_PTR dwResult = 0;

    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32W me32 =
    {
        0
    };

    if (lpModuleFullPath && nModuleFullPathLen > 0)
    {
        lpModuleFullPath[0] = 0;
    }


    // Take a snapshot of all modules in the specified process.
    //https://github.com/baldurk/renderdoc/blob/7ef73f92ef19d3dfc325a52aba6912386433bec9/renderdoc/os/win32/win32_process.cpp

    // up to 10 retries
    for (int i = 0; i < 10; i++)
    {
        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessId);

        if (hModuleSnap == INVALID_HANDLE_VALUE)
        {
            DWORD err = GetLastError();

            ATLTRACE(_T("CreateToolhelp32Snapshot(%u) -> 0x%08x\r\n"), dwProcessId, err);

            // retry if error is ERROR_BAD_LENGTH
            if (err == ERROR_BAD_LENGTH)
            {
                Sleep(1);
                continue;
            }
        }

        // didn't retry, or succeeded
        break;
    }

    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        ATLTRACE(_T("Couldn't create toolhelp dump of modules in process %u\r\n"), dwProcessId);
        return FALSE;
    }

    // Fill the size of the structure before using it.

    me32.dwSize = sizeof(MODULEENTRY32W);

    // Walk the module list of the process, and find the module of
    // interest. Then copy the information to the buffer pointed
    // to by lpMe32 so that it can be returned to the caller.

    BOOL bFindByName = lpModuleName != NULL;
    BOOL bCompareFullPath = FALSE;
    if (bFindByName)
    {
        bCompareFullPath = !PathIsRelativeW(lpModuleName);
    }

    if (Module32FirstW(hModuleSnap, &me32))
    {
        do
        {
            if (bFindByName)
            {
                LPCWSTR pszName = bCompareFullPath ? me32.szExePath : me32.szModule;
                if (!_wcsicmp(pszName, lpModuleName))
                {
                    DWORD len = 0;
                    if (lpModuleFullPath && nModuleFullPathLen > 0)
                    {
                        len = (DWORD)__min(nModuleFullPathLen, wcslen(me32.szExePath));
                        memcpy(lpModuleFullPath, me32.szExePath, len * sizeof(WCHAR));
                        if (len < nModuleFullPathLen) lpModuleFullPath[len] = 0;
                    }
                    dwResult = (DWORD_PTR)me32.hModule;
                    break;
                }
            }
            else
            {
                if (me32.hModule == hModule)
                {
                    DWORD len = 0;
                    if (lpModuleFullPath && nModuleFullPathLen > 0)
                    {
                        len = (DWORD)__min(nModuleFullPathLen, wcslen(me32.szExePath));
                        memcpy(lpModuleFullPath, me32.szExePath, len * sizeof(WCHAR));
                        if (len < nModuleFullPathLen) lpModuleFullPath[len] = 0;
                    }
                    dwResult = len;
                    break;
                }
            }
        } while (Module32NextW(hModuleSnap, &me32));
    }
    else
    {
        DWORD dwErrorCode = GetLastError();
        ATLTRACE(_T("Module32First failed. Error: %d\r\n"), dwErrorCode);
    }

    // Do not forget to clean up the snapshot object.

    if (hModuleSnap)
    {
        CloseHandle(hModuleSnap);
        hModuleSnap = NULL;
    }


    return dwResult;
}

static HMODULE GetProcessModuleHandle(HANDLE hProcess, LPCWSTR lpModuleName)
{
    return (HMODULE)FindProcessModule(hProcess, lpModuleName, NULL, NULL, 0);
}

static DWORD GetProcessModuleFileName(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    return (DWORD)FindProcessModule(hProcess, NULL, hModule, lpFilename, nSize);
}

extern NTSTATUS(NTAPI* _NtWow64ReadVirtualMemory64)(IN HANDLE ProcessHandle, IN PVOID64 BaseAddress, OUT PVOID Buffer, IN UINT64 NumberOfBytesToRead, OUT PUINT64 NumberOfBytesReaded);
extern NTSTATUS(NTAPI* _NtReadVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN SIZE_T BufferSize, OUT PSIZE_T NumberOfBytesRead OPTIONAL);
extern NTSTATUS(NTAPI* _NtQueryInformationProcess64)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);

static NTSTATUS NTAPI NtReadVirtualMemory64(IN HANDLE ProcessHandle, IN PVOID64 BaseAddress, OUT PVOID Buffer, IN UINT64 NumberOfBytesToRead, OUT PUINT64 NumberOfBytesReaded)
{
    if (_NtWow64ReadVirtualMemory64)
    {
        return _NtWow64ReadVirtualMemory64(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
    }
    else
    {
        if (NumberOfBytesReaded)
        {
            *NumberOfBytesReaded = 0;
        }
        return _NtReadVirtualMemory(ProcessHandle, (PVOID)(ULONG_PTR)(DWORD64)BaseAddress, Buffer, (SIZE_T)NumberOfBytesToRead, (PSIZE_T)NumberOfBytesReaded);
    }
}

static DWORD64 FindProcessModule64(HANDLE hProcess, LPCWSTR lpModuleName /*= NULL*/ OPTIONAL, PVOID64 hModule /*= NULL*/ OPTIONAL, OUT LPWSTR lpModuleFullPath /*= NULL*/ OPTIONAL, DWORD nModuleFullPathLen /*= 0*/ OPTIONAL)
{
    ATLASSERT(hProcess);
    ATLASSERT(lpModuleName || hModule);
    if (!hProcess || (!lpModuleName && !hModule))
    {
        return NULL;
    }

    if (_NtQueryInformationProcess64 == NULL || (_NtWow64ReadVirtualMemory64 == NULL && _NtReadVirtualMemory == NULL))
    {
        HMODULE hmod_ntdll = GetModuleHandle(_T("ntdll.dll"));
        if (hmod_ntdll)
        {
            BOOL Wow64Process = FALSE;
            IsWow64Process(GetCurrentProcess(), &Wow64Process);
            if (Wow64Process)
            {
                _NtQueryInformationProcess64 = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
                    GetProcAddress(hmod_ntdll, "NtWow64QueryInformationProcess64");
                _NtWow64ReadVirtualMemory64 = (NTSTATUS(NTAPI*)(HANDLE, PVOID64, PVOID, UINT64, PUINT64))
                    GetProcAddress(hmod_ntdll, "NtWow64ReadVirtualMemory64");
                //NtWow64ReadVirtualMemory64 does not support the process pseudo handle returned by GetCurrentProcess()
                ATLASSERT(hProcess != GetCurrentProcess());
            }
            else
            {
                _NtQueryInformationProcess64 = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
                    GetProcAddress(hmod_ntdll, "NtQueryInformationProcess");
                _NtReadVirtualMemory = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))
                    GetProcAddress(hmod_ntdll, "NtReadVirtualMemory");
            }
        }
    }

    if (_NtQueryInformationProcess64 == NULL || (_NtWow64ReadVirtualMemory64 == NULL && _NtReadVirtualMemory == NULL))
    {
        ATLASSERT(_NtQueryInformationProcess64 && (_NtWow64ReadVirtualMemory64 || _NtReadVirtualMemory));
        return NULL;
    }

    BOOL bFindByName = lpModuleName != NULL;
    BOOL bCompareFullPath = FALSE;
    if (bFindByName)
    {
        bCompareFullPath = !PathIsRelativeW(lpModuleName);
    }

    PROCESS_BASIC_INFORMATION64 pbi64;

    DWORD dwSize;
    UINT64 size;
    NTSTATUS iReturn;
    PVOID64 pAddrPEB = NULL;

    if (lpModuleFullPath && nModuleFullPathLen > 0)
    {
        lpModuleFullPath[0] = 0;
    }


    iReturn = _NtQueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi64, sizeof(pbi64), &dwSize);
    pAddrPEB = pbi64.PebBaseAddress;

    // NtQueryInformationProcess returns a negative value if it fails
    if (iReturn >= 0)
    {
        // 1. Find the Process Environment Block
        PEB64 PEB;
        size = dwSize;
        if (ERROR_SUCCESS != NtReadVirtualMemory64(hProcess, pAddrPEB, &PEB, sizeof(PEB), &size))
        {
            // Call GetLastError() if you need to know why
            return NULL;
        }

        ULONG64 dwBytesRead;
        PEB_LDR_DATA64 Ldr;
        if (ERROR_SUCCESS != NtReadVirtualMemory64(hProcess, PEB.Ldr, (LPVOID)&Ldr, sizeof(Ldr), &dwBytesRead))
        {
            ATLTRACE(_T("NtReadVirtualMemory error %u\n"), GetLastError());
            return NULL;
        }


        LDR_MODULE64 module_info =
        {
            0
        };
        /*
        Get address of first entry
        nt!_PEB_LDR_DATA
        ...
        +0x00c InLoadOrderModuleList : _LIST_ENTRY
        ...
        */
        PVOID InLoadOrderModuleList_Offset = &((PPEB_LDR_DATA64)NULL)->InLoadOrderModuleList;
        PVOID64 pStartModuleInfo = (PVOID64)((__int64)PEB.Ldr + (__int64)InLoadOrderModuleList_Offset);
        PVOID64 pNextModuleInfo = (PVOID64)Ldr.InLoadOrderModuleList.Flink;
        WCHAR wFullDllName[MAX_PATH];

        //Get info for each loaded DLL
        do
        {
            //Get LDR_MODULE (LDR_DATA_TABLE_ENTRY) structure
            iReturn = NtReadVirtualMemory64(hProcess, pNextModuleInfo, &module_info, sizeof(LDR_MODULE64), &dwBytesRead);
            if (ERROR_SUCCESS != iReturn)
            {
                ATLTRACE(_T("NtReadVirtualMemory error %u\n"), iReturn);
                return NULL;
            }

            wFullDllName[0] = 0;
            //Read string with Dll full name
            iReturn = NtReadVirtualMemory64(hProcess, (PVOID64)module_info.FullDllName.Buffer, (LPVOID)&wFullDllName, module_info.FullDllName.MaximumLength, &dwBytesRead);
            if (ERROR_SUCCESS != iReturn)
            {
                ATLTRACE(_T("NtReadVirtualMemory error %u\n"), iReturn);
                return NULL;
            }
            //wprintf(L"0x%I64x %s\n", module_info.DllBase, wFullDllName);

            if (bFindByName)
            {
                LPCWSTR pszName = bCompareFullPath ? wFullDllName : PathFindFileNameW(wFullDllName);
                if (!_wcsicmp(pszName, lpModuleName))
                {
                    DWORD len = 0;
                    if (lpModuleFullPath && nModuleFullPathLen > 0)
                    {
                        len = (DWORD)__min(nModuleFullPathLen, wcslen(wFullDllName));
                        memcpy(lpModuleFullPath, wFullDllName, len * sizeof(WCHAR));
                        if (len < nModuleFullPathLen) lpModuleFullPath[len] = 0;
                    }
                    return (DWORD64)module_info.DllBase;
                }
            }
            else
            {
                if (module_info.DllBase == hModule)
                {
                    DWORD len = 0;
                    if (lpModuleFullPath && nModuleFullPathLen > 0)
                    {
                        len = (DWORD)__min(nModuleFullPathLen, wcslen(wFullDllName));
                        memcpy(lpModuleFullPath, wFullDllName, len * sizeof(WCHAR));
                        if (len < nModuleFullPathLen) lpModuleFullPath[len] = 0;
                    }
                    return len;
                }
            }

            pNextModuleInfo = (PVOID64)module_info.InLoadOrderModuleList.Flink;
        } while (pNextModuleInfo != pStartModuleInfo);
    }

    return NULL;
}

static DWORD64 GetProcessModuleHandle64(HANDLE hProcess, LPCWSTR lpModuleName)
{
    return FindProcessModule64(hProcess, lpModuleName, NULL, NULL, 0);
}

static DWORD64 GetProcessModuleFileName64(HANDLE hProcess, PVOID64 hModule, LPWSTR lpFilename, DWORD nSize)
{
    return FindProcessModule64(hProcess, NULL, hModule, lpFilename, nSize);
}

template<typename IMAGE_NT_HEADERS_T>
DWORD64 GetProcAddressByImageExportDirectoryT(HANDLE hProcess, DWORD64 hModule, LPCSTR lpProcName)
{
    ATLASSERT(hProcess);
    ATLASSERT(hModule);
    ATLASSERT(lpProcName);
    if (!hProcess || !hModule || !lpProcName)
    {
        return NULL;
    }

    if (_NtWow64ReadVirtualMemory64 == NULL && _NtReadVirtualMemory == NULL)
    {
        HMODULE hmod_ntdll = GetModuleHandle(_T("ntdll.dll"));
        if (hmod_ntdll)
        {
            BOOL Wow64Process = FALSE;
            IsWow64Process(GetCurrentProcess(), &Wow64Process);
            if (Wow64Process)
            {
                _NtWow64ReadVirtualMemory64 = (NTSTATUS(NTAPI*)(HANDLE, PVOID64, PVOID, UINT64, PUINT64))
                    GetProcAddress(hmod_ntdll, "NtWow64ReadVirtualMemory64");
                //NtWow64ReadVirtualMemory64 does not support the process pseudo handle returned by GetCurrentProcess()
                ATLASSERT(hProcess != GetCurrentProcess());
            }
            else
            {
                _NtReadVirtualMemory = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))
                    GetProcAddress(hmod_ntdll, "NtReadVirtualMemory");
            }
        }
    }

    if (_NtWow64ReadVirtualMemory64 == NULL && _NtReadVirtualMemory == NULL)
    {
        ATLASSERT(_NtWow64ReadVirtualMemory64 || _NtReadVirtualMemory);
        return NULL;
    }

    DWORD* AddressOfNames = NULL;
    char* strFunctionBuffer = NULL;
    UINT64 read_len;
#undef READ_MEM
#define READ_MEM(addr, buf, size) if(!NT_SUCCESS(NtReadVirtualMemory64(hProcess, (PVOID64)(addr), buf, size, &read_len))) goto __clean__

    DWORD64 pRet = NULL;
    PIMAGE_DOS_HEADER pImageDosHeader = NULL;
    IMAGE_NT_HEADERS_T* pImageNtHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

    IMAGE_DOS_HEADER ImageDosHeader;
    READ_MEM(hModule, &ImageDosHeader, sizeof(ImageDosHeader));
    pImageDosHeader = &ImageDosHeader;
    IMAGE_NT_HEADERS_T ImageNtHeader;
    READ_MEM(hModule + pImageDosHeader->e_lfanew, &ImageNtHeader, sizeof(ImageNtHeader));
    pImageNtHeader = &ImageNtHeader;
    IMAGE_EXPORT_DIRECTORY ImageExportDirectory;
    READ_MEM(hModule + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &ImageExportDirectory, sizeof(ImageExportDirectory));
    pImageExportDirectory = &ImageExportDirectory;


    {
        DWORD dwExportRVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD dwExportSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        DWORD64 pAddressOfFunction = pImageExportDirectory->AddressOfFunctions + hModule;
        DWORD dwBase = (pImageExportDirectory->Base);

        // This is to check in what way (function name or function number) to check the function address
        DWORD dwName = (DWORD)(DWORD_PTR)lpProcName;
        if (IS_INTRESOURCE(dwName))// This is to look up the function address by means of ordinal number  
        {
            // (dwName & 0xFFFF0000) == 0  
            // Get the ordinal of the function ------>>>>>>>>>>>>>   IMAGE_ORDINAL(dwName)  
            // #define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL32(Ordinal)  
            // #define IMAGE_ORDINAL32(Ordinal)        (Ordinal & 0xffff)  
            if (dwName < dwBase || dwName > dwBase + pImageExportDirectory->NumberOfFunctions - 1)
            {
                return NULL;
            }
            DWORD dwRVA;
            READ_MEM(pAddressOfFunction + (DWORD64)(dwName - dwBase) * sizeof(DWORD), &dwRVA, sizeof(dwRVA));
            pRet = dwRVA + hModule;

            goto __clean__;
        }

        DWORD dwNumberOfNames = pImageExportDirectory->NumberOfNames;
        SIZE_T AddressOfNamesBufferLen = dwNumberOfNames * sizeof(DWORD);
        AddressOfNames = (DWORD*)_malloca(AddressOfNamesBufferLen);
        if (AddressOfNames == NULL)
        {
            goto __clean__;
        }
        READ_MEM(pImageExportDirectory->AddressOfNames + hModule, AddressOfNames, AddressOfNamesBufferLen);
        DWORD* pAddressOfNames = AddressOfNames;

        SIZE_T strFunctionBufferLen = strlen(lpProcName) + 1;
        strFunctionBuffer = (char*)_malloca(strFunctionBufferLen);
        if (strFunctionBuffer == NULL)
        {
            goto __clean__;
        }

        for (DWORD i = 0; i < dwNumberOfNames; i++)
        {
            READ_MEM(pAddressOfNames[i] + hModule, strFunctionBuffer, strFunctionBufferLen);
            char* strFunction = strFunctionBuffer;
            if (strcmp(strFunction, lpProcName) == 0)
            {
                DWORD64 pAddressOfNameOrdinals = pImageExportDirectory->AddressOfNameOrdinals + hModule;

                WORD NameOrdinal;
                READ_MEM(pAddressOfNameOrdinals + (DWORD64)i * sizeof(WORD), &NameOrdinal, sizeof(NameOrdinal));

                DWORD dwRVA;
                READ_MEM(pAddressOfFunction + (DWORD64)NameOrdinal * sizeof(DWORD), &dwRVA, sizeof(dwRVA));

                pRet = dwRVA + hModule;
                // Judging whether the obtained address is out of bounds 
                if (pRet < dwExportRVA + hModule || pRet > dwExportRVA + hModule + dwExportSize)
                {
                    goto __clean__;
                }

                char pTempDll[100];
                pTempDll[0] = 0;
                char pTempFuction[100];
                pTempFuction[0] = 0;
                READ_MEM(pRet, pTempDll, _countof(pTempDll));
                pTempDll[_countof(pTempDll) - 1] = 0;
                char* p = strchr(pTempDll, '.');
                if (!p)
                {
                    goto __clean__;
                }
                // *p = 0; The original 
                *p = '\0'; // The purpose is to truncate the string and replace '.' with 0, namely '\0'
                strncpy(pTempFuction, p + 1, _countof(pTempFuction));
                char dot_dll_Str[] = { '.', 'd', 'l', 'l', 0 };
                strncat(pTempDll, dot_dll_Str, __min(_countof(dot_dll_Str), (_countof(pTempDll) - 1) - strlen(pTempDll)));
                pTempDll[_countof(pTempDll) - 1] = 0;
                DWORD64 h = NULL;
                if (sizeof(IMAGE_NT_HEADERS_T) == sizeof(IMAGE_NT_HEADERS64))
                {
                    h = GetProcessModuleHandle64(hProcess, CA2W(pTempDll));
                }
                else if (sizeof(IMAGE_NT_HEADERS_T) == sizeof(IMAGE_NT_HEADERS32))
                {
                    h = (DWORD64)GetProcessModuleHandle(hProcess, CA2W(pTempDll));
                }
                else
                {
                    ATLASSERT(FALSE);
                }
                if (h == NULL)
                {
                    goto __clean__;
                }
                return GetProcAddressByImageExportDirectoryT<IMAGE_NT_HEADERS_T>(hProcess, h, pTempFuction);
            }
        }
    }


__clean__:
    if (AddressOfNames)
    {
        _freea(AddressOfNames);
        AddressOfNames = NULL;
    }
    if (strFunctionBuffer)
    {
        _freea(strFunctionBuffer);
        strFunctionBuffer = NULL;
    }
#undef READ_MEM
    return pRet;
}

static PVOID MapImage(LPCTSTR Path)
{
    LPVOID pMapView = NULL;
    HANDLE hMapping;
    HANDLE hFile;

    hFile = CreateFile(Path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        hMapping = CreateFileMapping(hFile, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
        if (hMapping != NULL)
        {
            pMapView = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

            CloseHandle(hMapping);
        }

        CloseHandle(hFile);
    }

    return pMapView;
}

#define UnmapImage(pMapView)  { if(pMapView) { UnmapViewOfFile (pMapView); (pMapView) = NULL; } }

__if_not_exists(GetWow64ExtFileName)
{
    static LPCTSTR GetWow64ExtFileName(USHORT usProcessorArchitecture, TCHAR szWow64ExtFileNameBuffer[MAX_PATH])
    {
        LPCTSTR pszWow64ExtFileName = NULL;

        switch (usProcessorArchitecture)
        {
        case PROCESSOR_ARCHITECTURE_AMD64:
        {
            pszWow64ExtFileName = TEXT("..\\x64\\Release\\wow64ext.dll");
        }
        break;
        case PROCESSOR_ARCHITECTURE_ARM64:
        {
            pszWow64ExtFileName = TEXT("..\\ARM64\\Release\\wow64ext.dll");
        }
        break;
        case PROCESSOR_ARCHITECTURE_IA64:
        {
            pszWow64ExtFileName = TEXT("..\\IA64\\Release\\wow64ext.dll");
        }
        break;
        default:
            break;
        }

        return pszWow64ExtFileName;
    }
}

extern HANDLE cur_process;
extern HMODULE hmod_wow64ext_only_mapped;
extern DWORD64 hmod_ntdll64;
extern HMODULE hmod_ntdll64_only_mapped;