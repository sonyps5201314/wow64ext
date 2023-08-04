#pragma once

#define _CRT_SECURE_NO_WARNINGS

#define _ATL_XP_TARGETING

#include <stdio.h>
#include <windows.h>
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

extern NTSTATUS(NTAPI* _NtReadVirtualMemory64)(IN HANDLE ProcessHandle, IN PVOID64 BaseAddress, OUT PVOID Buffer, IN UINT64 NumberOfBytesToRead, OUT PUINT64 NumberOfBytesReaded);
extern NTSTATUS(NTAPI* _NtQueryInformationProcess64)(IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
static PVOID64 GetProcessModuleHandle_64From32(DWORD dwPID, LPCWSTR lpModuleName)
{
    ATLASSERT(dwPID);
    ATLASSERT(lpModuleName);
    if (!dwPID || !lpModuleName)
    {
        return NULL;
    }

    BOOL bCompareFullPath = !PathIsRelativeW(lpModuleName);

    //Open process memory for read PEB
    CHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID));
    if (hProcess == NULL)
    {
        ATLTRACE(_T("Can't open '%d'\n"), dwPID);
        return NULL;
    }

    if (_NtQueryInformationProcess64 == NULL || _NtReadVirtualMemory64 == NULL)
    {
        HMODULE hmod_ntdll = GetModuleHandle(_T("ntdll.dll"));
        if (hmod_ntdll)
        {
            _NtQueryInformationProcess64 = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
                GetProcAddress(hmod_ntdll, "NtWow64QueryInformationProcess64");
            _NtReadVirtualMemory64 = (NTSTATUS(NTAPI*)(HANDLE, PVOID64, PVOID, UINT64, PUINT64))
                GetProcAddress(hmod_ntdll, "NtWow64ReadVirtualMemory64");
        }
    }

    PROCESS_BASIC_INFORMATION64 pbi64;
    if (_NtQueryInformationProcess64 == NULL || _NtReadVirtualMemory64 == NULL)
    {
        ATLASSERT(FALSE);
        return NULL;
    }

    DWORD dwSize;
    UINT64 size;
    NTSTATUS iReturn;
    PVOID64 pAddrPEB = NULL;


    iReturn = _NtQueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi64, sizeof(pbi64), &dwSize);
    pAddrPEB = pbi64.PebBaseAddress;

    // NtQueryInformationProcess returns a negative value if it fails
    if (iReturn >= 0)
    {
        // 1. Find the Process Environment Block
        PEB64 PEB;
        size = dwSize;
        if (ERROR_SUCCESS != _NtReadVirtualMemory64(hProcess, pAddrPEB, &PEB, sizeof(PEB), &size))
        {
            // Call GetLastError() if you need to know why
            return NULL;
        }

        ULONG64 dwBytesRead;
        PEB_LDR_DATA64 Ldr;
        if (ERROR_SUCCESS != _NtReadVirtualMemory64(hProcess, PEB.Ldr, (LPVOID)&Ldr, sizeof(Ldr), &dwBytesRead))
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
            iReturn = _NtReadVirtualMemory64(hProcess, pNextModuleInfo, &module_info, sizeof(LDR_MODULE64), &dwBytesRead);
            if (ERROR_SUCCESS != iReturn)
            {
                ATLTRACE(_T("NtReadVirtualMemory error %u\n"), iReturn);
                return NULL;
            }

            wFullDllName[0] = 0;
            //Read string with Dll full name
            iReturn = _NtReadVirtualMemory64(hProcess, (PVOID64)module_info.FullDllName.Buffer, (LPVOID)&wFullDllName, module_info.FullDllName.MaximumLength, &dwBytesRead);
            if (ERROR_SUCCESS != iReturn)
            {
                ATLTRACE(_T("NtReadVirtualMemory error %u\n"), iReturn);
                return NULL;
            }
            //wprintf(L"0x%I64x %s\n", module_info.DllBase, wFullDllName);

            if (bCompareFullPath)
            {
                if (!_wcsnicmp(wFullDllName, lpModuleName, _countof(wFullDllName)))
                {
                    return module_info.DllBase;
                }
            }
            else
            {
                LPCWSTR pszDllName = PathFindFileNameW(wFullDllName);
                if (!_wcsicmp(pszDllName, lpModuleName))
                {
                    return module_info.DllBase;
                }
            }

            pNextModuleInfo = (PVOID64)module_info.InLoadOrderModuleList.Flink;
        } while (pNextModuleInfo != pStartModuleInfo);
    }

    return NULL;
}

template<typename PIMAGE_NT_HEADERS_T>
PVOID GetProcAddressByImageExportDirectoryT(HMODULE hModule, LPCSTR lpProcName)
{
    char* pRet = NULL;
    PIMAGE_DOS_HEADER pImageDosHeader = NULL;
    PIMAGE_NT_HEADERS_T pImageNtHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

    pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
    pImageNtHeader = (PIMAGE_NT_HEADERS_T)((DWORD_PTR)hModule + pImageDosHeader->e_lfanew);
    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD dwExportRVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD dwExportSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    DWORD* pAddressOfFunction = (DWORD*)(pImageExportDirectory->AddressOfFunctions + (DWORD_PTR)hModule);
    DWORD* pAddressOfNames = (DWORD*)(pImageExportDirectory->AddressOfNames + (DWORD_PTR)hModule);
    DWORD dwNumberOfNames = (pImageExportDirectory->NumberOfNames);
    DWORD dwBase = (pImageExportDirectory->Base);

    WORD* pAddressOfNameOrdinals = (WORD*)(pImageExportDirectory->AddressOfNameOrdinals + (DWORD_PTR)hModule);

    // This is to check in what way (function name or function number) to check the function address
    DWORD_PTR dwName = (DWORD_PTR)lpProcName;
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
        pRet = (char*)(pAddressOfFunction[dwName - dwBase] + (DWORD_PTR)hModule);

        return pRet;
    }

    for (DWORD i = 0; i < dwNumberOfNames; i++)
    {
        char* strFunction = (char*)(pAddressOfNames[i] + (DWORD_PTR)hModule);
        if (strcmp(strFunction, (char*)lpProcName) == 0)
        {
            pRet = (char*)(pAddressOfFunction[pAddressOfNameOrdinals[i]] + (DWORD_PTR)hModule);
            // Judging whether the obtained address is out of bounds 
            if ((DWORD_PTR)pRet < dwExportRVA + (DWORD_PTR)hModule || (DWORD_PTR)pRet > dwExportRVA + (DWORD_PTR)hModule +

                dwExportSize)
            {
                return pRet;
            }

            char pTempDll[100];
            pTempDll[0] = 0;
            char pTempFuction[100];
            pTempFuction[0] = 0;
            strncpy(pTempDll, pRet, _countof(pTempDll));
            pTempDll[_countof(pTempDll) - 1] = 0;
            char* p = strchr(pTempDll, '.');
            if (!p)
            {
                return pRet;
            }
            // *p = 0; The original 
            *p = '\0'; // The purpose is to truncate the string and replace '.' with 0, namely '\0'
            strncpy(pTempFuction, p + 1, _countof(pTempFuction));
            char dot_dll_Str[] = { '.', 'd', 'l', 'l', 0 };
            strncat(pTempDll, dot_dll_Str, __min(_countof(dot_dll_Str), (_countof(pTempDll) - 1) - strlen(pTempDll)));
            pTempDll[_countof(pTempDll) - 1] = 0;
            HMODULE h = LoadLibraryA(pTempDll);
            if (h == NULL)
            {
                return pRet;
            }
            return GetProcAddressByImageExportDirectoryT<PIMAGE_NT_HEADERS_T>(h, pTempFuction);
        }
    }
    return NULL;
}

//https://github.com/hryuk/Carberp/blob/master/source%20-%20absource/pro/all%20source/anti_rapport/antirapport.cpp
static PVOID MapBinary(LPCTSTR Path)
{
    LPVOID Map = NULL;
    HANDLE hMapping;
    HANDLE hFile;

    hFile = CreateFile(Path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        hMapping = CreateFileMapping(hFile, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
        if (hMapping != NULL)
        {
            Map = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

            CloseHandle(hMapping);
        }

        CloseHandle(hFile);
    }

    return Map;
}

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

extern HMODULE hmod_wow64ext_only_mapped;
extern DWORD64 hmod_ntdll64;
extern HMODULE hmod_ntdll64_only_mapped;