#pragma once

#include "import.h"

// Wow64Ext APIs
static int Wow64Ext_DoWork(BOOL bToStart)
{
    BOOL Wow64Process = FALSE;
    IsWow64Process(GetCurrentProcess(), &Wow64Process);
    if (!Wow64Process)
    {
        return -1;
    }

    HMODULE hmod_ntdll32 = GetModuleHandle(_T("ntdll.dll"));
    if (!hmod_ntdll32)
    {
        return -2;
    }

    NTSTATUS(NTAPI * _NtWow64GetNativeSystemInformation)(SYSTEM_INFORMATION_CLASS class0, void* info, ULONG len, ULONG * retlen)
        = (NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, void*, ULONG, ULONG*))GetProcAddress(hmod_ntdll32, "NtWow64GetNativeSystemInformation");
    if (!_NtWow64GetNativeSystemInformation)
    {
        return -3;
    }

    LPCWSTR pDstModName = NULL;
    SYSTEM_PROCESSOR_INFORMATION cpu = { 0 };
    ULONG retlen = 0;
    NTSTATUS ntStatus = _NtWow64GetNativeSystemInformation(SystemProcessorInformation, &cpu, sizeof(cpu), &retlen);
    switch (cpu.ProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_AMD64:
    {
        pDstModName = L"wow64cpu.dll";
    }
    break;
    case PROCESSOR_ARCHITECTURE_ARM64:
    {
        pDstModName = L"xtajit.dll";
    }
    break;
    case PROCESSOR_ARCHITECTURE_IA64:
    {
        // NOT VERIFIED
        pDstModName = L"Wowia32x.dll";
    }
    break;
    default:
        return -4;
        break;
    }

    TCHAR szWow64ExtFileNameBuffer[MAX_PATH];
    szWow64ExtFileNameBuffer[0] = 0;
    LPCTSTR pszWow64ExtFileName = GetWow64ExtFileName(cpu.ProcessorArchitecture, szWow64ExtFileNameBuffer);
    if (pszWow64ExtFileName == NULL || pszWow64ExtFileName[0] == 0)
    {
        return -5;
    }

    if (bToStart)
    {
        ATLASSERT(hmod_wow64ext_only_mapped == NULL);
        if (hmod_wow64ext_only_mapped != NULL)
        {
            return -6;
        }
        hmod_wow64ext_only_mapped = (HMODULE)MapImage(pszWow64ExtFileName);
    }
    if (hmod_wow64ext_only_mapped == NULL)
    {
        return -7;
    }

    if (bToStart)
    {
        cur_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    }
    if (cur_process == NULL)
    {
        return -8;
    }

    UINT* pHeavensGateNum = (UINT*)GetProcAddressByImageExportDirectoryT<IMAGE_NT_HEADERS64>(cur_process, (DWORD64)hmod_wow64ext_only_mapped, "HeavensGateNum");
    if (bToStart)
    {
        // Temporarily map loading the x86 version's ntdll.dll to prevent NtWow64ReadVirtualMemory64 from being hooked
        // Windows 10 1709 is the first client version of Windows to support the ARM64 architecture.
        // This first ARM64 version comes with both ARM32 and x86 support.
        // https://betawiki.net/wiki/Windows_10_Fall_Creators_Update
        TCHAR szNtDll32Name_x86[MAX_PATH];
        szNtDll32Name_x86[0] = 0;
        _sntprintf(szNtDll32Name_x86, _countof(szNtDll32Name_x86), _T("%s\\SysWOW64\\ntdll.dll"), _tgetenv(_T("windir")));
        HMODULE hmod_ntdll32_x86_only_mapped = (HMODULE)MapImage(szNtDll32Name_x86);
        if (hmod_ntdll32_x86_only_mapped == NULL)
        {
            return -9;
        }
        PBYTE pcbCode = (PBYTE)GetProcAddressByImageExportDirectoryT<IMAGE_NT_HEADERS32>(cur_process, (DWORD64)hmod_ntdll32_x86_only_mapped, "NtWow64ReadVirtualMemory64");
        // B8 F5 01 00 00          mov     eax, 1F5h       ; NtWow64ReadVirtualMemory64
        if (pcbCode[0] == 0xB8)
        {
            DWORD num = *(DWORD*)&pcbCode[1];
            *pHeavensGateNum = num;
        }
        UnmapImage(hmod_ntdll32_x86_only_mapped);
    }

    PVOID64* pWow64SystemServiceEx_O = (PVOID64*)GetProcAddressByImageExportDirectoryT<IMAGE_NT_HEADERS64>(cur_process, (DWORD64)hmod_wow64ext_only_mapped, "Wow64SystemServiceEx_O");
    if (!bToStart && *pWow64SystemServiceEx_O == NULL)
    {
        return -10;
    }
    PVOID Wow64SystemServiceEx_M = (PVOID)GetProcAddressByImageExportDirectoryT<IMAGE_NT_HEADERS64>(cur_process, (DWORD64)hmod_wow64ext_only_mapped, "Wow64SystemServiceEx_M");
    PVOID pNewFunction = Wow64SystemServiceEx_M;

    if (bToStart)
    {
        hmod_ntdll64 = (DWORD64)GetProcessModuleHandle64_NoLock(cur_process, L"ntdll.dll");
        if (hmod_ntdll64 == NULL)
        {
            return -11;
        }
    }
    else
    {
        ATLASSERT(hmod_ntdll64);
        hmod_ntdll64 = NULL;
    }

    if (bToStart)
    {
        ATLASSERT(hmod_ntdll64_only_mapped == NULL);
        if (hmod_ntdll64_only_mapped != NULL)
        {
            return -12;
        }
        PVOID OldValue;
        BOOL bRet = Wow64DisableWow64FsRedirection(&OldValue);
        if (bRet == TRUE)
        {
            TCHAR szNtDll64Name[MAX_PATH];
            szNtDll64Name[0] = 0;
            _sntprintf(szNtDll64Name, _countof(szNtDll64Name), _T("%s\\System32\\ntdll.dll"), _tgetenv(_T("windir")));
            hmod_ntdll64_only_mapped = (HMODULE)MapImage(szNtDll64Name);

            Wow64RevertWow64FsRedirection(OldValue);
        }
        if (hmod_ntdll64_only_mapped == NULL)
        {
            return -13;
        }
    }
    else
    {
        UnmapImage(hmod_ntdll64_only_mapped);
    }

    HMODULE hDstMod = (HMODULE)GetProcessModuleHandle64_NoLock(cur_process, pDstModName);
    if (hDstMod == NULL)
    {
        return 1;
    }

    LPCSTR pDllNameOfThatFunction = "wow64.dll";
    LPCSTR pThatFunctionName = "Wow64SystemServiceEx";

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hDstMod;
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY ImageDataDirectory_Import = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImageImport = (PIMAGE_IMPORT_DESCRIPTOR)(ImageDataDirectory_Import.VirtualAddress == 0 ? NULL : (PBYTE)pDosHeader + ImageDataDirectory_Import.VirtualAddress);

    if (NULL == pImageImport)
        return 2;

    while (pImageImport->Name)
    {
        if (0 == _stricmp((char*)((PBYTE)hDstMod + pImageImport->Name), pDllNameOfThatFunction))
        {
            break;
        }
    CHECK_NEXT_IMAGE_IMPORT_DESCRIPTOR_FOR_FIND_DLL_NAME_OF_THAT_FUNCTION: ++pImageImport;
    }

    if (!pImageImport->Name)
    {
        return 3;
    }

    // Get caller's import address table (IAT) for the callee's functions
    PIMAGE_THUNK_DATA64 pFunctionAddressThunk = NULL;
    if (pImageImport->FirstThunk)
    {
        pFunctionAddressThunk = (PIMAGE_THUNK_DATA64)((PBYTE)hDstMod + pImageImport->FirstThunk);
    }
    ATLASSERT(pFunctionAddressThunk);
    if (pFunctionAddressThunk == NULL)
        return 4;

    PIMAGE_THUNK_DATA64 pNameThunk = NULL;
    if (pImageImport->OriginalFirstThunk)
    {
        pNameThunk = (PIMAGE_THUNK_DATA64)((PBYTE)hDstMod + pImageImport->OriginalFirstThunk);
    }
    ATLASSERT(pNameThunk);
    if (pNameThunk == NULL)
        return 5;

    PVOID64 lpFunction = NULL;

    // Find current function address
    for (; pNameThunk->u1.Function; pNameThunk++, pFunctionAddressThunk++)
    {
        if (IMAGE_ORDINAL_FLAG == (pNameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
        {
            continue;
        }
        else
        {
            // Is this the function we're looking for?
            IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)((PBYTE)hDstMod + pNameThunk->u1.AddressOfData);
            BOOL bFound = (0 == strcmp((const char*)pImportByName->Name, pThatFunctionName));
            if (bFound)
            {
                // Get the address of the function address
                PVOID64 pfn = (PVOID64)pFunctionAddressThunk->u1.Function;
                lpFunction = pfn;
                break;  // We did it, get out
            }
        }
    }

    if (lpFunction == NULL)
    {
        goto CHECK_NEXT_IMAGE_IMPORT_DESCRIPTOR_FOR_FIND_DLL_NAME_OF_THAT_FUNCTION;
    }

    DWORD dwOldProtect, dwNewProctect;
    if (VirtualProtect(&pFunctionAddressThunk->u1.Function, sizeof(PVOID64), PAGE_READWRITE, &dwOldProtect))
    {
        if (bToStart)
        {
            *pWow64SystemServiceEx_O = lpFunction;
            pFunctionAddressThunk->u1.Function = (ULONGLONG)pNewFunction;
        }
        else
        {
            pFunctionAddressThunk->u1.Function = (ULONGLONG)*pWow64SystemServiceEx_O;
        }
        VirtualProtect(&pFunctionAddressThunk->u1.Function, sizeof(PVOID64), dwOldProtect, &dwNewProctect);
    }
    if (!bToStart)
    {
        UnmapImage(hmod_wow64ext_only_mapped);

        CloseHandle(cur_process);
        cur_process = NULL;
    }

    return 0;
}

static DWORD64 Wow64Ext_GetNative64BitNtDllProcAddress(LPCSTR name)
{
    if (hmod_ntdll64 == NULL || hmod_ntdll64_only_mapped == NULL)
    {
        ATLASSERT(hmod_ntdll64 && hmod_ntdll64_only_mapped);
        return 0;
    }
    DWORD dwFuncIn32 = (DWORD)GetProcAddressByImageExportDirectoryT<IMAGE_NT_HEADERS64>(cur_process, (DWORD64)hmod_ntdll64_only_mapped, name);
    if (dwFuncIn32 == 0)
    {
        ATLASSERT(dwFuncIn32);
        return 0;
    }

    DWORD64 pfn = hmod_ntdll64 + (dwFuncIn32 - (DWORD)(DWORD_PTR)hmod_ntdll64_only_mapped);
    return pfn;
}

// Note: Each parameter must be DWORD64 in size
static DWORD64 Wow64Ext_CallNative64BitFunction(DWORD64 func, int argC, ...)
{
    if (func == 0)
    {
        ATLASSERT(func);
        return STATUS_INVALID_PARAMETER;
    }

    tagNative64BitFunctionCallInfo callInfo = { 0 };
    callInfo.pfn = func;
    callInfo.dwParamCount = argC;
    va_list args;
    va_start(args, argC);
    for (int i = 0; i < argC; i++)
    {
        callInfo.Params[i] = va_arg(args, DWORD64);
    }
    va_end(args);

    NTSTATUS ntStatus = _NtWow64ReadVirtualMemory64(NtCurrentProcess(), (PVOID64)0x975787875797CAB1, (PVOID)0x16895188, 0x9090950C0FEF00D, (PUINT64)&callInfo);
    return callInfo.result;
}

// Note: Each parameter must be DWORD64 in size
#define Wow64Ext_CallNative64BitNtDllFunctionByName(name, argC, ...) Wow64Ext_CallNative64BitFunction(Wow64Ext_GetNative64BitNtDllProcAddress(name), argC, __VA_ARGS__)