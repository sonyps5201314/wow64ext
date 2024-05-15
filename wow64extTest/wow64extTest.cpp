// wow64extTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#define _CRT_SECURE_NO_WARNINGS

#define _ATL_XP_TARGETING

#include <stdio.h>
#include <windows.h>
#include <tchar.h>

#include <ntdll.h>
#include <atlbase.h>

#pragma comment(lib, "ntdll.lib")

#ifdef HAS_RemoveApiSets
#include "RemoveApiSets\Misc.cpp"
#include "RemoveApiSets\Phlib.cpp"
#endif

#include "..\wow64ext\wow64ext.h"
#include "..\wow64ext\import.cpp"

int main()
{
    printf("wow64extTest\r\n");
    printf("\r\n");

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, GetCurrentProcessId());
    if (hProcess == NULL)
    {
        printf("cannot open process, %u\r\n", GetLastError());
        return -1;
    }

#ifdef HAS_RemoveApiSets
    pApiSetSchema = GetApiSetSchema();
    HMODULE hmod1 = GetProcessModuleHandle_WithLock(hProcess, _T("api-ms-win-core-com-l1-1-0.dll"));
    HMODULE hmod2 = GetProcessModuleHandle_NoLock(hProcess, _T("api-ms-win-core-com-l1-1-0.dll"));
    ATLASSERT(hmod1 == hmod2);
    delete pApiSetSchema;
    pApiSetSchema = NULL;
#endif

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

    SIZE_T ret_len = 0;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    NTSTATUS ntStatus = NtQueryVirtualMemory(hProcess, main, MemoryBasicInformation, &mbi, sizeof(mbi), &ret_len);
    printf("[WOW64]NtQueryVirtualMemory ntStatus=%d BaseAddress=0x%p\r\n", ntStatus, mbi.BaseAddress);
    if (Wow64Ext_DoWork(TRUE) == 0)
    {
        // Wow64Ext APIs test
        DWORD64 ret_len = 0;
        MEMORY_BASIC_INFORMATION64 mbi = { 0 };
        DWORD64 pfn = Wow64Ext_GetNative64BitNtDllProcAddress("NtQueryVirtualMemory");
        DWORD64 ntStatus = Wow64Ext_CallNative64BitFunction(pfn, 6, (DWORD64)hProcess, (DWORD64)main, (DWORD64)MemoryBasicInformation, (DWORD64)&mbi, (DWORD64)sizeof(mbi), (DWORD64)&ret_len);
        printf("[NATIVE]NtQueryVirtualMemory ntStatus=%I64d BaseAddress=0x%I64X\r\n", ntStatus, mbi.BaseAddress);

        // wow64ext classic APIs test
        DWORD64 hmod64 = GetModuleHandle64(L"wow64.dll");
        printf("[wow64ext]GetModuleHandle64 result=0x%I64X\r\n", hmod64);
        if (hmod64)
        {
            DWORD64 pfn = GetProcAddress64(hmod64, "Wow64SystemServiceEx");
            printf("[wow64ext]GetProcAddress64 result=0x%I64X\r\n", pfn);
            SIZE_T ret_len32 = VirtualQueryEx64(hProcess, pfn, &mbi, sizeof(mbi));
            printf("[wow64ext]VirtualQueryEx64 result=0x%X BaseAddress=0x%I64X\r\n", ret_len32, mbi.BaseAddress);
            DWORD64 pcbAllocCode = VirtualAllocEx64(hProcess, NULL, 64, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
            printf("[wow64ext]VirtualAllocEx64 result=0x%I64X\r\n", pcbAllocCode);
            DWORD dwOldProtect;
            BOOL bResult = VirtualProtectEx64(hProcess, pcbAllocCode, 32, PAGE_READWRITE, &dwOldProtect);
            printf("[wow64ext]VirtualProtectEx64 result=%d\r\n", bResult);
            BYTE cbCode[64] = { 0 };
            bResult = ReadProcessMemory64(hProcess, pfn, cbCode, sizeof(cbCode), NULL);
            printf("[wow64ext]ReadProcessMemory64 result=%d\r\n", bResult);
            bResult = WriteProcessMemory64(hProcess, pcbAllocCode, cbCode, sizeof(cbCode), NULL);
            printf("[wow64ext]WriteProcessMemory64 result=%d\r\n", bResult);
            bResult = VirtualFreeEx64(hProcess, pcbAllocCode, 0, MEM_RELEASE);
            printf("[wow64ext]VirtualFreeEx64 result=%d\r\n", bResult);

            _CONTEXT64* lpContext = NULL;

            AMD64_CONTEXT amd64Context = { 0 };
            amd64Context.ContextFlags = CONTEXT_INTEGER;

            ARM64_NT_CONTEXT arm64Context = { 0 };
            arm64Context.ContextFlags = CONTEXT_INTEGER;

            SYSTEM_PROCESSOR_INFORMATION cpu = { 0 };
            ULONG retlen = 0;
            NTSTATUS ntStatus = _NtWow64GetNativeSystemInformation(SystemProcessorInformation, &cpu, sizeof(cpu), &retlen);
            switch (cpu.ProcessorArchitecture)
            {
            case PROCESSOR_ARCHITECTURE_AMD64:
            {
                lpContext = (_CONTEXT64*)&amd64Context;
            }
            break;
            case PROCESSOR_ARCHITECTURE_ARM64:
            {
                lpContext = (_CONTEXT64*)&arm64Context;
            }
            break;
            default:
            {
                printf("[wow64ext]NtWow64GetNativeSystemInformation unknown ProcessorArchitecture=%hu\r\n", cpu.ProcessorArchitecture);
            }
            break;
            }
            if (lpContext)
            {
                bResult = GetThreadContext64(GetCurrentThread(), lpContext);
                printf("[wow64ext]GetThreadContext64 result=%d\r\n", bResult);
                if (bResult)
                {
                    bResult = SetThreadContext64(GetCurrentThread(), lpContext);
                    printf("[wow64ext]SetThreadContext64 result=%d\r\n", bResult);
                }
            }

            DWORD dwLastError = GetLastError();
            SetLastErrorFromNative64Call((DWORD64)STATUS_ACCESS_VIOLATION);
            bResult = GetLastError() == ERROR_NOACCESS;
            SetLastError(dwLastError);
            printf("[wow64ext]SetLastErrorFromNative64Call result=%d\r\n", bResult);
        }

        Wow64Ext_DoWork(FALSE);
    }
    CloseHandle(hProcess);
    hProcess = NULL;

    printf("\r\n");
    printf("press any key to continue.\r\n");
    int n = getchar();

    return 0;
}
