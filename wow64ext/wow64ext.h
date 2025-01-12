#pragma once

#ifndef __DISABLE_ERROR_ON_LARGEADDRESSAWARE_COMPATIBILITY_CHECK_FAILED__
#pragma warning( error : 4826 )
#elif !defined(__DISABLE_WARNING_ON_LARGEADDRESSAWARE_COMPATIBILITY_CHECK_FAILED__)
#pragma warning( default : 4826 )
#endif

// Without the double casting, the pointer is sign extended, not zero extended,
// which leads to invalid addresses with /LARGEADDRESSAWARE.
#define PTR_TO_DWORD64(p) ((DWORD64)(ULONG_PTR)(p))

// Sign-extension is required for pseudo handles such as the handle returned
// from GetCurrentProcess().
// "64-bit versions of Windows use 32-bit handles for interoperability [...] it
// is safe to [...] sign-extend the handle (when passing it from 32-bit to
// 64-bit)."
// https://docs.microsoft.com/en-us/windows/win32/winprog64/interprocess-communication
#define HANDLE_TO_DWORD64(p) ((DWORD64)(LONG_PTR)(p))

#include "api.h"

// wow64ext classic APIs

// Native64Call is an evolutionary version of X64Call, it not only supports x64 but also supports ARM64 and other 64-bit systems that support WOW64
// Note: Each parameter must be DWORD64 in size
#define Native64Call(func, argC, ...) Wow64Ext_CallNative64BitFunction(func, argC, __VA_ARGS__)

// Code modification from wine

#define WINE_WARN(...) do { } while(0)

#define WARN                       WINE_WARN

/* flag for LdrAddRefDll */
#define LDR_ADDREF_DLL_PIN              0x00000001

/* flags for LdrGetDllHandleEx */
#define LDR_GET_DLL_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 0x00000001
#define LDR_GET_DLL_HANDLE_EX_FLAG_PIN                0x00000002

static inline BOOL set_ntstatus(NTSTATUS status)
{
    if (status) SetLastError(RtlNtStatusToDosError(status));
    return !status;
}

static DWORD64 GetModuleHandle64(const wchar_t* lpModuleName)
{
    DWORD64 ret = NULL;
    NTSTATUS status;

    UNICODE_STRING64 wstr;
    ULONG ldr_flags = 0;

    ldr_flags |= LDR_GET_DLL_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;

    Wow64Ext_CallNative64BitNtDllFunctionByName("RtlInitUnicodeString", 2, PTR_TO_DWORD64(&wstr), PTR_TO_DWORD64(lpModuleName));
    status = (NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("LdrGetDllHandleEx", 5, (DWORD64)ldr_flags, (DWORD64)NULL, (DWORD64)NULL, PTR_TO_DWORD64(&wstr), PTR_TO_DWORD64(&ret));

    set_ntstatus(status);

    return ret;
}

static DWORD64 GetProcAddress64(DWORD64 hModule, const char* funcName)
{
    DWORD64 proc;
    ANSI_STRING64 str;

    if ((ULONG_PTR)funcName >> 16)
    {
        Wow64Ext_CallNative64BitNtDllFunctionByName("RtlInitAnsiString", 2, PTR_TO_DWORD64(&str), PTR_TO_DWORD64(funcName));
        if (!set_ntstatus((NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("LdrGetProcedureAddress", 4, hModule, PTR_TO_DWORD64(&str), (DWORD64)0, PTR_TO_DWORD64((void**)&proc)))) return NULL;
    }
    else if (!set_ntstatus((NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("LdrGetProcedureAddress", 4, hModule, (DWORD64)NULL, (DWORD64)LOWORD(funcName), PTR_TO_DWORD64((void**)&proc))))
        return NULL;

    return proc;
}


static SIZE_T VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength)
{
    DWORD64 ret;

    if (!set_ntstatus((NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtQueryVirtualMemory", 6, HANDLE_TO_DWORD64(hProcess), lpAddress, (DWORD64)MemoryBasicInformation, PTR_TO_DWORD64(lpBuffer), (DWORD64)dwLength, PTR_TO_DWORD64(&ret))))
        return 0;
    return (SIZE_T)ret;
}

static DWORD64 VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    DWORD64 size = dwSize;
    PVOID64 ret = (PVOID64)lpAddress;

    if (!set_ntstatus((NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtAllocateVirtualMemory", 6, HANDLE_TO_DWORD64(hProcess), PTR_TO_DWORD64(&ret), (DWORD64)0, PTR_TO_DWORD64(&size), (DWORD64)flAllocationType, (DWORD64)flProtect))) return NULL;
    return (DWORD64)ret;
}

static BOOL VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    DWORD64 size = dwSize;

    if (dwFreeType == MEM_RELEASE && size)
    {
        WARN("Trying to release memory with specified size.\n");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return set_ntstatus((NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtFreeVirtualMemory", 4, HANDLE_TO_DWORD64(hProcess), PTR_TO_DWORD64(&lpAddress), PTR_TO_DWORD64(&size), (DWORD64)dwFreeType));
}

static BOOL VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
{
    DWORD64 size = dwSize;

    return set_ntstatus((NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtProtectVirtualMemory", 5, HANDLE_TO_DWORD64(hProcess), PTR_TO_DWORD64(&lpAddress), PTR_TO_DWORD64(&size), (DWORD64)flNewProtect, PTR_TO_DWORD64(lpflOldProtect)));
}

#ifndef _WIN64

__if_not_exists(M128A)
{
    typedef struct DECLSPEC_ALIGN(16) _M128A {
        ULONGLONG Low;
        LONGLONG High;
    } M128A, * PM128A;
}

__if_not_exists(XSAVE_FORMAT)
{
    typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT {
        WORD   ControlWord;
        WORD   StatusWord;
        BYTE  TagWord;
        BYTE  Reserved1;
        WORD   ErrorOpcode;
        DWORD ErrorOffset;
        WORD   ErrorSelector;
        WORD   Reserved2;
        DWORD DataOffset;
        WORD   DataSelector;
        WORD   Reserved3;
        DWORD MxCsr;
        DWORD MxCsr_Mask;
        M128A FloatRegisters[8];

#if defined(_WIN64)

        M128A XmmRegisters[16];
        BYTE  Reserved4[96];

#else

        M128A XmmRegisters[8];
        BYTE  Reserved4[224];

#endif

    } XSAVE_FORMAT, * PXSAVE_FORMAT;
}
typedef XSAVE_FORMAT XMM_SAVE_AREA32, * PXMM_SAVE_AREA32;
#endif

typedef struct DECLSPEC_ALIGN(16) _AMD64_CONTEXT {
    DWORD64 P1Home;          /* 000 */
    DWORD64 P2Home;          /* 008 */
    DWORD64 P3Home;          /* 010 */
    DWORD64 P4Home;          /* 018 */
    DWORD64 P5Home;          /* 020 */
    DWORD64 P6Home;          /* 028 */

    /* Control flags */
    DWORD ContextFlags;      /* 030 */
    DWORD MxCsr;             /* 034 */

    /* Segment */
    WORD SegCs;              /* 038 */
    WORD SegDs;              /* 03a */
    WORD SegEs;              /* 03c */
    WORD SegFs;              /* 03e */
    WORD SegGs;              /* 040 */
    WORD SegSs;              /* 042 */
    DWORD EFlags;            /* 044 */

    /* Debug */
    DWORD64 Dr0;             /* 048 */
    DWORD64 Dr1;             /* 050 */
    DWORD64 Dr2;             /* 058 */
    DWORD64 Dr3;             /* 060 */
    DWORD64 Dr6;             /* 068 */
    DWORD64 Dr7;             /* 070 */

    /* Integer */
    DWORD64 Rax;             /* 078 */
    DWORD64 Rcx;             /* 080 */
    DWORD64 Rdx;             /* 088 */
    DWORD64 Rbx;             /* 090 */
    DWORD64 Rsp;             /* 098 */
    DWORD64 Rbp;             /* 0a0 */
    DWORD64 Rsi;             /* 0a8 */
    DWORD64 Rdi;             /* 0b0 */
    DWORD64 R8;              /* 0b8 */
    DWORD64 R9;              /* 0c0 */
    DWORD64 R10;             /* 0c8 */
    DWORD64 R11;             /* 0d0 */
    DWORD64 R12;             /* 0d8 */
    DWORD64 R13;             /* 0e0 */
    DWORD64 R14;             /* 0e8 */
    DWORD64 R15;             /* 0f0 */

    /* Counter */
    DWORD64 Rip;             /* 0f8 */

    /* Floating point */
    union {
        XMM_SAVE_AREA32 FltSave;  /* 100 */
        struct {
            M128A Header[2];      /* 100 */
            M128A Legacy[8];      /* 120 */
            M128A Xmm0;           /* 1a0 */
            M128A Xmm1;           /* 1b0 */
            M128A Xmm2;           /* 1c0 */
            M128A Xmm3;           /* 1d0 */
            M128A Xmm4;           /* 1e0 */
            M128A Xmm5;           /* 1f0 */
            M128A Xmm6;           /* 200 */
            M128A Xmm7;           /* 210 */
            M128A Xmm8;           /* 220 */
            M128A Xmm9;           /* 230 */
            M128A Xmm10;          /* 240 */
            M128A Xmm11;          /* 250 */
            M128A Xmm12;          /* 260 */
            M128A Xmm13;          /* 270 */
            M128A Xmm14;          /* 280 */
            M128A Xmm15;          /* 290 */
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    /* Vector */
    M128A VectorRegister[26];     /* 300 */
    DWORD64 VectorControl;        /* 4a0 */

    /* Debug control */
    DWORD64 DebugControl;         /* 4a8 */
    DWORD64 LastBranchToRip;      /* 4b0 */
    DWORD64 LastBranchFromRip;    /* 4b8 */
    DWORD64 LastExceptionToRip;   /* 4c0 */
    DWORD64 LastExceptionFromRip; /* 4c8 */
} AMD64_CONTEXT;

struct _CONTEXT64;// AMD64_CONTEXT or ARM64_NT_CONTEXT or new 64bit native arch process's _CONTEXT

static BOOL GetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext)
{
    return set_ntstatus((NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtGetContextThread", 2, HANDLE_TO_DWORD64(hThread), PTR_TO_DWORD64(lpContext)));
}

static BOOL SetThreadContext64(HANDLE hThread, const _CONTEXT64* lpContext)
{
    return set_ntstatus((NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtSetContextThread", 2, HANDLE_TO_DWORD64(hThread), PTR_TO_DWORD64(lpContext)));
}

// Code modification from reactos

static
DWORD
WINAPI
BaseSetLastNTError(IN NTSTATUS Status)
{
    DWORD dwErrCode;

    /* Convert from NT to Win32, then set */
    dwErrCode = RtlNtStatusToDosError(Status);
    SetLastError(dwErrCode);
    return dwErrCode;
}

static BOOL ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize32, SIZE_T* lpNumberOfBytesRead)
{
    DWORD64 nSize = nSize32;

    NTSTATUS Status;

    /* Do the read */
    Status = (NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtReadVirtualMemory", 5, HANDLE_TO_DWORD64(hProcess),
        lpBaseAddress,
        PTR_TO_DWORD64(lpBuffer),
        nSize,
        PTR_TO_DWORD64(&nSize));

    /* In user-mode, this parameter is optional */
    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = (SIZE_T)nSize;
    if (!NT_SUCCESS(Status))
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Return success */
    return TRUE;
}

// rewolf-wow64ext's WriteProcessMemory64 is not equivalent to the WriteProcessMemory implemented by Microsoft, but the WriteProcessMemory64 we modified is
static BOOL WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize32, SIZE_T* lpNumberOfBytesWritten)
{
    NTSTATUS Status;
    ULONG OldValue;
    DWORD64 RegionSize;
    PVOID64 Base;
    BOOLEAN UnProtect;

    DWORD64 nSize = nSize32;

    /* Set parameters for protect call */
    RegionSize = nSize;
    Base = (PVOID64)lpBaseAddress;

    /* Check the current status */
    Status = (NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtProtectVirtualMemory", 5, HANDLE_TO_DWORD64(hProcess),
        PTR_TO_DWORD64(&Base),
        PTR_TO_DWORD64(&RegionSize),
        (DWORD64)PAGE_EXECUTE_READWRITE,
        PTR_TO_DWORD64(&OldValue));
    if (NT_SUCCESS(Status))
    {
        /* Check if we are unprotecting */
        UnProtect = OldValue & (PAGE_READWRITE |
            PAGE_WRITECOPY |
            PAGE_EXECUTE_READWRITE |
            PAGE_EXECUTE_WRITECOPY) ? FALSE : TRUE;
        if (!UnProtect)
        {
            /* Set the new protection */
            Status = (NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtProtectVirtualMemory", 5, HANDLE_TO_DWORD64(hProcess),
                PTR_TO_DWORD64(&Base),
                PTR_TO_DWORD64(&RegionSize),
                (DWORD64)OldValue,
                PTR_TO_DWORD64(&OldValue));

            /* Write the memory */
            Status = (NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtWriteVirtualMemory", 5, HANDLE_TO_DWORD64(hProcess),
                lpBaseAddress,
                PTR_TO_DWORD64((LPVOID)lpBuffer),
                nSize,
                PTR_TO_DWORD64(&nSize));

            /* In Win32, the parameter is optional, so handle this case */
            if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = (SIZE_T)nSize;

            if (!NT_SUCCESS(Status))
            {
                /* We failed */
                BaseSetLastNTError(Status);
                return FALSE;
            }

            /* Flush the ITLB */
            Wow64Ext_CallNative64BitNtDllFunctionByName("NtFlushInstructionCache", 3, HANDLE_TO_DWORD64(hProcess), lpBaseAddress, nSize);
            return TRUE;
        }
        else
        {
            /* Check if we were read only */
            if (OldValue & (PAGE_NOACCESS | PAGE_READONLY))
            {
                /* Restore protection and fail */
                Wow64Ext_CallNative64BitNtDllFunctionByName("NtProtectVirtualMemory", 5, HANDLE_TO_DWORD64(hProcess),
                    PTR_TO_DWORD64(&Base),
                    PTR_TO_DWORD64(&RegionSize),
                    (DWORD64)OldValue,
                    PTR_TO_DWORD64(&OldValue));
                BaseSetLastNTError(STATUS_ACCESS_VIOLATION);

                /* Note: This is what Windows returns and code depends on it */
                return STATUS_ACCESS_VIOLATION;
            }

            /* Otherwise, do the write */
            Status = (NTSTATUS)Wow64Ext_CallNative64BitNtDllFunctionByName("NtWriteVirtualMemory", 5, HANDLE_TO_DWORD64(hProcess),
                lpBaseAddress,
                PTR_TO_DWORD64((LPVOID)lpBuffer),
                nSize,
                PTR_TO_DWORD64(&nSize));

            /* In Win32, the parameter is optional, so handle this case */
            if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = (SIZE_T)nSize;

            /* And restore the protection */
            Wow64Ext_CallNative64BitNtDllFunctionByName("NtProtectVirtualMemory", 5, HANDLE_TO_DWORD64(hProcess),
                PTR_TO_DWORD64(&Base),
                PTR_TO_DWORD64(&RegionSize),
                (DWORD64)OldValue,
                PTR_TO_DWORD64(&OldValue));
            if (!NT_SUCCESS(Status))
            {
                /* We failed */
                BaseSetLastNTError(STATUS_ACCESS_VIOLATION);

                /* Note: This is what Windows returns and code depends on it */
                return STATUS_ACCESS_VIOLATION;
            }

            /* Flush the ITLB */
            Wow64Ext_CallNative64BitNtDllFunctionByName("NtFlushInstructionCache", 3, HANDLE_TO_DWORD64(hProcess), lpBaseAddress, nSize);
            return TRUE;
        }
    }
    else
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return FALSE;
    }
}

// SetLastErrorFromNative64Call is an evolutionary version of SetLastErrorFromX64Call, it not only supports x64 but also supports ARM64 and other 64-bit systems that support WOW64
static VOID SetLastErrorFromNative64Call(DWORD64 status)
{
    BaseSetLastNTError((NTSTATUS)status);
}