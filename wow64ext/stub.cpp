#include "pch.h"

#include "shared.h"

EXTERN_C_START

__declspec(dllexport) UINT HeavensGateNum;
__declspec(dllexport) NTSTATUS(WINAPI* Wow64SystemServiceEx_O)(UINT num, UINT* args);
__declspec(dllexport) NTSTATUS WINAPI Wow64SystemServiceEx_M(UINT num, UINT* args)
{
    //check communication password
    if (num == HeavensGateNum)
    {
#pragma pack(push, 4)
        struct NtWow64ReadVirtualMemory64_Params
        {
            UINT ProcessHandle;
            UINT64 BaseAddress;
            UINT Buffer;
            UINT64 NumberOfBytesToRead;
            UINT NumberOfBytesReaded;
        };
#pragma pack(pop)

        NtWow64ReadVirtualMemory64_Params* pParams = (NtWow64ReadVirtualMemory64_Params*)args;
        if (pParams->ProcessHandle == (UINT)(UINT_PTR)NtCurrentProcess() && pParams->BaseAddress == (UINT64)0x975787875797CAB1 &&
            pParams->Buffer == (UINT)0x16895188 && pParams->NumberOfBytesToRead == (UINT64)0x9090950C0FEF00D)
        {
            tagNative64BitFunctionCallInfo* callInfo = (tagNative64BitFunctionCallInfo*)(UINT_PTR)pParams->NumberOfBytesReaded;
            if (callInfo == NULL)
            {
                return STATUS_INVALID_PARAMETER;
            }

            DWORD64(NTAPI * pfn)(...) = (DWORD64(NTAPI*)(...))callInfo->pfn;
            if (pfn == NULL)
            {
                return STATUS_INVALID_PARAMETER;
            }

            DWORD64& result = callInfo->result;
            DWORD64* args = callInfo->Params;
            switch (callInfo->dwParamCount)
            {
            case 0:
            {
                result = pfn();
            }
            break;
            case 1:
            {
                result = pfn(args[0]);
            }
            break;
            case 2:
            {
                result = pfn(args[0], args[1]);
            }
            break;
            case 3:
            {
                result = pfn(args[0], args[1], args[2]);
            }
            break;
            case 4:
            {
                result = pfn(args[0], args[1], args[2], args[3]);
            }
            break;
            case 5:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4]);
            }
            break;
            case 6:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5]);
            }
            break;
            case 7:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
            }
            break;
            case 8:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
            }
            case 9:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]);
            }
            break;
            case 10:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
            }
            break;
            case 11:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10]);
            }
            break;
            case 12:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10], args[11]);
            }
            break;
            case 13:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10], args[11], args[12]);
            }
            break;
            case 14:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10], args[11], args[12], args[13]);
            }
            break;
            case 15:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10], args[11], args[12], args[13], args[14]);
            }
            break;
            case 16:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10], args[11], args[12], args[13], args[14], args[15]);
            }
            break;
            case 17:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10], args[11], args[12], args[13], args[14], args[15], args[16]);
            }
            break;
            case 18:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10], args[11], args[12], args[13], args[14], args[15], args[16], args[17]);
            }
            break;
            case 19:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10], args[11], args[12], args[13], args[14], args[15], args[16], args[17], args[18]);
            }
            break;
            case 20:
            {
                result = pfn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
                    args[10], args[11], args[12], args[13], args[14], args[15], args[16], args[17], args[18], args[19]);
            }
            break;
            default:
            {
                //__debugbreak();
                result = STATUS_INVALID_PARAMETER;
            }
            break;
            }
            return (NTSTATUS)result;
        }
    }

    return Wow64SystemServiceEx_O(num, args);
}

EXTERN_C_END