#pragma once

NTSTATUS(NTAPI* _NtWow64ReadVirtualMemory64)(IN HANDLE ProcessHandle, IN PVOID64 BaseAddress, OUT PVOID Buffer, IN UINT64 NumberOfBytesToRead, OUT PUINT64 NumberOfBytesReaded);
NTSTATUS(NTAPI* _NtReadVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN SIZE_T BufferSize, OUT PSIZE_T NumberOfBytesRead OPTIONAL);
NTSTATUS(NTAPI* _NtQueryInformationProcess64)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);

HANDLE cur_process;
HMODULE hmod_wow64ext_only_mapped;
DWORD64 hmod_ntdll64;
HMODULE hmod_ntdll64_only_mapped;