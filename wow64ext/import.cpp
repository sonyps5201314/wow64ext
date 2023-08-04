#pragma once

NTSTATUS(NTAPI* _NtReadVirtualMemory64)(IN HANDLE ProcessHandle, IN PVOID64 BaseAddress, OUT PVOID Buffer, IN UINT64 NumberOfBytesToRead, OUT PUINT64 NumberOfBytesReaded);
NTSTATUS(NTAPI* _NtQueryInformationProcess64)(IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);

HMODULE hmod_wow64ext_only_mapped;
DWORD64 hmod_ntdll64;
HMODULE hmod_ntdll64_only_mapped;