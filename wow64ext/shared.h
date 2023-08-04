#pragma once

struct tagNative64BitFunctionCallInfo
{
    DWORD64 pfn;
    DWORD dwParamCount;
    DWORD64 Params[20];
    DWORD64 result;
};