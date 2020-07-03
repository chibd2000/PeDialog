// Tools.cpp: implementation of the Tools class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Tools.h"
#include <STDIO.H>
#include<Tlhelp32.h>
#define KEY 0x86

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
void __cdecl OutputDebugStringF(const char *format, ...)  
{  
    va_list vlArgs;  
    char* strBuffer = (char*)GlobalAlloc(GPTR, 4096);  
    va_start(vlArgs, format);  
    _vsnprintf(strBuffer, 4096 - 1, format, vlArgs);  
    va_end(vlArgs);  
    strcat(strBuffer, "\n");  
    OutputDebugStringA(strBuffer);  
    GlobalFree(strBuffer);  
    return;  
}  

DWORD GetProcessModuleBaseAddr(DWORD dwProcessId){
	DWORD ProcessImageBase;
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    // 获取指定进程全部模块的快照
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
    if (INVALID_HANDLE_VALUE == hModuleSnap)
    {
        DbgPrintf("GetProcessModuleBaseAddr's CreateToolhelp32Snapshot erorr,error is %d",GetLastError());
		CloseHandle(hModuleSnap);
        return 0;
    }
    // 获取快照中第一条信息
    BOOL bRet = Module32First(hModuleSnap, &me32);
    if (bRet)
    {
        // 获取加载基址
        ProcessImageBase = (DWORD)me32.modBaseAddr;
    }
    // 关闭句柄
    CloseHandle(hModuleSnap);
    return ProcessImageBase;
}

DWORD GetProcessModuleSize(DWORD dwProcessId){
	//DbgPrintf("dwprocessId: %d\n",dwProcessId);

	DWORD ProcessImageBase;
    MODULEENTRY32 me32 = { 0 };
    me32.dwSize = sizeof(MODULEENTRY32);
    // 获取指定进程全部模块的快照
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
    if (INVALID_HANDLE_VALUE == hModuleSnap)
    {
        DbgPrintf("GetProcessModuleSize's CreateToolhelp32Snapshot erorr,error is %d",GetLastError());
		CloseHandle(hModuleSnap);
        return 0;
    }
    // 获取快照中第一条信息
    BOOL bRet = Module32First(hModuleSnap, &me32);
    if (bRet)
    {
        // 获取加载基址
        ProcessImageBase = me32.modBaseSize;
    }
    // 关闭句柄
    CloseHandle(hModuleSnap);
    return ProcessImageBase;
}


void XorEncryptAAA(char* p_data,DWORD EncryptSize)
{
    for(DWORD i = 0; i < EncryptSize; i++)
    {
		p_data[i] = p_data[i] ^ KEY;
    }
}

void XorDecodeAAA(char* p_data,DWORD DecodeSize)
{   
    for(DWORD i = 0; i < DecodeSize; i++)
    {
		p_data[i] = p_data[i] ^ KEY;
    }	
}