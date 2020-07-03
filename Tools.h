// Tools.h: interface for the Tools class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_TOOLS_H__D1BBB939_AF86_4F69_8AC2_06136238E951__INCLUDED_)
#define AFX_TOOLS_H__D1BBB939_AF86_4F69_8AC2_06136238E951__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

DWORD GetProcessModuleBaseAddr(DWORD dwProcessId);
DWORD GetProcessModuleSize(DWORD dwProcessId);
void XorEncryptAAA(char* p_data,DWORD EncryptSize);
void XorDecodeAAA(char* p_data,DWORD EncryptSize);

	

void __cdecl OutputDebugStringF(const char *format, ...);
#ifdef _DEBUG  
#define DbgPrintf   OutputDebugStringF  
#else  
#define DbgPrintf  
#endif

#endif // !defined(AFX_TOOLS_H__D1BBB939_AF86_4F69_8AC2_06136238E951__INCLUDED_)
