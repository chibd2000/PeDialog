// Petools.h: interface for the Petools class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PETOOLS_H__E70A34E2_D90B_4345_AB6E_9FE4CF7FC116__INCLUDED_)
#define AFX_PETOOLS_H__E70A34E2_D90B_4345_AB6E_9FE4CF7FC116__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

DWORD CopyFileBufferToImageBuffer(PVOID pFileBuffer,PVOID pImageBuffer);		
DWORD CopyImageBufferToNewBuffer(PVOID pImageBuffer,PVOID* pNewBuffer);
void FileBufferToAddShellcode(PVOID pFileBuffer);
void AddNewSection(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer);
void ExpandSection(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer);
void printfPE(PVOID pFileBuffer);
void PrintRelocation(PVOID pFileBuffer); //打印重定位表
DWORD FOA_TO_RVA(PVOID FileAddress, DWORD FOA,PDWORD pRVA);
DWORD RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA);
void MyReadFile(PVOID* pFileBuffer,PDWORD BufferLenth, TCHAR* szFilePath);
void MyWriteFile(PVOID pMemBuffer,DWORD BufferLenth);
int GetBufferLength(PVOID Buffer);
void PrintfImportTable(PVOID pFileBuffer); //打印导入表
void MoveExportTable(PVOID pFileBuffer, PDWORD OldBufferSize,PVOID* pNewBuffer); //移动导出表
void MoveRelocationTable(PVOID pFileBuffer, PDWORD OldBufferSize,PVOID* pNewBuffer); //移动重定位表
void PrintBindImportTable(PVOID pFileBuffer); //打印绑定导入表
void MoveAndInjectImportTable(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer); //移动导入表、并且尝试进行注入
void printfResourceTable(PVOID pFileBuffer);

#endif // !defined(AFX_PETOOLS_H__E70A34E2_D90B_4345_AB6E_9FE4CF7FC116__INCLUDED_)
