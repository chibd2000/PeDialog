// PeDialog.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"
#include "Tools.h"
#include "Petools.h"
#include<STDIO.H>
#include<STDLIB.H>
#include<commctrl.h>
#include<commdlg.h>	
#include<Tlhelp32.h>			
#pragma comment(lib,"comctl32.lib")				

HINSTANCE hAppHinstance;
TCHAR* pFileStr;

BOOL CALLBACK DialogProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK AboutProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeSegmentProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
void InitModuleRow(HWND hwndDlg, DWORD dwProcessPid);
void InitProcessRow(HWND hwndDlg);
void InitProcessColumn(HWND hwndDlg);
void InitModuleColumn(HWND hwndDlg);
void InitPeHeader(HWND hwndDlg,TCHAR szFilePath[]);


int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
 	// TODO: Place code here.
	INITCOMMONCONTROLSEX icex;				
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);				
	icex.dwICC = ICC_WIN95_CLASSES;				
	InitCommonControlsEx(&icex);				

	hAppHinstance = hInstance;
	DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_MAIN),NULL,DialogProc);
	return 0;
}

void InitProcessColumn(HWND hwndDlg){
	LV_COLUMN lv;															
	HWND hListProcess;

	//初始化								
	memset(&lv,0,sizeof(LV_COLUMN));
	
	//获取IDC_LIST_PROCESS句柄								
	hListProcess = GetDlgItem(hwndDlg,IDC_LIST_PROCESS);
	
	//设置整行选中								
	SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);								
	
	//第一列								
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;								
	lv.pszText = TEXT("进程");				//列标题				
	lv.cx = 130;								//列宽
	lv.iSubItem = 0;								
	//ListView_InsertColumn(hListProcess, 0, &lv);								
	SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	
	//第二列								
	lv.pszText = TEXT("PID");								
	lv.cx = 70;								
	lv.iSubItem = 1;
	//ListView_InsertColumn(hListProcess, 1, &lv);								
	SendMessage(hListProcess,LVM_INSERTCOLUMN,1,(DWORD)&lv);								
	
	//第三列								
	lv.pszText = TEXT("镜像基址");								
	lv.cx = 100;								
	lv.iSubItem = 2;								
	ListView_InsertColumn(hListProcess, 2, &lv);								
	
	//第四列								
	lv.pszText = TEXT("镜像大小");								
	lv.cx = 100;								
	lv.iSubItem = 3;								
	ListView_InsertColumn(hListProcess, 3, &lv);
}

void InitProcessRow(HWND hwndDlg){
	HWND hListProcess;
	LV_ITEM vitem;
	
	hListProcess = GetDlgItem(hwndDlg,IDC_LIST_PROCESS);
	//初始化						
	memset(&vitem,0,sizeof(LV_ITEM));											
	
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hProcessSanp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSanp == INVALID_HANDLE_VALUE)
	{
		DbgPrintf("Error Get the Process SnapShot, error is %d\n",GetLastError());
		return;
	}
	
	
	TCHAR szBuffer[0x20];
	memset(szBuffer,0,0x20);

	BOOL bMoreProcess = Process32First(hProcessSanp, &pe32);
	DbgPrintf("%s",TEXT(pe32.szExeFile));

	vitem.mask = LVIF_TEXT;

	vitem.pszText = TEXT(itoa(pe32.th32ProcessID,szBuffer,10));												
	vitem.iSubItem = 1;
	ListView_SetItem(hListProcess, &vitem);						
	
	vitem.pszText = TEXT(itoa(GetProcessModuleBaseAddr(pe32.th32ProcessID),szBuffer,16));												
	vitem.iSubItem = 2;
	ListView_SetItem(hListProcess, &vitem);						
	
	vitem.pszText = TEXT(itoa(GetProcessModuleSize(pe32.th32ProcessID),szBuffer,16));												
	vitem.iSubItem = 3;						
	ListView_SetItem(hListProcess, &vitem);	
	
	while (bMoreProcess)
	{
		//DbgPrintf("Process Name: %s\t\tProcess ID: %d\t\tProcess BaseAddr: %d\t\tProcess Size: %d\n", pe32.szExeFile, pe32.th32ProcessID,GetProcessModuleBaseAddr(pe32.th32ProcessID),GetProcessModuleSize(pe32.th32ProcessID));
		bMoreProcess = Process32Next(hProcessSanp, &pe32);

		vitem.pszText = pe32.szExeFile;
		vitem.iSubItem = 0;
		//ListView_InsertItem(hListProcess, &vitem);						
		SendMessage(hListProcess, LVM_INSERTITEM,0,(DWORD)&vitem);						
		
		vitem.pszText = TEXT(itoa(pe32.th32ProcessID,szBuffer,10));												
		vitem.iSubItem = 1;
		ListView_SetItem(hListProcess, &vitem);						
		
		vitem.pszText = TEXT(itoa(GetProcessModuleBaseAddr(pe32.th32ProcessID),szBuffer,16));												
		vitem.iSubItem = 2;
		ListView_SetItem(hListProcess, &vitem);						
		
		vitem.pszText = TEXT(itoa(GetProcessModuleSize(pe32.th32ProcessID),szBuffer,16));												
		vitem.iSubItem = 3;						
		ListView_SetItem(hListProcess, &vitem);	
		
	}	
	// 4. 关闭句柄并退出函数
	CloseHandle(hProcessSanp);
}

void InitModuleColumn(HWND hwndDlg){
	LV_COLUMN lv;															
	HWND hListModule;
	
	//初始化								
	memset(&lv,0,sizeof(LV_COLUMN));
	
	//获取IDC_LIST_PROCESS句柄								
	hListModule = GetDlgItem(hwndDlg,IDC_LIST_MODULE);
	
	//设置整行选中								
	SendMessage(hListModule,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);								
	
	//第一列								
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;								
	lv.pszText = TEXT("模块名称");				//列标题				
	lv.cx = 200;								//列宽
	lv.iSubItem = 0;								
	//ListView_InsertColumn(hListProcess, 0, &lv);								
	SendMessage(hListModule,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	
	//第二列								
	lv.pszText = TEXT("模块位置");								
	lv.cx = 200;								
	lv.iSubItem = 1;
	//ListView_InsertColumn(hListProcess, 1, &lv);								
	SendMessage(hListModule,LVM_INSERTCOLUMN,1,(DWORD)&lv);
}

void InitModuleRow(HWND hwndDlg,DWORD dwProcessPid){
	LV_ITEM vitem;
	memset(&vitem,0,sizeof(LV_ITEM));					

	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32 = {sizeof(MODULEENTRY32)};

	HWND hListModule = GetDlgItem(hwndDlg, IDC_LIST_MODULE);

	// 1. 创建一个模块相关的快照句柄
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,dwProcessPid);
	if (hModuleSnap == INVALID_HANDLE_VALUE){
		DbgPrintf("EnumModules's CreateToolhelp32Snapshot Failed, error %d",GetLastError());
		return;
	}
	
	// 2. 通过模块快照句柄获取第一个模块信息
	if (!Module32First(hModuleSnap, &me32)) {
		DbgPrintf("Module32First Failed");
		CloseHandle(hModuleSnap);
		return;
	}

	TCHAR szbuffer[0x20];
	
	//每次遍历指定进程的模块的时候先清空listview的数据
	SendMessage(hListModule, LVM_DELETEALLITEMS, 0, 0);

	// 3. 循环获取模块信息
	vitem.mask = LVIF_TEXT;
	
	do {
		vitem.pszText = TEXT(me32.szModule);												
		vitem.iSubItem = 0;
		//ListView_InsertItem(hListProcess, &vitem);						
		SendMessage(hListModule, LVM_INSERTITEM,0,(DWORD)&vitem);						
		
		vitem.pszText = TEXT(itoa((DWORD)me32.modBaseAddr,szbuffer,16));												
		vitem.iSubItem = 1;
		ListView_SetItem(hListModule, &vitem);												

		//DbgPrintf("模块基址:%x,模块大小：%x,模块名称:%s\n",me32.modBaseAddr,me32.modBaseSize,me32.szModule);
	} while (Module32Next(hModuleSnap, &me32));
	

	// 4. 关闭句柄并退出函数
	CloseHandle(hModuleSnap);
}



void EnumModules(HWND hwndDlg, WPARAM wParam,LPARAM lParam){
	DWORD dwRowId;
	TCHAR szPid[0x20];
	LV_ITEM lv;
	HWND hListProcess;

	hListProcess = GetDlgItem(hwndDlg, IDC_LIST_PROCESS);

	memset(&lv, 0, sizeof(LV_ITEM));
	memset(szPid, 0, 0x20);

	//hModule = GetModuleHandle(NULL);
	//OutputDebugStringF("%d",(DWORD)hModule);

	dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);

	if(dwRowId == -1){
		MessageBox(NULL,"please choose process","Warn:",MB_OK);
		return;
	}

	lv.iSubItem = 1; // column
	lv.pszText = szPid; // buffer
	lv.cchTextMax = 0x20; // size
	SendMessage(hListProcess,LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);
	MessageBox(NULL,szPid,"PROCESS PID",MB_OK);
	
	InitModuleRow(hwndDlg,atoi(szPid));
	
	//DbgPrintf("%d",atoi(szPid));
	
}

void InitPeHeader(HWND hwndDlg,TCHAR* szFilePath){
	PVOID pFileBuffer = NULL;
	DWORD dwBufferLength = 0;
	MyReadFile(&pFileBuffer,&dwBufferLength,szFilePath);
	DbgPrintf("%x, %d",pFileBuffer, dwBufferLength);
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PVOID AddressOfNamesTable = NULL;
	DWORD AddressOfNameOrdinalsNumber = NULL;
	PVOID FunctionOfAddress = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);

	//判断是否是有效的MZ标志，也就是0x5A4D，取前四个字节
    if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)    
    {   
        DbgPrintf("不是有效的MZ标志\n");
        free(pFileBuffer);
        return;
    }   


	TCHAR szBuffer[0x20];
	HWND EDIT_AddressOfEntryPoint;
	HWND EDIT_ImageBase;
	HWND EDIT_SizeOfImage;
	HWND EDIT_BaseOfCode;
	HWND EDIT_BaseOfData;
	HWND EDIT_SectionAlignment;
	HWND EDIT_FileAlignment;
	HWND EDIT_Stand;
	HWND EDIT_SubSystem;
	HWND EDIT_NumberOfSections;
	HWND EDIT_TimeDateStamp;
	HWND EDIT_SizeOfHeaders;
	HWND EDIT_CheckSum;
	HWND EDIT_OptionHeader;
	HWND EDIT_SizeOfDirectory;
	HWND EDIT_Characteristics;



	EDIT_AddressOfEntryPoint = GetDlgItem(hwndDlg,IDC_EDIT1);
	SetDlgItemText(hwndDlg,IDC_EDIT1,itoa(pOptionHeader->AddressOfEntryPoint,szBuffer,16));

	EDIT_ImageBase = GetDlgItem(hwndDlg,IDC_EDIT2);
	SetDlgItemText(hwndDlg,IDC_EDIT2,itoa(pOptionHeader->ImageBase,szBuffer,16));

	EDIT_SizeOfImage = GetDlgItem(hwndDlg,IDC_EDIT3);
	SetDlgItemText(hwndDlg,IDC_EDIT3,itoa(pOptionHeader->SizeOfImage,szBuffer,16));

	EDIT_BaseOfCode = GetDlgItem(hwndDlg,IDC_EDIT4);
	SetDlgItemText(hwndDlg,IDC_EDIT4,itoa(pOptionHeader->BaseOfCode,szBuffer,16));

	EDIT_BaseOfData = GetDlgItem(hwndDlg,IDC_EDIT5);
	SetDlgItemText(hwndDlg,IDC_EDIT5,itoa(pOptionHeader->BaseOfData,szBuffer,16));

	EDIT_SectionAlignment = GetDlgItem(hwndDlg,IDC_EDIT6);
	SetDlgItemText(hwndDlg,IDC_EDIT6,itoa(pOptionHeader->SectionAlignment,szBuffer,16));
	
	EDIT_FileAlignment = GetDlgItem(hwndDlg,IDC_EDIT7);
	SetDlgItemText(hwndDlg,IDC_EDIT7,itoa(pOptionHeader->FileAlignment,szBuffer,16));

	EDIT_Stand = GetDlgItem(hwndDlg,IDC_EDIT8);
	SetDlgItemText(hwndDlg,IDC_EDIT8,CharUpper(itoa(pOptionHeader->Magic,szBuffer,16)));

	EDIT_SubSystem = GetDlgItem(hwndDlg,IDC_EDIT9);
	SetDlgItemText(hwndDlg,IDC_EDIT9,itoa(pOptionHeader->Subsystem,szBuffer,16));

	EDIT_NumberOfSections = GetDlgItem(hwndDlg,IDC_EDIT12);
	SetDlgItemText(hwndDlg,IDC_EDIT12,itoa(pPEHeader->NumberOfSections,szBuffer,16));

	EDIT_TimeDateStamp = GetDlgItem(hwndDlg,IDC_EDIT13);
	SetDlgItemText(hwndDlg,IDC_EDIT13,CharUpper(itoa(pPEHeader->TimeDateStamp,szBuffer,16)));

	EDIT_SizeOfHeaders = GetDlgItem(hwndDlg,IDC_EDIT10);
	SetDlgItemText(hwndDlg,IDC_EDIT10,itoa(pOptionHeader->SizeOfHeaders,szBuffer,16));

	EDIT_CheckSum = GetDlgItem(hwndDlg,IDC_EDIT11);
	SetDlgItemText(hwndDlg,IDC_EDIT11,itoa(pOptionHeader->CheckSum,szBuffer,16));

	EDIT_Characteristics = GetDlgItem(hwndDlg,IDC_EDIT14);
	SetDlgItemText(hwndDlg,IDC_EDIT14,itoa(pPEHeader->Characteristics,szBuffer,16));

	EDIT_OptionHeader = GetDlgItem(hwndDlg,IDC_EDIT15);
	SetDlgItemText(hwndDlg,IDC_EDIT15,CharUpper(itoa(pPEHeader->SizeOfOptionalHeader,szBuffer,16)));

	EDIT_SizeOfDirectory = GetDlgItem(hwndDlg,IDC_EDIT16);
	SetDlgItemText(hwndDlg,IDC_EDIT16,itoa(pOptionHeader->NumberOfRvaAndSizes,szBuffer,16));
}

void InitSegmentColumn(HWND hwndDlg){

}

void InitSegmentRow(HWND hwndDlg){
	
}

BOOL CALLBACK DialogProc(HWND hwndDlg,UINT uMsg,WPARAM wParam,LPARAM lParam){
	
	OPENFILENAME ofn;
	TCHAR szFileBuffer[0x20];
		
    switch(uMsg)                                
    {         
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
    case  WM_INITDIALOG : 	
		InitProcessColumn(hwndDlg);
		InitProcessRow(hwndDlg);
		InitModuleColumn(hwndDlg);
		return TRUE;

    case WM_COMMAND :  // 0x111                               
        switch (LOWORD (wParam))
		{
		case IDC_BUTTON_ABOUT :    
			{
				DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_ABOUT),hwndDlg,AboutProc);
				return TRUE;
			}                        
		case IDC_BUTTON_EXIT:                            
			EndDialog(hwndDlg, 0);                        
			return TRUE;     
		case IDC_BUTTON_PE:
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hwndDlg;
			ofn.lpstrFile = szFileBuffer;
			ofn.nMaxFile = sizeof(szFileBuffer);
			ofn.lpstrFilter = "*.exe;*.dll;*.scr;*.drv;*.sys";
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFile = MAX_PATH;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
			
			if (GetOpenFileName(&ofn)) {
				DbgPrintf("%s",ofn.lpstrFile);
				pFileStr = ofn.lpstrFile;
				DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE),hwndDlg,PeProc);
			}
			
			return TRUE;

        }

	case WM_NOTIFY:
		NMHDR* pNMHDR = (NMHDR*)lParam;
		if(wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK){
			EnumModules(hwndDlg,wParam,lParam);
			return TRUE;
		}
        break ;                            
    }                             
    
    return FALSE ;                                
} 

BOOL CALLBACK AboutProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch (uMsg)
	{
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}   

BOOL CALLBACK PeProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch (uMsg)
	{
	case WM_INITDIALOG:
		InitPeHeader(hwndDlg,pFileStr);
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD (wParam))
		{
		case IDC_BUTTON_PE_CLOSE:
			EndDialog(hwndDlg,0);
			return TRUE;
		case IDC_BUTTON_PE_Segment:
			DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE_SEGMENT),hwndDlg,PeSegmentProc);// BOOL CALLBACK PeSegmentProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam)
			return TRUE;
		case IDC_BUTTON_PE_DIRE:
			return TRUE;
		}
		return TRUE;
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}   

BOOL CALLBACK PeSegmentProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch (uMsg)
	{

	case WM_INITDIALOG:
		
	
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}


