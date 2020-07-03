// PeDialog.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"
#include "Tools.h"
#include "Petools.h"
#include<commctrl.h>
#include<commdlg.h>	
#include<Tlhelp32.h>
			
#pragma comment(lib,"comctl32.lib")				

HINSTANCE hAppHinstance;
TCHAR* pFileStr;
HWND hShellEdit1;
HWND hShellEdit2;
	

BOOL CALLBACK DialogProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK AboutProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeSegmentProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeDireProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeDireExportProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeDireImportProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeDireResourceProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeDireRelocationProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeDireIATProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeDireBoundProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PeShellProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam);
void InitModuleRow(HWND hwndDlg, DWORD dwProcessPid);
void InitProcessRow(HWND hwndDlg);
void InitProcessColumn(HWND hwndDlg);
void InitModuleColumn(HWND hwndDlg);
void InitPeHeader(HWND hwndDlg);
void InitDireTable(HWND hwndDlg);
void InitExportTable(HWND hwndDlg);
void InitImportTable(HWND hwndDlg);
void InitResourceTable(HWND hwndDlg);
void InitRelocationTable(HWND hwndDlg);
void InitBoundTable(HWND hwndDlg);
void InitIATTable(HWND hwndDlg);
void AddWaterShell();

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

		vitem.pszText = TEXT(pe32.szExeFile);
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
	//MessageBox(NULL,szPid,"PROCESS PID",MB_OK);
	
	InitModuleRow(hwndDlg,atoi(szPid));
	
	//DbgPrintf("%d",atoi(szPid));
	
}

void InitPeHeader(HWND hwndDlg){
	PVOID pFileBuffer = NULL;
	DWORD dwBufferLength = 0;
	MyReadFile(&pFileBuffer,&dwBufferLength,pFileStr);
	DbgPrintf("%x, %d",pFileBuffer, dwBufferLength);
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

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
	LV_COLUMN lv;															
	HWND hListPeSegment;
	
	//初始化								
	memset(&lv,0,sizeof(LV_COLUMN));
	
	//获取IDC_LIST_PROCESS句柄								
	hListPeSegment = GetDlgItem(hwndDlg,IDC_LIST_PE_SEGMENT);
	
	//设置整行选中								
	SendMessage(hListPeSegment,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);								
	
	//第一列								
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;								
	lv.pszText = TEXT("名称");				//列标题				
	lv.cx = 80;								//列宽
	lv.iSubItem = 0;								
	//ListView_InsertColumn(hListProcess, 0, &lv);								
	SendMessage(hListPeSegment,LVM_INSERTCOLUMN,0,(DWORD)&lv);

	//第二列								
	lv.pszText = TEXT("VOffset");								
	lv.cx = 80;								
	lv.iSubItem = 1;
	//ListView_InsertColumn(hListProcess, 1, &lv);								
	SendMessage(hListPeSegment,LVM_INSERTCOLUMN,1,(DWORD)&lv);
	
	//第二列								
	lv.pszText = TEXT("VSize");								
	lv.cx = 80;								
	lv.iSubItem = 2;
	//ListView_InsertColumn(hListProcess, 1, &lv);								
	SendMessage(hListPeSegment,LVM_INSERTCOLUMN,2,(DWORD)&lv);

	lv.pszText = TEXT("ROffset");								
	lv.cx = 80;								
	lv.iSubItem = 3;
	//ListView_InsertColumn(hListProcess, 1, &lv);								
	SendMessage(hListPeSegment,LVM_INSERTCOLUMN,3,(DWORD)&lv);

	lv.pszText = TEXT("RSize");								
	lv.cx = 80;								
	lv.iSubItem = 4;
	//ListView_InsertColumn(hListProcess, 1, &lv);								
	SendMessage(hListPeSegment,LVM_INSERTCOLUMN,4,(DWORD)&lv);

	lv.pszText = TEXT("标志");								
	lv.cx = 80;								
	lv.iSubItem = 5;
	//ListView_InsertColumn(hListProcess, 1, &lv);								
	SendMessage(hListPeSegment,LVM_INSERTCOLUMN,5,(DWORD)&lv);

}

void InitSegmentRow(HWND hwndDlg){
	LV_ITEM vitem;
	memset(&vitem,0,sizeof(LV_ITEM));

	PVOID pFileBuffer = NULL;
	DWORD dwBufferLength = 0;
	MyReadFile(&pFileBuffer,&dwBufferLength,pFileStr);
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

	HWND hListPeSegment;

	hListPeSegment = GetDlgItem(hwndDlg,IDC_LIST_PE_SEGMENT);
    
	TCHAR SectionName[0x10] = {0};
	TCHAR szbuffer[0x20] = {0};
	vitem.mask = LVIF_TEXT;
    for(int i=0;i<pPEHeader->NumberOfSections;i++){
        strcpy(SectionName,(TCHAR*)pSectionHeader[i].Name);
		DbgPrintf("--------------------\n");
        DbgPrintf("_IMAGE_SECTION_HEADER->Name:%s\n",SectionName);
        DbgPrintf("_IMAGE_SECTION_HEADER->VirtualSize:0x%x\n",pSectionHeader[i].Misc.VirtualSize);
        DbgPrintf("_IMAGE_SECTION_HEADER->VirtualAddress:0x%x\n",pSectionHeader[i].VirtualAddress);
        DbgPrintf("_IMAGE_SECTION_HEADER->SizeOfRawData:0x%x\n",pSectionHeader[i].SizeOfRawData);
        DbgPrintf("_IMAGE_SECTION_HEADER->PointerToRawData:0x%x\n",pSectionHeader[i].PointerToRawData);
        DbgPrintf("_IMAGE_SECTION_HEADER->Characteristics:0x%x\n",pSectionHeader[i].Characteristics);


		vitem.pszText = TEXT(SectionName);												
		vitem.iSubItem = 0;
		//ListView_InsertItem(hListProcess, &vitem);						
		SendMessage(hListPeSegment, LVM_INSERTITEM,0,(DWORD)&vitem);						
		

		vitem.pszText = TEXT(itoa(pSectionHeader[i].VirtualAddress,szbuffer,16));												
		vitem.iSubItem = 1;
		ListView_SetItem(hListPeSegment, &vitem);


		vitem.pszText = TEXT(itoa(pSectionHeader[i].Misc.VirtualSize,szbuffer,16));												
		vitem.iSubItem = 2;
		ListView_SetItem(hListPeSegment, &vitem);


		vitem.pszText = TEXT(itoa(pSectionHeader[i].PointerToRawData,szbuffer,16));												
		vitem.iSubItem = 3;
		ListView_SetItem(hListPeSegment, &vitem);


		vitem.pszText = TEXT(itoa(pSectionHeader[i].SizeOfRawData,szbuffer,16));												
		vitem.iSubItem = 4;
		ListView_SetItem(hListPeSegment, &vitem);


		vitem.pszText = TEXT(itoa(pSectionHeader[i].Characteristics,szbuffer,16));												
		vitem.iSubItem = 5;
		ListView_SetItem(hListPeSegment, &vitem);
		
    }
}

void InitDireTable(HWND hwndDlg){
	TCHAR szbuffer[0x20] = {0};
	HWND EDIT_RVA_EXPORT;
	HWND EDIT_SIZE_EXPORT;
	
	HWND EDIT_RVA_IMPORT;
	HWND EDIT_SIZE_IMPORT;

	HWND EDIT_RVA_RESOURCE;
	HWND EDIT_SIZE_RESOURCE;
	
	HWND EDIT_RVA_RELOCATION;
	HWND EDIT_SIZE_RELOCATION;

	HWND EDIT_RVA_BOUND;
	HWND EDIT_SIZE_BOUND;

	HWND EDIT_RVA_IAT;
	HWND EDIT_SIZE_IAT;

	PVOID pFileBuffer = NULL;
	DWORD dwBufferLength = 0;
	MyReadFile(&pFileBuffer,&dwBufferLength,pFileStr);
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);

	EDIT_RVA_EXPORT = GetDlgItem(hwndDlg, IDC_EDIT_RVA_EXPORT);
	EDIT_SIZE_EXPORT = GetDlgItem(hwndDlg, IDC_EDIT_SIZE_EXPORT);

	SetDlgItemText(hwndDlg, IDC_EDIT_RVA_EXPORT,CharUpper(itoa(pOptionHeader->DataDirectory[0].VirtualAddress,szbuffer,16)));
	SetDlgItemText(hwndDlg, IDC_EDIT_SIZE_EXPORT,CharUpper(itoa(pOptionHeader->DataDirectory[0].Size,szbuffer,16)));

	EDIT_RVA_IMPORT = GetDlgItem(hwndDlg, IDC_EDIT_RVA_IMPORT);
	EDIT_SIZE_IMPORT = GetDlgItem(hwndDlg, IDC_EDIT_SIZE_IMPORT);

	SetDlgItemText(hwndDlg, IDC_EDIT_RVA_IMPORT,CharUpper(itoa(pOptionHeader->DataDirectory[1].VirtualAddress,szbuffer,16)));
	SetDlgItemText(hwndDlg, IDC_EDIT_SIZE_IMPORT,CharUpper(itoa(pOptionHeader->DataDirectory[1].Size,szbuffer,16)));

	EDIT_RVA_RESOURCE = GetDlgItem(hwndDlg, IDC_EDIT_RVA_RESOURCE);
	EDIT_SIZE_RESOURCE = GetDlgItem(hwndDlg, IDC_EDIT_SIZE_RESOURCE);
	SetDlgItemText(hwndDlg, IDC_EDIT_RVA_RESOURCE,CharUpper(itoa(pOptionHeader->DataDirectory[2].VirtualAddress,szbuffer,16)));
	SetDlgItemText(hwndDlg, IDC_EDIT_SIZE_RESOURCE,CharUpper(itoa(pOptionHeader->DataDirectory[2].Size,szbuffer,16)));

	EDIT_RVA_RELOCATION = GetDlgItem(hwndDlg, IDC_EDIT_RVA_RELOCATION);
	EDIT_SIZE_RELOCATION = GetDlgItem(hwndDlg, IDC_EDIT_SIZE_RELOCATION);
	SetDlgItemText(hwndDlg, IDC_EDIT_RVA_RELOCATION,CharUpper(itoa(pOptionHeader->DataDirectory[5].VirtualAddress,szbuffer,16)));
	SetDlgItemText(hwndDlg, IDC_EDIT_SIZE_RELOCATION,CharUpper(itoa(pOptionHeader->DataDirectory[5].Size,szbuffer,16)));

	EDIT_RVA_BOUND = GetDlgItem(hwndDlg, IDC_EDIT_RVA_BOUND);
	EDIT_SIZE_BOUND = GetDlgItem(hwndDlg, IDC_EDIT_SIZE_BOUND);
	SetDlgItemText(hwndDlg, IDC_EDIT_RVA_BOUND,CharUpper(itoa(pOptionHeader->DataDirectory[11].VirtualAddress,szbuffer,16)));
	SetDlgItemText(hwndDlg, IDC_EDIT_SIZE_BOUND,CharUpper(itoa(pOptionHeader->DataDirectory[11].Size,szbuffer,16)));

	EDIT_RVA_IAT = GetDlgItem(hwndDlg, IDC_EDIT_RVA_IAT);
	EDIT_SIZE_IAT = GetDlgItem(hwndDlg, IDC_EDIT_SIZE_IAT);
	SetDlgItemText(hwndDlg, IDC_EDIT_RVA_IAT,CharUpper(itoa(pOptionHeader->DataDirectory[12].VirtualAddress,szbuffer,16)));
	SetDlgItemText(hwndDlg, IDC_EDIT_SIZE_IAT,CharUpper(itoa(pOptionHeader->DataDirectory[12].Size,szbuffer,16)));

}

void InitExportTable(HWND hwndDlg){
	TCHAR szBuffer[2048];
	TCHAR szTempBuffer[0x64];
	memset(szBuffer, 0, 2048);
	memset(szTempBuffer, 0, 0x20);
	
	HWND hEditExport;

	PVOID pFileBuffer = NULL;
	DWORD dwBufferLength = 0;
	MyReadFile(&pFileBuffer,&dwBufferLength,pFileStr);

    PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	DWORD FOA = 0;
	DWORD RVA = 0;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);

	RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress,&FOA);
	
	//导出表的地址
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + FOA);

	hEditExport = GetDlgItem(hwndDlg, IDC_EDIT_EXPORT);

	//1、导出函数名称表来寻找导出函数地址表，AddressOfNames是一个指向函数名称的RVA地址，需要先转换为 文件偏移地址
	RVA_TO_FOA(pFileBuffer,pExportDirectory->AddressOfNames,&FOA);

	PVOID AddressOfNamesTable = NULL;
	DWORD AddressOfNameOrdinalsNumber = NULL;
	char FunName[10] = {0};

	//2、再加上pFileBuffer，转换为文件地址，得到函数名称存储的地方的首地址，当前的首地址是RVA，也需要进行RVA -> FOA转换
	AddressOfNamesTable = (PVOID)(*(PDWORD)((DWORD)pFileBuffer+(DWORD)FOA)); 
	RVA_TO_FOA(pFileBuffer,(DWORD)AddressOfNamesTable,&FOA); // // 导出函数名称表中函数名称的FOA

	AddressOfNamesTable = (PVOID)((DWORD)pFileBuffer + (DWORD)FOA); // 加上pFileBuffer位置就到了真正的函数名称表的地址

	//3、得到函数名称表的文件地址，每个函数的名称 占四个字节，然后进行遍历判断	
	for(DWORD j=0;j<pExportDirectory->NumberOfNames;j++){
		//(PDWORD)((DWORD)AddressOfNamesTable + 4*j);
		//获取当前函数名称表中的函数名称，然后循环判断
		//printf("this is my test:%s \n", (PVOID)((DWORD)AddressOfNamesTable));
		strcpy(FunName,(PCHAR)((DWORD)AddressOfNamesTable)); //这里+1 是最后一个字节为空字节 那么就为结束符
		if(0 == memcmp((PDWORD)((DWORD)AddressOfNamesTable),(PDWORD)FunName,strlen(FunName))){			
			//4、找到序号表AddressOfNameOrdinals下标所对应的的值，序号表中每个成员占2字节 word类型
			RVA_TO_FOA(pFileBuffer,pExportDirectory->AddressOfNameOrdinals,&FOA);
			AddressOfNameOrdinalsNumber = *(PWORD)((DWORD)FOA + (DWORD)pFileBuffer + (DWORD)j*2);
			//5、通过序号表中下标对用的值去导出函数地址表AddressOfFunctions中寻找 该值下标对应的值
			RVA_TO_FOA(pFileBuffer,pExportDirectory->AddressOfFunctions,&FOA);

			AddressOfNamesTable = (PVOID)((DWORD)AddressOfNamesTable + (DWORD)(strlen((PCHAR)AddressOfNamesTable)+1));

			wsprintf(szTempBuffer,"函数序号: %d\r\n函数名称为: %s\r\n导出函数地址表的地址为：0x%.8x\r\n\r\n--------------------------\r\n"
				,AddressOfNameOrdinalsNumber
				,FunName
				,*(PDWORD)(PVOID)((DWORD)FOA + (DWORD)pFileBuffer + AddressOfNameOrdinalsNumber*4)
				);
			
			//DbgPrintf("%s",szTempBuffer);
			//strcat(szBuffer,szTempBuffer);
			DbgPrintf("%s",szTempBuffer);
			//sprintf(szBuffer, "%s ", szTempBuffer);
			/*
			DbgPrintf("函数序号: %d\t",AddressOfNameOrdinalsNumber);
			DbgPrintf("函数名称为: %s\t",FunName);
			DbgPrintf("导出函数地址表的地址为：0x%.8x\n",*(PDWORD)(PVOID)((DWORD)FOA + (DWORD)pFileBuffer + AddressOfNameOrdinalsNumber*4));*/
		}
	}

	SetWindowText(hEditExport,szBuffer);
	//IDC_EDIT_EXPORT
}


void InitImportTable(HWND hwndDlg){
	TCHAR szBuffer[10000];
	TCHAR szTempBuffer[0x64];
	memset(szBuffer, 0, 10000);
	memset(szTempBuffer, 0, 0x64);

	HWND hEditImport;
	hEditImport = GetDlgItem(hwndDlg, IDC_EDIT_IMPORT);

	PVOID pFileBuffer = NULL;
	DWORD dwBufferLength = 0;
	MyReadFile(&pFileBuffer,&dwBufferLength,pFileStr);

    PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pIMPORT_DESCRIPTOR = NULL;
	PIMAGE_IMPORT_BY_NAME pImage_IMPORT_BY_NAME = NULL;

	TCHAR ImportTableDllName[0x20] = {0};
	TCHAR FunctionName[20] = {0};

	PDWORD OriginalFirstThunk_INT = NULL;
	PDWORD FirstThunk_IAT = NULL;

	DWORD RVA = 0;
	DWORD FOA = 0;
	DWORD Original = 0;
	
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);

	//获取导入表的位置
	RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[1].VirtualAddress,&FOA);
	
	//每个导入表的相关信息占20个字节
	pIMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + (DWORD)FOA);
	
	//这里可以进行while操作，这里while的判断依据为pIMPORT_DESCRIPTOR个数
	
	while(pIMPORT_DESCRIPTOR->FirstThunk && pIMPORT_DESCRIPTOR->OriginalFirstThunk){
		//这里打印的是INT表

		//获取当前导入表DLL的名字
		strcpy(ImportTableDllName,(PCHAR)((DWORD)pFileBuffer + (DWORD)pIMPORT_DESCRIPTOR->Name));
		strcat(szBuffer,ImportTableDllName);

		//OriginalFirstThunk转换FOA
		RVA_TO_FOA(pFileBuffer,pIMPORT_DESCRIPTOR->OriginalFirstThunk,&FOA);
		
		OriginalFirstThunk_INT = (PDWORD)((DWORD)pFileBuffer + (DWORD)FOA);
	
		while(*OriginalFirstThunk_INT){
			if((*OriginalFirstThunk_INT) & 0X80000000){
				//高位为1 则 除去最高位的值就是函数的导出序号
				Original = *OriginalFirstThunk_INT & 0xFFF;	//去除最高标志位。
				wsprintf(szTempBuffer,"\r\n按序号导入: %d \r\n",Original);

			}else{
				//高位不为1 则指向IMAGE_IMPORT_BY_NAME
				RVA_TO_FOA(pFileBuffer,*OriginalFirstThunk_INT,&FOA);
				pImage_IMPORT_BY_NAME = (PIMAGE_IMPORT_BY_NAME)FOA;
				strcpy(FunctionName,(PCHAR)((DWORD)pFileBuffer + (DWORD)&(pImage_IMPORT_BY_NAME->Name)));
				wsprintf(szTempBuffer,"\r\n按函数名导入 函数名为: %s\r\n",FunctionName);
			}

			OriginalFirstThunk_INT++;
			DbgPrintf("%s",szTempBuffer);
			strcat(szBuffer,szTempBuffer);
		}
		pIMPORT_DESCRIPTOR++;		
	}


	SetWindowText(hEditImport,szBuffer);
}
void InitResourceTable(HWND hwndDlg){

}
void InitRelocationTable(HWND hwndDlg){
	TCHAR szBuffer[10000];
	TCHAR szTempBuffer[128];
	memset(szBuffer, 0, 10000);
	memset(szTempBuffer, 0, 128);
	
	HWND hEditRelocation;
	hEditRelocation = GetDlgItem(hwndDlg, IDC_EDIT_RELOCATION);
	
	PVOID pFileBuffer = NULL;
	DWORD dwBufferLength = 0;
	MyReadFile(&pFileBuffer,&dwBufferLength,pFileStr);

	PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_BASE_RELOCATION pRelocationDirectory = NULL;
	DWORD FOA;
	DWORD RVA_Data;
	WORD reloData;
	int NumberOfRelocation = 0;
	PWORD Location = NULL;
	int i;
	
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);
	
	// _IMAGE_DATA_DIRECTORY中的指向重定位表的虚拟地址转换为FOA地址
	//printf("%x\n",pOptionHeader->DataDirectory[5].VirtualAddress);
	
	//printf("pRelocationDirectory_RVA:%x\n",pOptionHeader->DataDirectory[5].VirtualAddress);
	RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[5].VirtualAddress,&FOA);
	//printf("pRelocationDirectory_FOA:%x\n", FOA);
	
	pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer+(DWORD)FOA); //定位第一张重定位表 文件中的地址
	
	while(pRelocationDirectory->SizeOfBlock && pRelocationDirectory->VirtualAddress){		
		NumberOfRelocation = (pRelocationDirectory->SizeOfBlock - 8)/2;// 每个重定位块中的数据项的数量

		DbgPrintf("%d",NumberOfRelocation);
		
		Location = (PWORD)((DWORD)pRelocationDirectory + 8); // 加上8个字节
		
		for(i=0;i<NumberOfRelocation;i++){
			if(Location[i] >> 12 != 0){ //判断是否是垃圾数据
				// WORD类型的变量进行接收
				reloData = (Location[i] & 0xFFF); //这里进行与操作 只取4字节 二进制的后12位
				RVA_Data = pRelocationDirectory->VirtualAddress + reloData; //这个是RVA的地址
				RVA_TO_FOA(pFileBuffer,RVA_Data,&FOA);
				wsprintf(szTempBuffer,"第[%04X]项  数据项的数据为:[%04X]  数据属性为:[%X]  RVA的地址为:[%08X]  重定位的数据:[%08X]\r\n",i+1,reloData,(Location[i] >> 12),RVA_Data,*(PDWORD)((DWORD)pFileBuffer+FOA));
				DbgPrintf("第[%04X]项  数据项的数据为:[%04X]  数据属性为:[%X]  RVA的地址为:[%08X]  重定位的数据:[%08X]\n",i+1,reloData,(Location[i] >> 12),RVA_Data,*(PDWORD)((DWORD)pFileBuffer+FOA));
				strcat(szBuffer, szTempBuffer);
			}
		}
		pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationDirectory + (DWORD)pRelocationDirectory->SizeOfBlock); //上面的for循环完成之后，跳转到下个重定位块 继续如上的操作
	}

	SetWindowText(hEditRelocation, szBuffer);

}
void InitBoundTable(HWND hwndDlg){

	TCHAR szBuffer[10000];
	TCHAR szTempBuffer[0x64];
	memset(szBuffer, 0, 10000);
	memset(szTempBuffer, 0, 0x64);
	
	HWND hEditBound;
	hEditBound = GetDlgItem(hwndDlg, IDC_EDIT_BOUND);

	PVOID pFileBuffer = NULL;
	DWORD dwBufferLength = 0;
	MyReadFile(&pFileBuffer,&dwBufferLength,pFileStr);

	PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pIMAGE_BOUND_IMPORT_DESCRIPTOR = NULL;
	PIMAGE_BOUND_FORWARDER_REF pIMAGE_BOUND_FORWARDER_REF = NULL;
	
	char ModuleName[20] = {0};
	DWORD BOUNG_IMPORT_DESCRIPTOR_TEMP = 0;
	int i = 0;
	DWORD RVA = 0;
	DWORD FOA = 0;
	
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);
	
	RVA_TO_FOA(pFileBuffer, pOptionHeader->DataDirectory[11].VirtualAddress,&FOA);
	
	//保存第一个DESCRIPTOR的地址 后面加OffsetModuleName来进行使用
	BOUNG_IMPORT_DESCRIPTOR_TEMP = (DWORD)pFileBuffer+(DWORD)FOA;
	
	
	//开始进行打印操作
	pIMAGE_BOUND_IMPORT_DESCRIPTOR = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer+(DWORD)FOA);
	
	while (*(PDWORD)pIMAGE_BOUND_IMPORT_DESCRIPTOR)
	{
		printf("\n");
		strcpy(ModuleName, (PCHAR)((DWORD)BOUNG_IMPORT_DESCRIPTOR_TEMP + (DWORD)pIMAGE_BOUND_IMPORT_DESCRIPTOR->OffsetModuleName));
		/*printf("模块名称: %s \n",ModuleName);
		printf("模块的时间戳为: %x \n", pIMAGE_BOUND_IMPORT_DESCRIPTOR->TimeDateStamp);
		printf("当前模块引用的dll的数量为: %x\n",pIMAGE_BOUND_IMPORT_DESCRIPTOR->NumberOfModuleForwarderRefs);*/

		wsprintf(szTempBuffer,"模块名称:%s  模块的时间戳为: %x  当前模块引用的dll的数量为: %x\r\n"
			,ModuleName
			,pIMAGE_BOUND_IMPORT_DESCRIPTOR->TimeDateStamp
			,pIMAGE_BOUND_IMPORT_DESCRIPTOR->NumberOfModuleForwarderRefs);
		strcat(szBuffer, szTempBuffer);
		
		for(i=0;i<pIMAGE_BOUND_IMPORT_DESCRIPTOR->NumberOfModuleForwarderRefs;i++){
			pIMAGE_BOUND_IMPORT_DESCRIPTOR++;
			pIMAGE_BOUND_FORWARDER_REF = (PIMAGE_BOUND_FORWARDER_REF)pIMAGE_BOUND_IMPORT_DESCRIPTOR;
			strcpy(ModuleName, (PCHAR)((DWORD)BOUNG_IMPORT_DESCRIPTOR_TEMP + (DWORD)pIMAGE_BOUND_FORWARDER_REF->OffsetModuleName));
			/*printf("\t引用的模块名称: %s \n",ModuleName);
			printf("\t引用的模块的时间戳: %x\n", pIMAGE_BOUND_FORWARDER_REF->TimeDateStamp);*/

			wsprintf(szTempBuffer,"\t引用的模块名称:%s\r\n  \t引用的模块的时间戳为: %x \r\n ",ModuleName,pIMAGE_BOUND_FORWARDER_REF->TimeDateStamp);
			strcat(szBuffer, szTempBuffer);
		}
		
		pIMAGE_BOUND_IMPORT_DESCRIPTOR++;
	}

	SetWindowText(hEditBound,szBuffer);
}
void InitIATTable(HWND hwndDlg){
	TCHAR szBuffer[10000];
	TCHAR szTempBuffer[0x64];
	TCHAR FunctionName[0x64] = {0};
	memset(szBuffer, 0, 2048);
	memset(szTempBuffer, 0, 0x20);

	HWND hEditIAT;
	hEditIAT = GetDlgItem(hwndDlg, IDC_EDIT_IAT);
	
	PVOID pFileBuffer = NULL;
	DWORD dwBufferLength = 0;
	MyReadFile(&pFileBuffer,&dwBufferLength,pFileStr);
	
    PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pIMPORT_DESCRIPTOR = NULL;
	PIMAGE_IMPORT_BY_NAME pImage_IMPORT_BY_NAME = NULL;
	
	TCHAR ImportTableDllName[10] = {0};
	
	PDWORD OriginalFirstThunk_INT = NULL;
	PDWORD FirstThunk_IAT = NULL;
	
	DWORD RVA = 0;
	DWORD FOA = 0;
	DWORD Original = 0;
	
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);

	//继续如上操作进行打印操作
	//这里打印的是iat表

	//获取导入表的位置
	RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[1].VirtualAddress,&FOA);
	
	//每个导入表的相关信息占20个字节
	pIMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + (DWORD)FOA);

	while(pIMPORT_DESCRIPTOR->FirstThunk && pIMPORT_DESCRIPTOR->OriginalFirstThunk){

		RVA_TO_FOA(pFileBuffer,pIMPORT_DESCRIPTOR->FirstThunk,&FOA);
		
		FirstThunk_IAT = (PDWORD)((DWORD)pFileBuffer + (DWORD)FOA);
		
		while(*FirstThunk_IAT){
			if((*FirstThunk_IAT) & 0X80000000){
				//高位为1 则 除去最高位的值就是函数的导出序号
				Original = *FirstThunk_IAT & 0xFFF;	//去除最高标志位。
				wsprintf(szTempBuffer,"\r\n按序号导入: %d \r\n", Original);
			}else{
				//高位不为1 则指向IMAGE_IMPORT_BY_NAME
				RVA_TO_FOA(pFileBuffer,*FirstThunk_IAT,&FOA);
				pImage_IMPORT_BY_NAME = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + FOA);
				DbgPrintf("%s",pImage_IMPORT_BY_NAME->Name);
				strcpy(FunctionName,(PCHAR)pImage_IMPORT_BY_NAME->Name);
				wsprintf(szTempBuffer, "\r\n按函数名导入 函数名为: %s \r\n",FunctionName);
			}
			
			FirstThunk_IAT++;
			//DbgPrintf("%s",szTempBuffer);
			strcat(szBuffer,szTempBuffer);
		}
		pIMPORT_DESCRIPTOR++;
	}

	SetWindowText(hEditIAT, szBuffer);
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
		case IDC_BUTTON_ADD_SHELL:
			DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE_SHELL),hwndDlg,PeShellProc);
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
		InitPeHeader(hwndDlg);
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
			DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE_DIRE),hwndDlg,PeDireProc);//
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
		InitSegmentColumn(hwndDlg);
		InitSegmentRow(hwndDlg);
		return TRUE;
		

	
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}


BOOL CALLBACK PeDireProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	TCHAR szBuffer[0x20];
	switch (uMsg)
	{
		
	case WM_INITDIALOG:
		InitDireTable(hwndDlg);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD (wParam)){
		HWND hEdit;
		case IDC_BUTTON_EXPORT_TABLE:
			hEdit = GetDlgItem(hwndDlg, IDC_EDIT_RVA_EXPORT);
			GetWindowText(hEdit, szBuffer, 0x20);
			if(atoi(szBuffer) == 0){
				MessageBox(hwndDlg,TEXT("当前无导出表"),"提示:",MB_ICONWARNING);
				return TRUE;
			}
			DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE_DIRE_EXPORT),hwndDlg,PeDireExportProc);//
		
			return TRUE;


		case IDC_BUTTON_IMPORT_TABLE:
			hEdit = GetDlgItem(hwndDlg, IDC_EDIT_RVA_IMPORT);
			GetWindowText(hEdit, szBuffer, 0x20);
			if(atoi(szBuffer) == 0){
				MessageBox(hwndDlg,TEXT("当前无导入表"),"提示:",MB_ICONWARNING);
				return TRUE;
			}
			DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE_DIRE_IMPORT),hwndDlg,PeDireImportProc);//
			return TRUE;

		case IDC_BUTTON_RESOURCE_TABLE:
			hEdit = GetDlgItem(hwndDlg, IDC_EDIT_RVA_RESOURCE);
			GetWindowText(hEdit, szBuffer, 0x20);
			if(atoi(szBuffer) == 0){
				MessageBox(hwndDlg,TEXT("当前无资源表"),"提示:",MB_ICONWARNING);
				return TRUE;
			}
			DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE_DIRE_RESOURCE),hwndDlg,PeDireResourceProc);//
			return TRUE;

		case IDC_BUTTON_RELOCATION_TABLE:
			hEdit = GetDlgItem(hwndDlg, IDC_EDIT_RVA_RELOCATION);
			GetWindowText(hEdit, szBuffer, 0x20);
			if(atoi(szBuffer) == 0){
				MessageBox(hwndDlg,TEXT("当前无重定位表"),"提示:",MB_ICONWARNING);
				return TRUE;
			}
			DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE_DIRE_RELOCATION),hwndDlg,PeDireRelocationProc);//
			return TRUE;

		case IDC_BUTTON_BOUND_TABLE:
			hEdit = GetDlgItem(hwndDlg, IDC_EDIT_RVA_BOUND);
			GetWindowText(hEdit, szBuffer, 0x20);
			if(atoi(szBuffer) == 0){
				MessageBox(hwndDlg,TEXT("当前无绑定导入表"),"提示:",MB_ICONWARNING);
				return TRUE;
			}
			DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE_DIRE_BOUND),hwndDlg,PeDireBoundProc);//
			return TRUE;

		case IDC_BUTTON_IAT_TABLE:
			hEdit = GetDlgItem(hwndDlg, IDC_EDIT_RVA_IAT);
			GetWindowText(hEdit, szBuffer, 0x20);
			if(atoi(szBuffer) == 0){
				MessageBox(hwndDlg,TEXT("当前无IAT表"),"提示:",MB_ICONWARNING);
				return TRUE;
			}
			DialogBox(hAppHinstance,MAKEINTRESOURCE(IDD_DIALOG_PE_DIRE_IAT),hwndDlg,PeDireIATProc);//
			return TRUE;
		}
		return TRUE;
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}


BOOL CALLBACK PeDireExportProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch (uMsg)
	{
		
	case WM_INITDIALOG:
		InitExportTable(hwndDlg);
		return TRUE;
		
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}

BOOL CALLBACK PeDireImportProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch (uMsg)
	{
		
	case WM_INITDIALOG:
		InitImportTable(hwndDlg);
		return TRUE;
		
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}

BOOL CALLBACK PeDireResourceProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch (uMsg)
	{
		
	case WM_INITDIALOG:
		InitResourceTable(hwndDlg);
		return TRUE;
		
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}

BOOL CALLBACK PeDireRelocationProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch (uMsg)
	{
		
	case WM_INITDIALOG:
		InitRelocationTable(hwndDlg);
		return TRUE;
		
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}

BOOL CALLBACK PeDireIATProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch (uMsg)
	{
		
	case WM_INITDIALOG:
		InitIATTable(hwndDlg);
		return TRUE;
		
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}

BOOL CALLBACK PeDireBoundProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch (uMsg)
	{
		
	case WM_INITDIALOG:
		InitBoundTable(hwndDlg);
		return TRUE;
		
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}


BOOL CALLBACK PeShellProc(HWND hwndDlg,UINT uMsg, WPARAM wParam, LPARAM lParam){
	OPENFILENAME ofn;
	TCHAR szFileBuffer[MAX_PATH];
	memset(szFileBuffer, 0, MAX_PATH);

	switch (uMsg)
	{
		
	case WM_INITDIALOG:
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD (wParam)){
		case IDC_SHELL_BUTTON2:
			hShellEdit1 = GetDlgItem(hwndDlg, IDC_SHELL_EDIT1);
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hwndDlg;
			ofn.lpstrFile = szFileBuffer;
			ofn.nMaxFile = sizeof(szFileBuffer);
			ofn.lpstrFilter = "*.exe";
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFile = MAX_PATH;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
			
			if (GetOpenFileName(&ofn)) {
				SetWindowText(hShellEdit1, ofn.lpstrFile);
			}
			
			return TRUE;

		case IDC_SHELL_BUTTON3:
			hShellEdit2 = GetDlgItem(hwndDlg, IDC_SHELL_EDIT2);
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hwndDlg;
			ofn.lpstrFile = szFileBuffer;
			ofn.nMaxFile = sizeof(szFileBuffer);
			ofn.lpstrFilter = "*.exe";
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFile = MAX_PATH;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
			
			if (GetOpenFileName(&ofn)) {
				SetWindowText(hShellEdit2, ofn.lpstrFile);
			}

			return TRUE;
		case IDC_BUTTON1:
			//加壳操作
			AddWaterShell();
			return TRUE;

		}
		
		return TRUE;
		
	case WM_CLOSE:
		EndDialog(hwndDlg,0);
		return TRUE;
	}
	return FALSE;
}


void GetSrcFromShell(PVOID pFileBufferNewShell, PVOID* FileBufferNewSrc){
	PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

		
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBufferNewShell;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBufferNewShell+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);

	// (1) 定为到SHELL文件的最后一个节	
	*FileBufferNewSrc = (PVOID)((DWORD)pFileBufferNewShell + (PIMAGE_SECTION_HEADER)pSectionHeader[pPEHeader->NumberOfSections-1].PointerToRawData);
}




void AddWaterShell(){
	//--------------------------------------加密过程--------------------------------------
	TCHAR szBufferSrc[MAX_PATH];
	TCHAR szBufferShell[MAX_PATH];
	TCHAR* szBufferNew;

	memset(szBufferSrc,0,MAX_PATH);
	memset(szBufferShell,0,MAX_PATH);

	PVOID pFileBufferSrc = NULL;
	PVOID pFileBufferShell = NULL;

	PVOID pFileNewBufferShell = NULL;

	DWORD dwBufferLengthSrc = 0;
	DWORD dwBufferLengthShell = 0;

	GetWindowText(hShellEdit1,szBufferShell,MAX_PATH); // shell file 
	GetWindowText(hShellEdit2,szBufferSrc,MAX_PATH); // shell file 

	MyReadFile(&pFileBufferSrc,&dwBufferLengthSrc,szBufferSrc); //src

	XorEncryptAAA((char*)pFileBufferSrc,dwBufferLengthSrc);

	MyReadFile(&pFileBufferShell,&dwBufferLengthShell,szBufferShell);// shell 

	ShellAddNewSectionAndData(pFileBufferShell, &dwBufferLengthShell, &pFileNewBufferShell, pFileBufferSrc, dwBufferLengthSrc); // (1) 定为到SHELL文件的最后一个节	
	
	szBufferNew = &szBufferShell[0];
	strcat(szBufferNew, ".exe");

	MyWriteFile(pFileNewBufferShell,dwBufferLengthShell, szBufferNew);
	//--------------------------------------加密过程--------------------------------------

	/*
	//--------------------------------------解密过程--------------------------------------
	// 1、读取shell的数据
	PVOID pFileBufferNewShell = NULL;
	DWORD dwBufferLengthNewShell = 0;
	MyReadFile(&pFileBufferNewShell,&dwBufferLengthNewShell,szBufferNew);

	// 2、获取源文件的数据 解密
	PVOID pFileBufferNewSrc = NULL;	
	GetSrcFromShell(pFileBufferNewShell, &pFileBufferNewSrc);
	XorEncryptAAA((char*)pFileBufferNewSrc,dwBufferLengthSrc);

	DWORD dwSrcSizeOfImage = GetSizeOfImage(pFileBufferNewSrc);
	DWORD dwSrcImageBase = GetImageBase(pFileBufferNewSrc);

	// 3、拉伸PE  pImageBufferNewSrc
	PVOID pImageBufferNewSrc = NULL;
	CopyFileBufferToImageBuffer(pFileBufferNewSrc,&pImageBufferNewSrc);

	// 4、以挂起方式运行壳程序进程
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	CONTEXT cont;
	GetThreadContext(pi.hThread, &cont);

	si.cb = sizeof(STARTUPINFO);
	::CreateProcess(szBufferShell,NULL,NULL,NULL,NULL,CREATE_SUSPENDED, NULL,NULL,&si,&pi);

	DWORD dwImageBase = GetImageBase(pFileBufferShell);

	//5、卸载外壳程序的文件镜像
	typedef long NTSTATUS;
	typedef NTSTATUS(__stdcall *pfnZwUnmapViewOfSection)(HANDLE ProcessHandle, LPVOID BaseAddress);

	pfnZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;
	HMODULE hModule = LoadLibrary("ntdll.dll");
	if(hModule){
		ZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(hModule, "ZwUnmapViewOfSection");
		if(ZwUnmapViewOfSection)
			ZwUnmapViewOfSection(pi.hProcess, (PVOID)dwImageBase);
		FreeLibrary(hModule);
	}



	//6、在指定的位置(src的ImageBase)申请指定大小(src的SizeOfImage)的内存(VirtualAllocEx)
	LPVOID status = NULL;
	status = VirtualAllocEx(pi.hProcess, (LPVOID)dwSrcImageBase,dwSrcSizeOfImage,MEM_RESERVE | MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if(status != NULL){
		//7、如果成功，将Src的PE文件拉伸 复制到该空间中
		WriteProcessMemory(pi.hProcess, (LPVOID)dwSrcImageBase, pImageBufferNewSrc, dwSrcSizeOfImage, NULL);
	}else{
		//8、如果申请空间失败，但有重定位表：在任意位置申请空间，然后将PE文件拉伸、复制、修复重定位表。
		PIMAGE_BASE_RELOCATION pRelocationDirectory = NULL;
		DWORD NumberOfRelocation;
		PWORD Location;
		DWORD RVA_Data;
		WORD reloData;
		DWORD FOA;
		DWORD TempImageBase = 0x11111111;
		pRelocationDirectory = GetRelocationTable(pFileBufferNewSrc);
		if(pRelocationDirectory->VirtualAddress){
			ChangesImageBase(pFileBufferNewSrc, TempImageBase);

			WriteProcessMemory(pi.hProcess, (LPVOID)dwSrcImageBase, pImageBufferNewSrc, dwSrcSizeOfImage, NULL);
			
			while(pRelocationDirectory->SizeOfBlock && pRelocationDirectory->VirtualAddress){				
				NumberOfRelocation = (pRelocationDirectory->SizeOfBlock - 8)/2;// 每个重定位块中的数据项的数量
				Location = (PWORD)((DWORD)pRelocationDirectory + 8); // 加上8个字节
				for(DWORD i=0;i<NumberOfRelocation;i++){
					if(Location[i] >> 12 != 0){ //判断是否是垃圾数据
						// WORD类型的变量进行接收
						reloData = (Location[i] & 0xFFF); //这里进行与操作 只取4字节 二进制的后12位
						RVA_Data = pRelocationDirectory->VirtualAddress + reloData; //这个是RVA的地址
						RVA_TO_FOA(pFileBufferNewSrc,RVA_Data,&FOA);
						//这里是自增的 进行修复重定位，上面的Imagebase我们自增了1000，那么要修复的地址都需要自增1000
						*(PDWORD)((DWORD)pFileBufferNewSrc+(DWORD)FOA) = *(PDWORD)((DWORD)pFileBufferNewSrc+(DWORD)FOA) + TempImageBase - dwSrcImageBase;	 // 任意位置 - Origin ImageBase			
					}
				}
				pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationDirectory + (DWORD)pRelocationDirectory->SizeOfBlock); //上面的for循环完成之后，跳转到下个重定位块 继续如上的操作
			}

			dwSrcImageBase = TempImageBase;
		}else{
			// 9、如果第6步申请空间失败，并且还没有重定位表，直接返回：失败.
			return;	
		}
	}
	
	// 10、修改外壳程序的Context:
    DWORD dwEntryPoint = GetOep(pFileBufferNewSrc);
	dwImageBase = dwSrcImageBase;

	cont.Eax = dwEntryPoint + dwImageBase;

	char* baseAddress = (char*)cont.Ebx+8;
	WriteProcessMemory(pi.hProcess, baseAddress, (LPVOID)dwImageBase,4, NULL);
    SetThreadContext(pi.hThread, &cont);
	//记得恢复线程
    ResumeThread(pi.hThread);
	*/
}
	   