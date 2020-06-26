// Petools.cpp: implementation of the Petools class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Petools.h"
#include<STDLIB.H>
#include<STDIO.H>
#include<WINDOWS.H>

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

void MyReadFile(PVOID* pFileBuffer,PDWORD BufferLenth, TCHAR* szFilePath){
	FILE* File;
	File = fopen(szFilePath,"rb");
	
	if(File == NULL){
		printf("文件句柄打开失败");
		return;
	}
	
	//读取文件
	fseek(File,0,SEEK_END);
	*BufferLenth = ftell(File);
	
	//重新把File指针指向文件的开头
	fseek(File,0,SEEK_SET);
	
	//开辟新空间
	*pFileBuffer = (PVOID)malloc(*BufferLenth);
	
	//内存清零
	memset(*pFileBuffer,0,*BufferLenth);
	
	//读取到内存缓冲区
	fread(*pFileBuffer,*BufferLenth,1,File);// 一次读入*bufferlenth个字节，重复1次
	
	//关闭文件句柄
	fclose(File);
}

//FOA_TO_RVA:FOA 转换 RVA							
DWORD FOA_TO_RVA(PVOID FileAddress, DWORD FOA,PDWORD pRVA)
{
	int ret = 0;
	int i;
	
	PIMAGE_DOS_HEADER pDosHeader				= (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader				= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader	= (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup			= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	
	//RVA在文件头中 或 SectionAlignment 等于 FileAlignment 时RVA等于FOA
	if (FOA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		*pRVA = FOA;
		return ret;
	}
	
	//循环判断FOA在节区中
	for (i=0;i < pFileHeader->NumberOfSections; i++)
	{
		if (FOA >= pSectionGroup[i].PointerToRawData && FOA < pSectionGroup[i].PointerToRawData + pSectionGroup[i].SizeOfRawData)
		{
			*pRVA = FOA - pSectionGroup[i].PointerToRawData + pSectionGroup[i].VirtualAddress;
			return *pRVA;
		}
	}
	
	//没有找到地址
	ret = -4;
	printf("func FOA_TO_RVA() Error: %d 地址转换失败！\n", ret);
	return ret;
}

//功能：RVA 转换 FOA
// RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[5].VirtualAddress,&FOA);
DWORD RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA)
{
	int ret = 0;
	int i=0;
	PIMAGE_DOS_HEADER pDosHeader				= (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader				= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader	= (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup			= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	
	
	//RVA在文件头中 或 SectionAlignment(内存对齐) 等于 FileAlignment(文件对齐) 时 RVA等于FOA
	if (RVA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		// 37000
		*pFOA = RVA;
		return ret;
	}
	
	/*
		第一步：指定节.VirtualAddress <= RVA <= 指定节.VirtualAddress + Misc.VirtualSize(当前节内存实际大小)
		第二步：差值 = RVA - 指定节.VirtualAddress
		第三步：FOA = 指定节.PointerToRawData + 差值
	*/

	//循环判断RVA在节区中
	for (i=0;i<pFileHeader->NumberOfSections; i++)
	{
		// RVA > 当前节在内存中的偏移地址 并且 RVA < 当前节的内存偏移地址+文件偏移地址
		if (RVA >= pSectionGroup[i].VirtualAddress && RVA < pSectionGroup[i].VirtualAddress + pSectionGroup[i].Misc.VirtualSize)
		{
			*pFOA =  RVA - pSectionGroup[i].VirtualAddress + pSectionGroup[i].PointerToRawData;
			return ret;
		}
	}
	
	//没有找到地址
	ret = -4;
	printf("func RVA_TO_FOA() Error: %d 地址转换失败！\n", ret);
	return ret;
}

// 功能：打印PE结构
void printfPE(PVOID pFileBuffer){
    PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PVOID AddressOfNamesTable = NULL;
	DWORD AddressOfNameOrdinalsNumber = NULL;
	PVOID FunctionOfAddress = NULL;
	char FunName[10] = {0};
	int i,j;

	DWORD FOA;
	char SectionName[9] = {0};

    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);


    //判断是否是有效的MZ标志，也就是0x5A4D，取前四个字节
    if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)    
    {   
        printf("不是有效的MZ标志\n");
        free(pFileBuffer);
        return ; 
    }   
	

    
    //打印DOS头    
    printf("********************DOS头********************\n\n"); 
    printf("_IMAGE_DOS_HEADERMZ->e_magic MZ标志：0x%x\n",pDosHeader->e_magic);
    printf("_IMAGE_DOS_HEADERMZ->e_lfanew指向PE标志：0x%x\n",pDosHeader->e_lfanew);
    printf("\n");
	
    //判断是否是有效的PE标志  
    if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)  
    {   
        printf("不是有效的PE标志\n");
        free(pFileBuffer);
        return ;
    }   
	
    
    //打印NT头 
    printf("********************NT头********************\n\n");  
    printf("_IMAGE_NT_HEADERS->Signature文件PE标识：0x%x\n",pNTHeader->Signature);
    printf("\n");
	

    printf("********************PE头********************\n\n");  
    printf("_IMAGE_FILE_HEADER->Machine支持的CPU：0x%x\n",pPEHeader->Machine);
    printf("_IMAGE_FILE_HEADER->NumberOfSections节的数量：0x%x\n",pPEHeader->NumberOfSections);
    printf("_IMAGE_FILE_HEADER->SizeOfOptionalHeader可选PE头的大小：0x%x\n",pPEHeader->SizeOfOptionalHeader);
    printf("\n");

	
    printf("********************OPTIOIN_PE头********************\n\n");  
    printf("_IMAGE_OPTIONAL_HEADER->Magic分辨系统位数:0x%x\n",pOptionHeader->Magic);
    printf("_IMAGE_OPTIONAL_HEADER->AddressOfEntryPoint程序入口:0x%x\n",pOptionHeader->AddressOfEntryPoint);
    printf("_IMAGE_OPTIONAL_HEADER->ImageBase内存镜像基址:0x%x\n",pOptionHeader->ImageBase);
    printf("_IMAGE_OPTIONAL_HEADER->SectionAlignment内存对齐大小:0x%x\n",pOptionHeader->SectionAlignment);
    printf("_IMAGE_OPTIONAL_HEADER->FileAlignment文件对齐大小:0x%x\n",pOptionHeader->FileAlignment);
    printf("_IMAGE_OPTIONAL_HEADER->SizeOfImage内存中PE的大小(SectionAlignment整数倍):0x%x\n",pOptionHeader->SizeOfImage);
    printf("_IMAGE_OPTIONAL_HEADER->SizeOfHeaders头+节表按照文件对齐的大小:0x%x\n",pOptionHeader->SizeOfImage);
    printf("_IMAGE_OPTIONAL_HEADER->NumberOfRvaAndSizes目录项数目:0x%x\n",pOptionHeader->NumberOfRvaAndSizes);
	
    printf("\n");
	
    //节表
    printf("********************节表********************\n\n");
    
    for(i=1;i<=pPEHeader->NumberOfSections;i++){
        char SectionName[9] ={0};
        strcpy(SectionName,(char *)pSectionHeader->Name);
        printf("_IMAGE_SECTION_HEADER->Name:%s\n",SectionName);
        printf("_IMAGE_SECTION_HEADER->VirtualSize:0x%x\n",pSectionHeader->Misc);
        printf("_IMAGE_SECTION_HEADER->VirtualAddress:0x%x\n",pSectionHeader->VirtualAddress);
        printf("_IMAGE_SECTION_HEADER->SizeOfRawData:0x%x\n",pSectionHeader->SizeOfRawData);
        printf("_IMAGE_SECTION_HEADER->PointerToRawData:0x%x\n",pSectionHeader->PointerToRawData);
        printf("_IMAGE_SECTION_HEADER->Characteristics:0x%x\n",pSectionHeader->Characteristics);
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
        printf("\n");
    }


	RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress,&FOA);
	
	//导出表的地址
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + FOA);
	
	//目录表中的16张表的解析
	
	//先解析第一张表《导出表》
	printf("********************导出表********************\n\n");
	printf("导出表的虚拟地址:%x\n",pOptionHeader->DataDirectory[0].VirtualAddress);
	printf("导出表的大小:%x\n",pOptionHeader->DataDirectory[0].Size);
	printf("_IMAGE_EXPORT_DIRECTORY->Characteristics: 0x%x\n",pExportDirectory->Characteristics);
	printf("_IMAGE_EXPORT_DIRECTORY->TimeDateStamp时间戳: 0x%x\n",pExportDirectory->TimeDateStamp);
	printf("_IMAGE_EXPORT_DIRECTORY->MajorVersion: 0x%x\n",pExportDirectory->MajorVersion);
	printf("_IMAGE_EXPORT_DIRECTORY->MinorVersion: 0x%x\n",pExportDirectory->MinorVersion);
	printf("_IMAGE_EXPORT_DIRECTORY->Name指向该导出表文件名字符串: 0x%x\n",pExportDirectory->Name);
	printf("_IMAGE_EXPORT_DIRECTORY->Base导出函数起始序号: 0x%x\n",pExportDirectory->Base);
	printf("_IMAGE_EXPORT_DIRECTORY->NumberOfFunctions所有导出函数的个数: 0x%x\n",pExportDirectory->NumberOfFunctions);
	printf("_IMAGE_EXPORT_DIRECTORY->NumberOfNames以函数名字导出的函数个数: 0x%x\n",pExportDirectory->NumberOfNames);
	printf("_IMAGE_EXPORT_DIRECTORY->RVA_AddressOfFunctions导出函数地址表: 0x%x\n",pExportDirectory->AddressOfFunctions);
	printf("_IMAGE_EXPORT_DIRECTORY->RAV_AddressOfNames导出函数名称表: 0x%x\n",pExportDirectory->AddressOfNames);
	printf("_IMAGE_EXPORT_DIRECTORY->RVA_AddressOfNameOrdinals导出函数序号表: 0x%x\n",pExportDirectory->AddressOfNameOrdinals);	

	printf("\n");




	//1、导出函数名称表来寻找导出函数地址表，AddressOfNames是一个指向函数名称的RVA地址，需要先转换为 文件偏移地址
	RVA_TO_FOA(pFileBuffer,pExportDirectory->AddressOfNames,&FOA);

	//printf("pExportDirectory->AddressOfNames导出函数名称表: 0x%x\n",FOA);

	//2、再加上pFileBuffer，转换为文件地址，得到函数名称存储的地方的首地址，当前的首地址是RVA，也需要进行RVA -> FOA转换
	AddressOfNamesTable = (PVOID)(*(PDWORD)((DWORD)pFileBuffer+(DWORD)FOA)); 
	RVA_TO_FOA(pFileBuffer,(DWORD)AddressOfNamesTable,&FOA); // // 导出函数名称表中函数名称的FOA

	//AddressOfNamesTable = (PVOID)FOA;
	AddressOfNamesTable = (PVOID)((DWORD)pFileBuffer + (DWORD)FOA); // 加上pFileBuffer位置就到了真正的函数名称表的地址
	printf("\n");
	
	//3、得到函数名称表的文件地址，每个函数的名称 占四个字节，然后进行遍历判断	
	for(j=0;j<pExportDirectory->NumberOfNames;j++){
		//(PDWORD)((DWORD)AddressOfNamesTable + 4*j);
		//获取当前函数名称表中的函数名称，然后循环判断
		//printf("this is my test:%s \n", (PVOID)((DWORD)AddressOfNamesTable));
		strcpy(FunName,(PCHAR)((DWORD)AddressOfNamesTable)); //这里+1 是最后一个字节为空字节 那么就为结束符
		if(0 == memcmp((PDWORD)((DWORD)AddressOfNamesTable),(PDWORD)FunName,strlen(FunName))){
			AddressOfNamesTable = (PVOID)((DWORD)AddressOfNamesTable + (DWORD)(strlen((PCHAR)AddressOfNamesTable)+1));			
			//4、找到序号表AddressOfNameOrdinals下标所对应的的值，序号表中每个成员占2字节 word类型
			RVA_TO_FOA(pFileBuffer,pExportDirectory->AddressOfNameOrdinals,&FOA);
			AddressOfNameOrdinalsNumber = *(PWORD)((DWORD)FOA + (DWORD)pFileBuffer + (DWORD)j*2);
			//5、通过序号表中下标对用的值去导出函数地址表AddressOfFunctions中寻找 该值下标对应的值
			RVA_TO_FOA(pFileBuffer,pExportDirectory->AddressOfFunctions,&FOA);
			printf("函数序号: %d\t",AddressOfNameOrdinalsNumber);
			printf("函数名称为: %s\t",FunName);
			printf("导出函数地址表的地址为：0x%.8x\n",*(PDWORD)(PVOID)((DWORD)FOA + (DWORD)pFileBuffer + AddressOfNameOrdinalsNumber*4));
		}
	}
	
	printf("\n");

	printf("********************导入表********************\n\n");
	printf("导入表的虚拟地址:%x\n",pOptionHeader->DataDirectory[1].VirtualAddress);
	printf("导入表的大小:%x\n",pOptionHeader->DataDirectory[1].Size);

	
	printf("\n");

	printf("********************资源表********************\n\n");
	printf("资源表的虚拟地址:%x\n",pOptionHeader->DataDirectory[2].VirtualAddress);
	printf("资源表的大小:%x\n",pOptionHeader->DataDirectory[2].Size);
	printf("\n");

    //释放内存  
    free(pFileBuffer);  
}
