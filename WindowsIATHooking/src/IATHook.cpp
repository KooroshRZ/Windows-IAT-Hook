#include "IATHook.h"

int main() {
	
	MODULEINFO modInfo;
	HMODULE hMod = GetModuleHandle(0);

	GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO));

	LPBYTE lpAddress = (LPBYTE)modInfo.lpBaseOfDll;
	printf("Base virtual address(DOS_HEADER) of Process :%p\n", (void*)lpAddress);
	system("PAUSE");

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)lpAddress;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(lpAddress + pIDH->e_lfanew);
	printf("NT_HEADER Address : %p\n", (void*)pINH);
	system("PAUSE");

	PIMAGE_OPTIONAL_HEADER pIOH = (PIMAGE_OPTIONAL_HEADER)&(pINH->OptionalHeader);
	printf("OPTIONAL_HEADER Address : %p\n", (void*)(pIOH));
	system("PAUSE");

	PIMAGE_IMPORT_DESCRIPTOR pIID = PIMAGE_IMPORT_DESCRIPTOR(lpAddress + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	printf("IMPORT_DIRECTORY_TABLE address %p\n", (void*)(pIID));
	system("PAUSE");

	for (; pIID->Characteristics; pIID++) {

		printf("IMPORT DIRECROTY ENTRY : %s\n", (char*)(lpAddress + pIID->Name));
		

		PIMAGE_THUNK_DATA pITDN = (PIMAGE_THUNK_DATA)(lpAddress + pIID->OriginalFirstThunk); // ILT
		PIMAGE_THUNK_DATA pITDA = (PIMAGE_THUNK_DATA)(lpAddress + pIID->FirstThunk); // IAT

		for (; pITDN->u1.AddressOfData; pITDN++, pITDA++) {
			PIMAGE_IMPORT_BY_NAME pIIBN = (PIMAGE_IMPORT_BY_NAME)(lpAddress + pITDN->u1.AddressOfData);
			printf("	%s with address : %p\n", (char*)pIIBN->Name, (void*)pITDA);
		}

		system("PAUSE");
	}



}

