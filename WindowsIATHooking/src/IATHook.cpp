#include "IATHook.h"


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved
) {
	
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//MessageBox(0, "Hello I'm DLL injected inside you !!!", "DLL_PROCESS_ATTACH", MB_ICONINFORMATION);
		//LogMessage("Hello I'm DLL injected inside you in DLL_PROCESS_ATTACH mode!!!");
		//exit(1);
		StartHook();
		break;
	}

}

DWORD ModifiedFunc() {

	return 100000;

}

void StartHook() {
	MODULEINFO modInfo;
	HMODULE hMod = GetModuleHandle(0);

	GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO));

	LPBYTE lpAddress = (LPBYTE)modInfo.lpBaseOfDll;
	printf("Base virtual address(DOS_HEADER) of Process :%p\n", (void*)lpAddress);
	//system("PAUSE");

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)lpAddress;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(lpAddress + pIDH->e_lfanew);
	printf("NT_HEADER Address : %p\n", (void*)pINH);
	//system("PAUSE");

	PIMAGE_OPTIONAL_HEADER pIOH = (PIMAGE_OPTIONAL_HEADER)&(pINH->OptionalHeader);
	printf("OPTIONAL_HEADER Address : %p\n", (void*)(pIOH));
	//system("PAUSE");

	PIMAGE_IMPORT_DESCRIPTOR pIID = PIMAGE_IMPORT_DESCRIPTOR(lpAddress + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	printf("IMPORT_DIRECTORY_TABLE address %p\n\n", (void*)(pIID));
	//system("PAUSE");

	for (; pIID->Characteristics; pIID++) 
		if (!strcmp("KERNEL32.dll", (char*)(lpAddress + pIID->Name))) {
			printf("IMPORT DIRECROTY ENTRY : %s\n", (char*)(lpAddress + pIID->Name));
			break;
		}
			
	

	PIMAGE_THUNK_DATA pITDN = (PIMAGE_THUNK_DATA)(lpAddress + pIID->OriginalFirstThunk); // ILT
	PIMAGE_THUNK_DATA pITDA = (PIMAGE_THUNK_DATA)(lpAddress + pIID->FirstThunk); // IAT

	for (; pITDN->u1.AddressOfData; pITDN++) {
		PIMAGE_IMPORT_BY_NAME pIIBN = (PIMAGE_IMPORT_BY_NAME)(lpAddress + pITDN->u1.AddressOfData);
		if (!strcmp("GetCurrentProcessId", (char*)pIIBN->Name)) {
			printf("	%s with address : \n", (char*)pIIBN->Name);
			Sleep(2000);
			break;
		}
			
		pITDA++;
	}

	//Sleep(200000);


	DWORD dwOLD = NULL;
	VirtualProtect((LPVOID)&(pITDA->u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOLD);
	pITDA->u1.Function = (SIZE_T)HookedGetCurrentProcessId;
	VirtualProtect((LPVOID)&(pITDA->u1.Function), sizeof(DWORD), dwOLD, NULL);

}

DWORD HookedGetCurrentProcessId(VOID) {
	printf("\n\nentered\n\n");
	return 10000;
}
