#include "IATHook.h"


BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		//HookFunction((char*)"GetCurrentProcessId", (PSIZE_T)&HookedGetCurrentProcessId);
		HookFunction((char*)"TerminateProcess", (PSIZE_T)&HookedTerminateProcess);
	}
	return TRUE;
}

void HookFunction(char* funcName, PSIZE_T function)
{
	PSIZE_T pOldFunction = FindFunctionAddress(funcName);

	DWORD accessProtectionValue, accessProtec;

	int vProtect = VirtualProtect(pOldFunction, sizeof(PSIZE_T), PAGE_EXECUTE_READWRITE, &accessProtectionValue);

	//*pOldFunction = (SIZE_T)((PSIZE_T)&HookedGetCurrentProcessId);
	*pOldFunction = (SIZE_T)function;

	vProtect = VirtualProtect(pOldFunction, sizeof(PSIZE_T), accessProtectionValue, &accessProtec);
}

int WINAPI HookedGetCurrentProcessId(VOID)
{
	//return MessageBoxA(hWnd, "Hello", "DLL answering here!", uType);
	return 10000;
}

bool WINAPI
HookedTerminateProcess(
	_In_ HANDLE hProcess,
	_In_ UINT uExitCode
) {
	MessageBox(0, "FUCK OFF !!!", "...", MB_ICONINFORMATION);
	return false;
}

PSIZE_T FindFunctionAddress(char* funcName)
{
	
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



	PIMAGE_THUNK_DATA	pITDN = (PIMAGE_THUNK_DATA)(lpAddress + pIID->OriginalFirstThunk); // ILT
	PIMAGE_THUNK_DATA	pITDA = (PIMAGE_THUNK_DATA)(lpAddress + pIID->FirstThunk); // IAT
	PSIZE_T				pOldFunction = nullptr;



	do {
		PIMAGE_IMPORT_BY_NAME pIIBN = (PIMAGE_IMPORT_BY_NAME)(lpAddress + pITDN->u1.AddressOfData);
		if (!strcmp("GetCurrentProcessId", (char*)pIIBN->Name)) {

			pOldFunction = (PSIZE_T)&(pITDA->u1.Function);
			printf("\n\npITDA->u1.Function   :    %p", pITDA->u1.Function);
			printf("\n	---> %s was found with address : 0x%p\n\n", (char*)pIIBN->Name, *pOldFunction);
			return pOldFunction;
		}
		pITDA++;
		pITDN++;
	} while (pITDN->u1.AddressOfData);

	return 0;
}