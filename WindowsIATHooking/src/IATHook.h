#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

// Hooked Function Implementations
int WINAPI HookedGetCurrentProcessId(
	VOID
);

bool WINAPI HookedTerminateProcess(
	_In_ HANDLE hProcess,
	_In_ UINT uExitCode
);



// Nessesary Functions for Hooking
PSIZE_T FindFunctionAddress(char* funcName);
void HookFunction(char* funcName, PSIZE_T function);

