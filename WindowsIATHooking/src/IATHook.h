#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>


// Hooked Function Implementations
DWORD WINAPI HookedGetCurrentProcessId(
	VOID
);

// Nessesary Functions for Hooking
PSIZE_T FindFunctionAddress(char* funcName);
void HookFunction(char* funcName, SIZE_T function);

