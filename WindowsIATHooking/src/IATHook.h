#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

void StartHook();

//DWORD WINAPI HookedGetCurrentProcessId(VOID);
DWORD HookedGetCurrentProcessId(VOID);