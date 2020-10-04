#pragma once
#include <windows.h>

// Typedefs
typedef LPVOID(WINAPI* VirtualAllocExProc)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);
typedef BOOL(WINAPI* GetThreadContextProc)(
	HANDLE    hThread,
	LPCONTEXT lpContext
	);
typedef BOOL(WINAPI* SetThreadContextProc)(
	HANDLE        hThread,
	const CONTEXT* lpContext
	);
typedef DWORD(WINAPI* ResumeThreadProc)(HANDLE hThread);

// Global Variables
HMODULE ntdll = GetModuleHandleA("ntdll");
HMODULE kernel32 = GetModuleHandleA("kernel32");

// Prototypes
int RunPE32(LPVOID lpBuffer);
tNtQueryInformationProcess NtQueryInformationProcess = (tNtQueryInformationProcess)(GetProcAddress(ntdll, "NtQueryInformationProcess"));
tNtSuspendProcess NtSuspendProcess = (tNtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
tNtUnmapViewOfSection NtUnmapViewOfSection = (tNtUnmapViewOfSection)(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
tNtReadVirtualMemory NtReadVirtualMemory = (tNtReadVirtualMemory)(GetProcAddress(ntdll, "NtReadVirtualMemory"));
tNtWriteVirtualMemory NtWriteVirtualMemory = (tNtWriteVirtualMemory)(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
tNtAllocateVirtualMemory NtAllocateVirtualMemory = (tNtAllocateVirtualMemory)(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
VirtualAllocExProc VirtualAllocEx_ = (VirtualAllocExProc)(GetProcAddress(kernel32, "VirtualAllocEx"));
ResumeThreadProc ResumeThread_ = (ResumeThreadProc)(GetProcAddress(kernel32, "ResumeThread"));
GetThreadContextProc GetThreadContext_ = (GetThreadContextProc)(GetProcAddress(kernel32, "GetThreadContext"));
SetThreadContextProc SetThreadContext_ = (SetThreadContextProc)(GetProcAddress(kernel32, "SetThreadContext"));

