#include "stdafx.h"

PVOID(NTAPI *NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(PVOID, PVOID, PVOID, PVOID);

BOOL SetupSyscalls() {
	HANDLE module = LoadLibrary(L"ntdll.dll");
	if (!module) {
		MessageBox(0, L"Failed to load NTDLL", L"Failure", MB_ICONERROR);
		return FALSE;
	}

	*(PVOID *)&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = GetProcAddress(module, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) {
		MessageBox(0, L"Failed to find \"NtConvertBetweenAuxiliaryCounterAndPerformanceCounter\"", L"Failure", MB_ICONERROR);
		return FALSE;
	}

	return TRUE;
}

NTSTATUS DoSyscall(SYSCALL syscall, PVOID args) {
	SYSCALL_DATA data = { 0 };
	data.Unique = SYSCALL_UNIQUE;
	data.Syscall = syscall;
	data.Arguments = args;

	// NtConvertBetweenAuxiliaryCounterAndPerformanceCounter will dereference this
	PVOID dataPtr = &data;

	INT64 status = 0;
	NtConvertBetweenAuxiliaryCounterAndPerformanceCounter((PVOID)1, &dataPtr, &status, 0);
	return (NTSTATUS)status;
}