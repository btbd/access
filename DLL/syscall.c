#include "stdafx.h"

PVOID(NTAPI *NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(ULONG64, PVOID, PVOID, PVOID);

BOOL SetupSyscalls() {
	*(PVOID *)&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = GetProcAddress(
		GetModuleHandle(L"ntdll.dll"),
		"NtConvertBetweenAuxiliaryCounterAndPerformanceCounter"
	);

	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) {
		MessageBox(
			0,
			L"Failed to find \"NtConvertBetweenAuxiliaryCounterAndPerformanceCounter\"",
			L"Failure",
			MB_ICONERROR
		);

		return FALSE;
	}

	return TRUE;
}

NTSTATUS DoSyscall(SYSCALL syscall, PVOID args) {
	SYSCALL_DATA data;
	data.Unique = SYSCALL_UNIQUE;
	data.Syscall = syscall;
	data.Arguments = args;

	// NtConvertBetweenAuxiliaryCounterAndPerformanceCounter will dereference this
	PVOID dataPtr = &data;

	INT64 status = 0;
	NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(1, &dataPtr, &status, 0);
	return (NTSTATUS)status;
}