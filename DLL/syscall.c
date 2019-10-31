#include "stdafx.h"

PVOID(NTAPI *NtGdiDdDDIGetSharedResourceAdapterLuid)(PVOID unique, PVOID syscall, PVOID buffer);

BOOL SetupSyscalls() {
	HANDLE module = LoadLibrary(L"win32u.dll");
	if (!module) {
		module = LoadLibrary(L"gdi32full.dll");

		if (!module) {
			MessageBox(0, L"Failed to load a valid GDI module", L"Failure", MB_ICONERROR);
			return FALSE;
		}
	}

	*(PVOID *)&NtGdiDdDDIGetSharedResourceAdapterLuid = GetProcAddress(module, "NtGdiDdDDIGetSharedResourceAdapterLuid");
	if (!NtGdiDdDDIGetSharedResourceAdapterLuid) {
		MessageBox(0, L"Failed to find \"NtGdiDdDDIGetSharedResourceAdapterLuid\"", L"Failure", MB_ICONERROR);
		return FALSE;
	}

	return TRUE;
}

NTSTATUS DoSyscall(SYSCALL syscall, PVOID args) {
	return (NTSTATUS)(SIZE_T)NtGdiDdDDIGetSharedResourceAdapterLuid((PVOID)SYSCALL_UNIQUE, (PVOID)syscall, args);
}