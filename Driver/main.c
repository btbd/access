#include "stdafx.h"

PVOID DxgkGetSharedResourceAdapterLuid = 0;
INT64(NTAPI *DxgkGetSharedResourceAdapterLuidOriginal)(INT64, INT64, PVOID);

NTSTATUS(NTAPI *PsResumeThread)(PETHREAD Thread, PULONG PreviousCount);
NTSTATUS(NTAPI *PsSuspendThread)(PETHREAD Thread, PULONG PreviousSuspendCount);

INT64 NTAPI DxgkGetSharedResourceAdapterLuidHook(INT64 unique, INT64 syscall, PVOID buffer) {
	if (ExGetPreviousMode() != UserMode || unique != SYSCALL_UNIQUE) {
		return DxgkGetSharedResourceAdapterLuidOriginal(unique, syscall, buffer);
	}

	switch (syscall) {
		/*** Process ***/
		HANDLE_SYSCALL(NtOpenProcess, NTOPENPROCESS_ARGS)
		HANDLE_SYSCALL(NtSuspendProcess, NTSUSPENDPROCESS_ARGS)
		HANDLE_SYSCALL(NtResumeProcess, NTRESUMEPROCESS_ARGS)
		HANDLE_SYSCALL(NtQuerySystemInformationEx, NTQUERYSYSTEMINFORMATIONEX_ARGS)
		HANDLE_SYSCALL(NtQueryInformationProcess, NTQUERYINFORMATIONPROCESS_ARGS)
		HANDLE_SYSCALL(NtSetInformationProcess, NTSETINFORMATIONPROCESS_ARGS)
		HANDLE_SYSCALL(NtFlushInstructionCache, NTFLUSHINSTRUCTIONCACHE_ARGS)

		/*** Memory ***/
		HANDLE_SYSCALL(NtAllocateVirtualMemory, NTALLOCATEVIRTUALMEMORY_ARGS)
		HANDLE_SYSCALL(NtFlushVirtualMemory, NTFLUSHVIRTUALMEMORY_ARGS)
		HANDLE_SYSCALL(NtFreeVirtualMemory, NTFREEVIRTUALMEMORY_ARGS)
		HANDLE_SYSCALL(NtLockVirtualMemory, NTLOCKVIRTUALMEMORY_ARGS)
		HANDLE_SYSCALL(NtUnlockVirtualMemory, NTUNLOCKVIRTUALMEMORY_ARGS)
		HANDLE_SYSCALL(NtProtectVirtualMemory, NTPROTECTVIRTUALMEMORY_ARGS)
		HANDLE_SYSCALL(NtReadVirtualMemory, NTREADVIRTUALMEMORY_ARGS)
		HANDLE_SYSCALL(NtWriteVirtualMemory, NTWRITEVIRTUALMEMORY_ARGS)
		HANDLE_SYSCALL(NtQueryVirtualMemory, NTQUERYVIRTUALMEMORY_ARGS)
			
		/*** Threads ***/
		HANDLE_SYSCALL(NtOpenThread, NTOPENTHREAD_ARGS)
		HANDLE_SYSCALL(NtQueryInformationThread, NTQUERYINFORMATIONTHREAD_ARGS)
		HANDLE_SYSCALL(NtSetInformationThread, NTSETINFORMATIONTHREAD_ARGS)
		HANDLE_SYSCALL(NtGetContextThread, NTGETCONTEXTTHREAD_ARGS)
		HANDLE_SYSCALL(NtSetContextThread, NTSETCONTEXTTHREAD_ARGS)
		HANDLE_SYSCALL(NtResumeThread, NTRESUMETHREAD_ARGS)
		HANDLE_SYSCALL(NtSuspendThread, NTSUSPENDTHREAD_ARGS)

		/*** Sync ***/
		HANDLE_SYSCALL(NtWaitForSingleObject, NTWAITFORSINGLEOBJECT_ARGS)
	}

	return STATUS_NOT_IMPLEMENTED;
}

ULONG PreviousModeOffset = 0;
KPROCESSOR_MODE KeSetPreviousMode(KPROCESSOR_MODE mode) {
	KPROCESSOR_MODE old = ExGetPreviousMode();
	*(KPROCESSOR_MODE *)((PBYTE)KeGetCurrentThread() + PreviousModeOffset) = mode;
	return old;
}

NTSTATUS Main() {
	// Get KTHREAD.PreviousMode offset
	PreviousModeOffset = *(PULONG)((PBYTE)ExGetPreviousMode + 0xC);
	if (PreviousModeOffset > 0x400) {
		printf("! invalid PreviousModeOffset (%x) !\n", PreviousModeOffset);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	
	// NtSuspend/ResumeThread not exported
	PVOID func = FindPattern((PCHAR)PsRegisterPicoProvider, 0x100, "\x48\x8D\x0D\x00\x00\x00\x00\x48\x89\x4A\x40", "xxx????xxxx");
	if (!func) {
		printf("! failed to find \"PsResumeThread\" !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*(PVOID *)&PsResumeThread = (PBYTE)func + *(PINT)((PBYTE)func + 3) + 7;

	func = FindPattern(func, 0x40, "\x48\x8D\x0D\x00\x00\x00\x00\x48\x89\x4A\x50", "xxx????xxxx");
	if (!func) {
		printf("! failed to find \"PsSuspendThead\" !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*(PVOID *)&PsSuspendThread = (PBYTE)func + *(PINT)((PBYTE)func + 3) + 7;

	// Hook dxgkrnl syscall
	PVOID base = GetBaseAddress("dxgkrnl.sys", 0);
	if (!base) {
		printf("! failed to get \"dxgkrnl.sys\" base !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	func = RtlFindExportedRoutineByName(base, "DxgkGetSharedResourceAdapterLuid");
	if (!func) {
		// Not exported below 1903
		func = FindPatternImage(base, "\x48\x8D\x15\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xB8\x00\x00\x00\x00\x48\x83\xC4\x00\xC3", "xxx????x????x????xxx?x");
		if (func) {
			func = FindPattern(func, 0x100, "\x48\x8B\xC4", "xxx");
		}

		if (!func) {
			printf("! failed to find \"DxgkGetSharedResourceAdapterLuid\" !\n");
			return STATUS_FAILED_DRIVER_ENTRY;
		}
	}

	if (!TrampolineHook((PVOID)DxgkGetSharedResourceAdapterLuidHook, func, (PVOID *)&DxgkGetSharedResourceAdapterLuidOriginal)) {
		printf("! failed to hook \"DxgkGetSharedResourceAdapterLuid\" !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DxgkGetSharedResourceAdapterLuid = func;

	printf("success\n");
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT driver) {
	UNREFERENCED_PARAMETER(driver);

	UnTrampolineHook(DxgkGetSharedResourceAdapterLuid, (PVOID)DxgkGetSharedResourceAdapterLuidOriginal);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(registryPath);
	driver->DriverUnload = DriverUnload;

	return Main();
}