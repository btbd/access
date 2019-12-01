#include "stdafx.h"

struct {
	PVOID Src[0x100];
	PVOID Original[0x100];
	ULONG Length;
} hooks = { 0 };

/*** Process ***/
NTSTATUS(NTAPI *NtOpenProcess)(PHANDLE processHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID clientId);
NTSTATUS NTAPI NtOpenProcessHook(PHANDLE processHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID clientId) {
	if (clientId->UniqueProcess == (HANDLE)(SIZE_T)GetCurrentProcessId()) {
		return NtOpenProcess(processHandle, desiredAccess, objectAttributes, clientId);
	}

	NTOPENPROCESS_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.DesiredAccess = desiredAccess;
	args.ObjectAttributes = objectAttributes;
	args.ClientId = clientId;
	return DoSyscall(SyscallNtOpenProcess, &args);
}

NTSTATUS(NTAPI *NtSuspendProcess)(HANDLE processHandle);
NTSTATUS NTAPI NtSuspendProcessHook(HANDLE processHandle) {
	if (!IsValidHandle(processHandle)) {
		return NtSuspendProcess(processHandle);
	}

	NTSUSPENDPROCESS_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	return DoSyscall(SyscallNtSuspendProcess, &args);
}

NTSTATUS(NTAPI *NtResumeProcess)(HANDLE processHandle);
NTSTATUS NTAPI NtResumeProcessHook(HANDLE processHandle) {
	if (!IsValidHandle(processHandle)) {
		return NtSuspendProcess(processHandle);
	}

	NTRESUMEPROCESS_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	return DoSyscall(SyscallNtResumeProcess, &args);
}

NTSTATUS(NTAPI *NtQuerySystemInformationEx)(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID inputBuffer, ULONG inputBufferLength, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
NTSTATUS NTAPI NtQuerySystemInformationExHook(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID inputBuffer, ULONG inputBufferLength, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength) {
	switch (systemInformationClass) {
		case SystemSupportedProcessArchitectures:
			if (inputBuffer && inputBufferLength >= sizeof(HANDLE) && IsValidHandle(*(PHANDLE)inputBuffer)) {
				NTQUERYSYSTEMINFORMATIONEX_ARGS args = { 0 };
				args.SystemInformationClass = systemInformationClass;
				args.InputBuffer = inputBuffer;
				args.InputBufferLength = inputBufferLength;
				args.SystemInformation = systemInformation;
				args.SystemInformationLength = systemInformationLength;
				args.ReturnLength = returnLength;
				return DoSyscall(SyscallNtQuerySystemInformationEx, &args);
			}

			break;
	}
	
	return NtQuerySystemInformationEx(systemInformationClass, inputBuffer, inputBufferLength, systemInformation, systemInformationLength, returnLength);
}

NTSTATUS(NTAPI *NtQueryInformationProcess)(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID processInformation, ULONG processInformationLength, PULONG returnLength);
NTSTATUS NTAPI NtQueryInformationProcessHook(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID processInformation, ULONG processInformationLength, PULONG returnLength) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtQueryInformationProcess(processHandle, processInformationClass, processInformation, processInformationLength, returnLength);
	}
	
	NTQUERYINFORMATIONPROCESS_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.ProcessInformationClass = processInformationClass;
	args.ProcessInformation = processInformation;
	args.ProcessInformationLength = processInformationLength;
	args.ReturnLength = returnLength;
	return DoSyscall(SyscallNtQueryInformationProcess, &args);
}

NTSTATUS(NTAPI *NtSetInformationProcess)(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID processInformation, ULONG processInformationLength);
NTSTATUS NTAPI NtSetInformationProcessHook(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID processInformation, ULONG processInformationLength) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtSetInformationProcess(processHandle, processInformationClass, processInformation, processInformationLength);
	}

	NTQUERYINFORMATIONPROCESS_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.ProcessInformationClass = processInformationClass;
	args.ProcessInformation = processInformation;
	args.ProcessInformationLength = processInformationLength;
	return DoSyscall(SyscallNtSetInformationProcess, &args);
}

NTSTATUS(NTAPI *NtFlushInstructionCache)(HANDLE processHandle, PVOID baseAddress, ULONG numberOfBytesToFlush);
NTSTATUS NTAPI NtFlushInstructionCacheHook(HANDLE processHandle, PVOID baseAddress, ULONG numberOfBytesToFlush) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtFlushInstructionCache(processHandle, baseAddress, numberOfBytesToFlush);
	}
	
	NTFLUSHINSTRUCTIONCACHE_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.NumberOfBytesToFlush = numberOfBytesToFlush;
	return DoSyscall(SyscallNtFlushInstructionCache, &args);
}

NTSTATUS(NTAPI *NtClose)(HANDLE handle);
NTSTATUS NTAPI NtCloseHook(HANDLE handle) {
	if (!IsValidHandle(handle)) {
		return NtClose(handle);
	}

	return ERROR_SUCCESS;
}

/*** Memory ***/
NTSTATUS(NTAPI *NtAllocateVirtualMemory)(HANDLE processHandle, PVOID baseAddress, SIZE_T zeroBits, PSIZE_T regionSize, ULONG allocationType, ULONG protect);
NTSTATUS NTAPI NtAllocateVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, SIZE_T zeroBits, PSIZE_T regionSize, ULONG allocationType, ULONG protect) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtAllocateVirtualMemory(processHandle, baseAddress, zeroBits, regionSize, allocationType, protect);
	}

	NTALLOCATEVIRTUALMEMORY_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.ZeroBits = zeroBits;
	args.RegionSize = regionSize;
	args.AllocationType = allocationType;
	args.Protect = protect;
	return DoSyscall(SyscallNtAllocateVirtualMemory, &args);
}

NTSTATUS(NTAPI *NtFlushVirtualMemory)(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, PIO_STATUS_BLOCK ioStatus);
NTSTATUS NTAPI NtFlushVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, PIO_STATUS_BLOCK ioStatus) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtFlushVirtualMemory(processHandle, baseAddress, regionSize, ioStatus);
	}

	NTFLUSHVIRTUALMEMORY_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.RegionSize = regionSize;
	args.IoStatus = ioStatus;
	return DoSyscall(SyscallNtFlushVirtualMemory, &args);
}

NTSTATUS(NTAPI *NtFreeVirtualMemory)(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG freeType);
NTSTATUS NTAPI NtFreeVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG freeType) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtFreeVirtualMemory(processHandle, baseAddress, regionSize, freeType);
	}

	NTFREEVIRTUALMEMORY_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.RegionSize = regionSize;
	args.FreeType = freeType;
	return DoSyscall(SyscallNtFreeVirtualMemory, &args);
}

NTSTATUS(NTAPI *NtLockVirtualMemory)(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption);
NTSTATUS NTAPI NtLockVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtLockVirtualMemory(processHandle, baseAddress, regionSize, lockOption);
	}

	NTLOCKVIRTUALMEMORY_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.RegionSize = regionSize;
	args.LockOption = lockOption;
	return DoSyscall(SyscallNtLockVirtualMemory, &args);
}

NTSTATUS(NTAPI *NtUnlockVirtualMemory)(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption);
NTSTATUS NTAPI NtUnlockVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG lockOption) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtLockVirtualMemory(processHandle, baseAddress, regionSize, lockOption);
	}

	NTUNLOCKVIRTUALMEMORY_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.RegionSize = regionSize;
	args.LockOption = lockOption;
	return DoSyscall(SyscallNtUnlockVirtualMemory, &args);
}

NTSTATUS(NTAPI *NtProtectVirtualMemory)(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG newAccessProtection, PULONG oldAccessProtection);
NTSTATUS NTAPI NtProtectVirtualMemoryHook(HANDLE processHandle, PVOID *baseAddress, PSIZE_T regionSize, ULONG newAccessProtection, PULONG oldAccessProtection) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtProtectVirtualMemory(processHandle, baseAddress, regionSize, newAccessProtection, oldAccessProtection);
	}

	NTPROTECTVIRTUALMEMORY_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.RegionSize = regionSize;
	args.NewAccessProtection = newAccessProtection;
	args.OldAccessProtection = oldAccessProtection;
	return DoSyscall(SyscallNtProtectVirtualMemory, &args);
}

NTSTATUS(NTAPI *NtReadVirtualMemory)(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToRead, PSIZE_T numberOfBytesRead);
NTSTATUS NTAPI NtReadVirtualMemoryHook(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToRead, PSIZE_T numberOfBytesRead) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtReadVirtualMemory(processHandle, baseAddress, buffer, numberOfBytesToRead, numberOfBytesRead);
	}

	NTREADVIRTUALMEMORY_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.Buffer = buffer;
	args.NumberOfBytesToRead = numberOfBytesToRead;
	args.NumberOfBytesRead = numberOfBytesRead;
	return DoSyscall(SyscallNtReadVirtualMemory, &args);
}

NTSTATUS(NTAPI *NtWriteVirtualMemory)(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToWrite, PSIZE_T numberOfBytesWritten);
NTSTATUS NTAPI NtWriteVirtualMemoryHook(HANDLE processHandle, PVOID baseAddress, PVOID buffer, SIZE_T numberOfBytesToWrite, PSIZE_T numberOfBytesWritten) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtWriteVirtualMemory(processHandle, baseAddress, buffer, numberOfBytesToWrite, numberOfBytesWritten);
	}

	NTWRITEVIRTUALMEMORY_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.Buffer = buffer;
	args.NumberOfBytesToWrite = numberOfBytesToWrite;
	args.NumberOfBytesWritten = numberOfBytesWritten;
	return DoSyscall(SyscallNtWriteVirtualMemory, &args);
}

NTSTATUS(NTAPI *NtQueryVirtualMemory)(HANDLE processHandle, PVOID baseAddress, MEMORY_INFORMATION_CLASS memoryInformationClass, PVOID memoryInformation, SIZE_T memoryInformationLength, PSIZE_T returnLength);
NTSTATUS NTAPI NtQueryVirtualMemoryHook(HANDLE processHandle, PVOID baseAddress, MEMORY_INFORMATION_CLASS memoryInformationClass, PVOID memoryInformation, SIZE_T memoryInformationLength, PSIZE_T returnLength) {
	if (processHandle == GetCurrentProcess() || !IsValidHandle(processHandle)) {
		return NtQueryVirtualMemory(processHandle, baseAddress, memoryInformationClass, memoryInformation, memoryInformationLength, returnLength);
	}

	NTQUERYVIRTUALMEMORY_ARGS args = { 0 };
	args.ProcessHandle = processHandle;
	args.BaseAddress = baseAddress;
	args.MemoryInformationClass = memoryInformationClass;
	args.MemoryInformation = memoryInformation;
	args.MemoryInformationLength = memoryInformationLength;
	args.ReturnLength = returnLength;
	return DoSyscall(SyscallNtQueryVirtualMemory, &args);
}

/*** Thread ***/
NTSTATUS(NTAPI *NtOpenThread)(PHANDLE threadHandle, ACCESS_MASK accessMask, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID clientId);
NTSTATUS NTAPI NtOpenThreadHook(PHANDLE threadHandle, ACCESS_MASK accessMask, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID clientId) {
	if (clientId->UniqueProcess == GetCurrentProcess() || clientId->UniqueThread == (HANDLE)(SIZE_T)GetCurrentThreadId()) {
		return NtOpenThread(threadHandle, accessMask, objectAttributes, clientId);
	}
	
	NTOPENTHREAD_ARGS args = { 0 };
	args.ThreadHandle = threadHandle;
	args.AccessMask = accessMask;
	args.ObjectAttributes = objectAttributes;
	args.ClientId = clientId;
	return DoSyscall(SyscallNtOpenThread, &args);
}

NTSTATUS(NTAPI *NtQueryInformationThread)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength, PULONG returnLength);
NTSTATUS NTAPI NtQueryInformationThreadHook(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength, PULONG returnLength) {
	if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
		return NtQueryInformationThread(threadHandle, threadInformationClass, threadInformation, threadInformationLength, returnLength);
	}

	NTQUERYINFORMATIONTHREAD_ARGS args = { 0 };
	args.ThreadHandle = threadHandle;
	args.ThreadInformationClass = threadInformationClass;
	args.ThreadInformation = threadInformation;
	args.ThreadInformationLength = threadInformationLength;
	args.ReturnLength = returnLength;
	return DoSyscall(SyscallNtQueryInformationThread, &args);
}

NTSTATUS(NTAPI *NtSetInformationThread)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);
NTSTATUS NTAPI NtSetInformationThreadHook(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength) {
	if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
		return NtSetInformationThread(threadHandle, threadInformationClass, threadInformation, threadInformationLength);
	}

	NTSETINFORMATIONTHREAD_ARGS args = { 0 };
	args.ThreadHandle = threadHandle;
	args.ThreadInformationClass = threadInformationClass;
	args.ThreadInformation = threadInformation;
	args.ThreadInformationLength = threadInformationLength;
	return DoSyscall(SyscallNtSetInformationThread, &args);
}

NTSTATUS(NTAPI *NtGetContextThread)(HANDLE threadHandle, PCONTEXT context);
NTSTATUS NTAPI NtGetContextThreadHook(HANDLE threadHandle, PCONTEXT context) {
	if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
		return NtGetContextThread(threadHandle, context);
	}

	NTGETCONTEXTTHREAD_ARGS args = { 0 };
	args.ThreadHandle = threadHandle;
	args.Context = context;
	return DoSyscall(SyscallNtGetContextThread, &args);
}

NTSTATUS(NTAPI *NtSetContextThread)(HANDLE threadHandle, PCONTEXT context);
NTSTATUS NTAPI NtSetContextThreadHook(HANDLE threadHandle, PCONTEXT context) {
	if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
		return NtSetContextThread(threadHandle, context);
	}

	NTSETCONTEXTTHREAD_ARGS args = { 0 };
	args.ThreadHandle = threadHandle;
	args.Context = context;
	return DoSyscall(SyscallNtSetContextThread, &args);
}

NTSTATUS(NTAPI *NtResumeThread)(HANDLE threadHandle, PULONG suspendCount);
NTSTATUS NTAPI NtResumeThreadHook(HANDLE threadHandle, PULONG suspendCount) {
	if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
		return NtResumeThread(threadHandle, suspendCount);
	}

	NTRESUMETHREAD_ARGS args = { 0 };
	args.ThreadHandle = threadHandle;
	args.SuspendCount = suspendCount;
	return DoSyscall(SyscallNtResumeThread, &args);
}

NTSTATUS(NTAPI *NtSuspendThread)(HANDLE threadHandle, PULONG previousSuspendCount);
NTSTATUS NTAPI NtSuspendThreadHook(HANDLE threadHandle, PULONG previousSuspendCount) {
	if (threadHandle == GetCurrentThread() || !IsValidHandle(threadHandle)) {
		return NtResumeThread(threadHandle, previousSuspendCount);
	}

	NTSUSPENDTHREAD_ARGS args = { 0 };
	args.ThreadHandle = threadHandle;
	args.PreviousSuspendCount = previousSuspendCount;
	return DoSyscall(SyscallNtSuspendThread, &args);
}

/*** Sync ***/
NTSTATUS(NTAPI *NtWaitForSingleObject)(HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout);
NTSTATUS NTAPI NtWaitForSingleObjectHook(HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout) {
	if (!IsValidHandle(handle)) {
		return NtWaitForSingleObject(handle, alertable, timeout);
	}

	NTWAITFORSINGLEOBJECT_ARGS args = { 0 };
	args.Handle = handle;
	args.Alertable = alertable;
	args.Timeout = timeout;
	return DoSyscall(SyscallNtWaitForSingleObject, &args);
}

VOID Attach() {
	HANDLE ntdll = GetModuleHandle(L"ntdll.dll");
	if (!ntdll) {
		MessageBox(0, L"Failed to get a handle for \"ntdll.dll\"", L"Failure", MB_ICONERROR);
		return;
	}

	if (!SetupSyscalls()) {
		return;
	}

	/*** Process ***/
	HOOK(NtOpenProcess);
	HOOK(NtSuspendProcess);
	HOOK(NtResumeProcess);
	HOOK(NtQuerySystemInformationEx);
	HOOK(NtQueryInformationProcess);
	HOOK(NtSetInformationProcess);
	HOOK(NtFlushInstructionCache);
	HOOK(NtClose);

	/*** Memory ***/
	HOOK(NtAllocateVirtualMemory);
	HOOK(NtFlushVirtualMemory);
	HOOK(NtFreeVirtualMemory);
	HOOK(NtLockVirtualMemory);
	HOOK(NtUnlockVirtualMemory);
	HOOK(NtProtectVirtualMemory);
	HOOK(NtReadVirtualMemory);
	HOOK(NtWriteVirtualMemory);
	HOOK(NtQueryVirtualMemory);

	/*** Thread ***/
	HOOK(NtOpenThread);
	HOOK(NtQueryInformationThread);
	HOOK(NtSetInformationThread);
	HOOK(NtGetContextThread);
	HOOK(NtSetContextThread);
	HOOK(NtSuspendThread);
	HOOK(NtResumeThread);

	/*** Sync ***/
	HOOK(NtWaitForSingleObject);
}

VOID Detach() {
	for (ULONG i = 0; i < hooks.Length; ++i) {
		UnTrampolineHook(hooks.Src[i], hooks.Original[i]);
	}
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
	switch (reason) {
		case DLL_PROCESS_ATTACH:
			Attach();
			break;
		case DLL_PROCESS_DETACH:
			Detach();
			break;
	}

	return TRUE;
}