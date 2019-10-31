#include "stdafx.h"

extern NTSTATUS(NTAPI *PsSuspendThread)(PETHREAD Thread, PULONG PreviousSuspendCount);
extern NTSTATUS(NTAPI *PsResumeThread)(PETHREAD Thread, PULONG PreviousCount);

/*** Process ***/
INT64 CoreNtOpenProcess(PNTOPENPROCESS_ARGS args) {
	CLIENT_ID clientId = { 0 };
	try {
		ProbeForRead(args->ClientId, sizeof(CLIENT_ID), sizeof(LONG));
		clientId = *args->ClientId;

		ProbeForWrite(args->ProcessHandle, sizeof(HANDLE), sizeof(LONG));
	} except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	NTSTATUS status = STATUS_SUCCESS;
	if (clientId.UniqueThread) {
		PETHREAD thread = 0;
		PEPROCESS process = 0;

		if (NT_SUCCESS(status = PsLookupProcessThreadByCid(&clientId, &process, &thread))) {
			try {	
				*args->ProcessHandle = EncodeHandle(PsGetProcessId(process));
			} except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
			
			ObDereferenceObject(thread);
			ObDereferenceObject(process);
		}
	} else {
		PEPROCESS process = 0;

		if (NT_SUCCESS(status = PsLookupProcessByProcessId(clientId.UniqueProcess, &process))) {
			try {
				*args->ProcessHandle = EncodeHandle(clientId.UniqueProcess);
			} except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}

			ObDereferenceObject(process);
		}
	}
	
	return status;
}

INT64 CoreNtSuspendProcess(PNTSUSPENDPROCESS_ARGS args) {
	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		status = PsSuspendProcess(process);
		ObDereferenceObject(process);
	}

	return status;
}

INT64 CoreNtResumeProcess(PNTRESUMEPROCESS_ARGS args) {
	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		status = PsResumeProcess(process);
		ObDereferenceObject(process);
	}

	return status;
}

INT64 CoreNtQuerySystemInformationEx(PNTQUERYSYSTEMINFORMATIONEX_ARGS args) {
	switch (args->SystemInformationClass) {
		case SystemSupportedProcessArchitectures:
			if (args->InputBuffer && args->InputBufferLength == sizeof(HANDLE)) {
				HANDLE processHandle = 0;
				try {
					ProbeForRead(args->InputBuffer, args->InputBufferLength, sizeof(LONG));
					ProbeForWrite(args->SystemInformation, args->SystemInformationLength, sizeof(LONG));
					if (args->ReturnLength) {
						ProbeForWrite(args->ReturnLength, sizeof(ULONG), sizeof(LONG));
					}

					processHandle = *(PHANDLE)args->InputBuffer;
				} except(EXCEPTION_EXECUTE_HANDLER) {
					return GetExceptionCode();
				}

				PEPROCESS process = 0;
				NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(processHandle), &process);
				if (NT_SUCCESS(status)) {
					processHandle = NtCurrentProcess();

					PVOID systemInformation = 0;
					ULONG returnLength = 0;

					if (args->SystemInformation && args->SystemInformationLength) {
						systemInformation = ExAllocatePool(NonPagedPool, args->SystemInformationLength);
						if (!systemInformation) {
							ObDereferenceObject(process);
							return STATUS_INSUFFICIENT_RESOURCES;
						}
					}

					KeAttachProcess((PKPROCESS)process);
					KeEnterCriticalRegion();
					KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

					status = NtQuerySystemInformationEx(args->SystemInformationClass, &processHandle, args->InputBufferLength, systemInformation, args->SystemInformationLength, &returnLength);

					KeSetPreviousMode(previousMode);
					KeLeaveCriticalRegion();
					KeDetachProcess();

					ObDereferenceObject(process);

					if (systemInformation) {
						try {
							memcpy(args->SystemInformation, systemInformation, returnLength);
						} except(EXCEPTION_EXECUTE_HANDLER) {
							status = GetExceptionCode();
						}

						ExFreePool(systemInformation);
					}

					if (args->ReturnLength) {
						try {
							*args->ReturnLength = returnLength;
						} except(EXCEPTION_EXECUTE_HANDLER) {
							status = GetExceptionCode();
						}
					}
				}

				return status;
			}

			break;
	}

	return NtQuerySystemInformationEx(args->SystemInformationClass, args->InputBuffer, args->InputBufferLength, args->SystemInformation, args->SystemInformationLength, args->ReturnLength);
}

INT64 CoreNtQueryInformationProcess(PNTQUERYINFORMATIONPROCESS_ARGS args) {
	if (args->ProcessInformation) {
		try {
			ProbeForWrite(args->ProcessInformation, args->ProcessInformationLength, sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	if (args->ReturnLength) {
		try {
			ProbeForWrite(args->ReturnLength, sizeof(ULONG), sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		PVOID processInformation = 0;
		ULONG returnLength = 0;

		if (args->ProcessInformation && args->ProcessInformationLength) {
			processInformation = ExAllocatePool(NonPagedPool, args->ProcessInformationLength);
			if (!processInformation) {
				ObDereferenceObject(process);
				return STATUS_INSUFFICIENT_RESOURCES;
			}
		}

		KeAttachProcess((PKPROCESS)process);
		KeEnterCriticalRegion();
		KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);
		
		status = NtQueryInformationProcess(NtCurrentProcess(), args->ProcessInformationClass, processInformation, args->ProcessInformationLength, &returnLength);
		
		KeSetPreviousMode(previousMode);
		KeLeaveCriticalRegion();
		KeDetachProcess();

		ObDereferenceObject(process);

		if (processInformation) {
			try {
				memcpy(args->ProcessInformation, processInformation, returnLength);

				// Adjust relative pointers
				if (returnLength >= sizeof(PVOID)) {
					for (ULONG i = 0; i <= returnLength - sizeof(PVOID); i += sizeof(ULONG)) {
						PVOID *ptr = (PVOID *)((PBYTE)args->ProcessInformation + i);
						SIZE_T offset = (PBYTE)*ptr - (PBYTE)processInformation;

						if (offset < returnLength) {
							*ptr = (PBYTE)args->ProcessInformation + offset;
						}
					}
				}
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}

			ExFreePool(processInformation);
		}

		if (args->ReturnLength) {
			try {
				*args->ReturnLength = returnLength;
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		}
	}

	return status;
}

INT64 CoreNtSetInformationProcess(PNTSETINFORMATIONPROCESS_ARGS args) {
	if (!args->ProcessInformation || !args->ProcessInformationLength) {
		return STATUS_INVALID_PARAMETER;
	}

	try {
		ProbeForRead(args->ProcessInformation, args->ProcessInformationLength, sizeof(BYTE));
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
	
	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		PVOID processInformation = ExAllocatePool(NonPagedPool, args->ProcessInformationLength);
		if (processInformation) {
			try {
				memcpy(processInformation, args->ProcessInformation, args->ProcessInformationLength);
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}

			if (NT_SUCCESS(status)) {
				KeAttachProcess((PKPROCESS)process);
				KeEnterCriticalRegion();
				KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

				status = NtSetInformationProcess(NtCurrentProcess(), args->ProcessInformationClass, processInformation, args->ProcessInformationLength);

				KeSetPreviousMode(previousMode);
				KeLeaveCriticalRegion();
				KeDetachProcess();
			}

			ExFreePool(processInformation);
		} else {
			status = STATUS_INSUFFICIENT_RESOURCES;
		}

		ObDereferenceObject(process);
	}

	return status;
}

INT64 CoreNtFlushInstructionCache(PNTFLUSHINSTRUCTIONCACHE_ARGS args) {
	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		KeAttachProcess((PKPROCESS)process);
		KeEnterCriticalRegion();
		KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);
		
		status = ZwFlushInstructionCache(NtCurrentProcess(), args->BaseAddress, args->NumberOfBytesToFlush);
		
		KeSetPreviousMode(previousMode);
		KeLeaveCriticalRegion();
		KeDetachProcess();

		ObDereferenceObject(process);
	}

	return status;
}

/*** Memory ***/
INT64 CoreNtAllocateVirtualMemory(PNTALLOCATEVIRTUALMEMORY_ARGS args) {
	PVOID baseAddress = 0;
	SIZE_T regionSize = 0;
	try {
		ProbeForWrite(args->BaseAddress, sizeof(PVOID), sizeof(LONG));
		ProbeForWrite(args->RegionSize, sizeof(SIZE_T), sizeof(LONG));

		baseAddress = *args->BaseAddress;
		regionSize = *args->RegionSize;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		KeAttachProcess((PKPROCESS)process);
		KeEnterCriticalRegion();
		KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

		status = NtAllocateVirtualMemory(NtCurrentProcess(), &baseAddress, args->ZeroBits, &regionSize, args->AllocationType, args->Protect);
		
		KeSetPreviousMode(previousMode);
		KeLeaveCriticalRegion();
		KeDetachProcess();

		ObDereferenceObject(process);

		try {
			*args->BaseAddress = baseAddress;
			*args->RegionSize = regionSize;
		} except(EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	}

	return status;
}

INT64 CoreNtFlushVirtualMemory(PNTFLUSHVIRTUALMEMORY_ARGS args) {
	PVOID baseAddress = 0;
	SIZE_T regionSize = 0;
	IO_STATUS_BLOCK ioStatus = { 0 };
	try {
		ProbeForWrite(args->BaseAddress, sizeof(PVOID), sizeof(LONG));
		ProbeForWrite(args->RegionSize, sizeof(SIZE_T), sizeof(LONG));
		ProbeForWrite(args->IoStatus, sizeof(IO_STATUS_BLOCK), sizeof(LONG));

		baseAddress = *args->BaseAddress;
		regionSize = *args->RegionSize;
		ioStatus = *args->IoStatus;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		KeAttachProcess((PKPROCESS)process);
		KeEnterCriticalRegion();
		KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);

		status = ZwFlushVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, &ioStatus);
		
		KeSetPreviousMode(previousMode);
		KeLeaveCriticalRegion();
		KeDetachProcess();

		ObDereferenceObject(process);

		try {
			*args->BaseAddress = baseAddress;
			*args->RegionSize = regionSize;
			*args->IoStatus = ioStatus;
		} except(EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	}

	return status;
}

INT64 CoreNtFreeVirtualMemory(PNTFREEVIRTUALMEMORY_ARGS args) {
	PVOID baseAddress = 0;
	SIZE_T regionSize = 0;
	try {
		ProbeForWrite(args->BaseAddress, sizeof(PVOID), sizeof(LONG));
		ProbeForWrite(args->RegionSize, sizeof(SIZE_T), sizeof(LONG));

		baseAddress = *args->BaseAddress;
		regionSize = *args->RegionSize;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		KeAttachProcess((PKPROCESS)process);
		KeEnterCriticalRegion();
		KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);
		
		status = NtFreeVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, args->FreeType);
		
		KeSetPreviousMode(previousMode);
		KeLeaveCriticalRegion();
		KeDetachProcess();

		ObDereferenceObject(process);

		try {
			*args->BaseAddress = baseAddress;
			*args->RegionSize = regionSize;
		} except(EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	}

	return status;
}

INT64 CoreNtLockVirtualMemory(PNTLOCKVIRTUALMEMORY_ARGS args) {
	PVOID baseAddress = 0;
	SIZE_T regionSize = 0;
	try {
		ProbeForWrite(args->BaseAddress, sizeof(PVOID), sizeof(LONG));
		ProbeForWrite(args->RegionSize, sizeof(SIZE_T), sizeof(LONG));

		baseAddress = *args->BaseAddress;
		regionSize = *args->RegionSize;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		KeAttachProcess((PKPROCESS)process);
		KeEnterCriticalRegion();
		KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);
		
		status = ZwLockVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, args->LockOption);
		
		KeSetPreviousMode(previousMode);
		KeLeaveCriticalRegion();
		KeDetachProcess();

		ObDereferenceObject(process);

		try {
			*args->BaseAddress = baseAddress;
			*args->RegionSize = regionSize;
		} except(EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	}

	return status;
}

INT64 CoreNtUnlockVirtualMemory(PNTUNLOCKVIRTUALMEMORY_ARGS args) {
	PVOID baseAddress = 0;
	SIZE_T regionSize = 0;
	try {
		ProbeForWrite(args->BaseAddress, sizeof(PVOID), sizeof(LONG));
		ProbeForWrite(args->RegionSize, sizeof(SIZE_T), sizeof(LONG));

		baseAddress = *args->BaseAddress;
		regionSize = *args->RegionSize;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		KeAttachProcess((PKPROCESS)process);
		KeEnterCriticalRegion();
		KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);
		
		status = ZwUnlockVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, args->LockOption);
		
		KeSetPreviousMode(previousMode);
		KeLeaveCriticalRegion();
		KeDetachProcess();

		ObDereferenceObject(process);

		try {
			*args->BaseAddress = baseAddress;
			*args->RegionSize = regionSize;
		} except(EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	}

	return status;
}

INT64 CoreNtProtectVirtualMemory(PNTPROTECTVIRTUALMEMORY_ARGS args) {
	PVOID baseAddress = 0;
	SIZE_T regionSize = 0;
	try {
		ProbeForWrite(args->BaseAddress, sizeof(PVOID), sizeof(LONG));
		ProbeForWrite(args->RegionSize, sizeof(SIZE_T), sizeof(LONG));
		ProbeForWrite(args->OldAccessProtection, sizeof(ULONG), sizeof(LONG));

		baseAddress = *args->BaseAddress;
		regionSize = *args->RegionSize;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		ULONG oldAccessProtection = 0;

		KeAttachProcess((PKPROCESS)process);
		KeEnterCriticalRegion();
		KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);
		
		status = ZwProtectVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, args->NewAccessProtection, &oldAccessProtection);
		
		KeSetPreviousMode(previousMode);
		KeLeaveCriticalRegion();
		KeDetachProcess();

		ObDereferenceObject(process);

		try {
			*args->BaseAddress = baseAddress;
			*args->RegionSize = regionSize;
			*args->OldAccessProtection = oldAccessProtection;
		} except(EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	}

	return status;
}

INT64 CoreNtReadVirtualMemory(PNTREADVIRTUALMEMORY_ARGS args) {
	if (((PBYTE)args->BaseAddress + args->NumberOfBytesToRead < (PBYTE)args->BaseAddress) ||
		((PBYTE)args->Buffer + args->NumberOfBytesToRead < (PBYTE)args->Buffer) || 
		((PVOID)((PBYTE)args->BaseAddress + args->NumberOfBytesToRead) > MM_HIGHEST_USER_ADDRESS) ||
		((PVOID)((PBYTE)args->Buffer + args->NumberOfBytesToRead) > MM_HIGHEST_USER_ADDRESS)) {

		return STATUS_ACCESS_VIOLATION;
	}

	if (args->NumberOfBytesRead) {
		try {
			ProbeForWrite(args->NumberOfBytesRead, sizeof(SIZE_T), sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		if (args->NumberOfBytesToRead) {
			SIZE_T numberOfBytesRead = 0;
			status = MmCopyVirtualMemory(process, args->BaseAddress, PsGetCurrentProcess(), args->Buffer, args->NumberOfBytesToRead, ExGetPreviousMode(), &numberOfBytesRead);

			if (args->NumberOfBytesRead) {
				try {
					*args->NumberOfBytesRead = numberOfBytesRead;
				} except(EXCEPTION_EXECUTE_HANDLER) {
					status = GetExceptionCode();
				}
			}
		}
		
		ObDereferenceObject(process);
	}

	return status;
}

INT64 CoreNtWriteVirtualMemory(PNTWRITEVIRTUALMEMORY_ARGS args) {
	if (((PBYTE)args->BaseAddress + args->NumberOfBytesToWrite < (PBYTE)args->BaseAddress) ||
		((PBYTE)args->Buffer + args->NumberOfBytesToWrite < (PBYTE)args->Buffer) ||
		((PVOID)((PBYTE)args->BaseAddress + args->NumberOfBytesToWrite) > MM_HIGHEST_USER_ADDRESS) ||
		((PVOID)((PBYTE)args->Buffer + args->NumberOfBytesToWrite) > MM_HIGHEST_USER_ADDRESS)) {

		return STATUS_ACCESS_VIOLATION;
	}

	if (args->NumberOfBytesWritten) {
		try {
			ProbeForWrite(args->NumberOfBytesWritten, sizeof(SIZE_T), sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		if (args->NumberOfBytesToWrite) {
			SIZE_T numberOfBytesWritten = 0;
			status = MmCopyVirtualMemory(PsGetCurrentProcess(), args->Buffer, process, args->BaseAddress, args->NumberOfBytesToWrite, ExGetPreviousMode(), &numberOfBytesWritten);

			if (args->NumberOfBytesWritten) {
				try {
					*args->NumberOfBytesWritten = numberOfBytesWritten;
				} except(EXCEPTION_EXECUTE_HANDLER) {
					status = GetExceptionCode();
				}
			}
		}

		ObDereferenceObject(process);
	}

	return status;
}

INT64 CoreNtQueryVirtualMemory(PNTQUERYVIRTUALMEMORY_ARGS args) {
	if (args->MemoryInformation) {
		try {
			ProbeForWrite(args->MemoryInformation, args->MemoryInformationLength, sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	if (args->ReturnLength) {
		try {
			ProbeForWrite(args->ReturnLength, sizeof(SIZE_T), sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	PEPROCESS process = 0;
	NTSTATUS status = PsLookupProcessByProcessId(DecodeHandle(args->ProcessHandle), &process);
	if (NT_SUCCESS(status)) {
		PVOID memoryInformation = 0;
		SIZE_T returnLength = 0;

		if (args->MemoryInformation && args->MemoryInformationLength) {
			memoryInformation = ExAllocatePool(NonPagedPool, args->MemoryInformationLength);
			if (!memoryInformation) {
				ObDereferenceObject(process);
				return STATUS_INSUFFICIENT_RESOURCES;
			}
		}

		KeAttachProcess((PKPROCESS)process);
		KeEnterCriticalRegion();
		KPROCESSOR_MODE previousMode = KeSetPreviousMode(KernelMode);
		
		status = ZwQueryVirtualMemory(NtCurrentProcess(), args->BaseAddress, args->MemoryInformationClass, memoryInformation, args->MemoryInformationLength, &returnLength);
		
		KeSetPreviousMode(previousMode);
		KeLeaveCriticalRegion();
		KeDetachProcess();

		ObDereferenceObject(process);

		if (memoryInformation) {
			try {
				memcpy(args->MemoryInformation, memoryInformation, returnLength);
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}

			ExFreePool(memoryInformation);
		}

		if (args->ReturnLength) {
			try {
				*args->ReturnLength = returnLength;
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		}
	}

	return status;
}

/*** Thread ***/
INT64 CoreNtOpenThread(PNTOPENTHREAD_ARGS args) {
	CLIENT_ID clientId = { 0 };
	try {
		ProbeForRead(args->ClientId, sizeof(CLIENT_ID), sizeof(LONG));
		ProbeForWrite(args->ThreadHandle, sizeof(HANDLE), sizeof(LONG));

		clientId = *args->ClientId;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
	
	NTSTATUS status = STATUS_SUCCESS;
	if (clientId.UniqueProcess) {
		PETHREAD thread = 0;
		PEPROCESS process = 0;

		if (NT_SUCCESS(status = PsLookupProcessThreadByCid(&clientId, &process, &thread))) {
			try {
				*args->ThreadHandle = EncodeHandle(PsGetThreadId(thread));
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}

			ObDereferenceObject(thread);
			ObDereferenceObject(process);
		}
	} else {
		PETHREAD thread = 0;

		if (NT_SUCCESS(status = PsLookupThreadByThreadId(clientId.UniqueThread, &thread))) {
			try {
				*args->ThreadHandle = EncodeHandle(clientId.UniqueThread);
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}

			ObDereferenceObject(thread);
		}
	}
	
	return status;
}

INT64 CoreNtQueryInformationThread(PNTQUERYINFORMATIONTHREAD_ARGS args) {
	if (args->ThreadInformation) {
		try {
			ProbeForWrite(args->ThreadInformation, args->ThreadInformationLength, sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	if (args->ReturnLength) {
		try {
			ProbeForWrite(args->ReturnLength, sizeof(ULONG), sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	PETHREAD thread = 0;
	NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
	if (NT_SUCCESS(status)) {
		// This is an unsafe way to get thread info without a handle, APC, or manual implementation of ETHREAD structure
		KeEnterGuardedRegion();

		BYTE info[THREAD_INFO_SIZE] = { 0 };
		memcpy(info, PsGetCurrentThread(), THREAD_INFO_SIZE);

		for (ULONG i = 0; i < LENGTH(THREAD_INFO_SECTIONS); i += 2) {
			ULONG start = THREAD_INFO_SECTIONS[i];
			ULONG end = THREAD_INFO_SECTIONS[i + 1];
			memcpy((PBYTE)PsGetCurrentThread() + start, (PBYTE)thread + start, end - start);
		}

		KPROCESSOR_MODE old = KeSetPreviousMode(KernelMode);
		status = ZwQueryInformationThread(NtCurrentThread(), args->ThreadInformationClass, args->ThreadInformation, args->ThreadInformationLength, args->ReturnLength);
		KeSetPreviousMode(old);

		// Manually copy TEB if requested
		if (NT_SUCCESS(status) && args->ThreadInformationClass == ThreadBasicInformation && args->ThreadInformation && args->ThreadInformationLength) {
			try {
				((PTHREAD_BASIC_INFORMATION)args->ThreadInformation)->TebBaseAddress = PsGetThreadTeb(thread);
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		}

		for (ULONG i = 0; i < LENGTH(THREAD_INFO_SECTIONS); i += 2) {
			ULONG start = THREAD_INFO_SECTIONS[i];
			ULONG end = THREAD_INFO_SECTIONS[i + 1];
			memcpy((PBYTE)PsGetCurrentThread() + start, (PBYTE)info + start, end - start);
		}

		KeLeaveGuardedRegion();

		ObDereferenceObject(thread);
	}

	return status;
}

INT64 CoreNtSetInformationThread(PNTSETINFORMATIONTHREAD_ARGS args) {
	if (args->ThreadInformation && args->ThreadInformationLength) {
		try {
			ProbeForRead(args->ThreadInformation, args->ThreadInformationLength, sizeof(BYTE));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	PETHREAD thread = 0;
	NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
	if (NT_SUCCESS(status)) {
		KeEnterGuardedRegion();

		switch (args->ThreadInformationClass) {
			case ThreadZeroTlsCell:
				// Don't mess with current thread's TEB
				status = STATUS_NOT_IMPLEMENTED;
				break;
			case ThreadIdealProcessor: {
				if (!args->ThreadInformation) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}
					
				if (args->ThreadInformationLength != sizeof(ULONG)) {
					status = STATUS_INFO_LENGTH_MISMATCH;
					break;
				}

				ULONG idealProcessor = 0;
				try {
					idealProcessor = *(PULONG)args->ThreadInformation;
				} except(EXCEPTION_EXECUTE_HANDLER) {
					status = GetExceptionCode();
					break;
				}

				status = KeSetIdealProcessorThread(thread, (UCHAR)idealProcessor);

				break;
			}
			default:
				// Same story as NtQueryInformationThread
				if (NT_SUCCESS(status = PsSuspendThread(thread, 0))) {
					BYTE info[THREAD_INFO_SIZE] = { 0 };
					memcpy(info, PsGetCurrentThread(), THREAD_INFO_SIZE);

					for (ULONG i = 0; i < LENGTH(THREAD_INFO_SECTIONS); i += 2) {
						ULONG start = THREAD_INFO_SECTIONS[i];
						ULONG end = THREAD_INFO_SECTIONS[i + 1];
						memcpy((PBYTE)PsGetCurrentThread() + start, (PBYTE)thread + start, end - start);
					}

					KPROCESSOR_MODE old = KeSetPreviousMode(KernelMode);
					status = ZwSetInformationThread(NtCurrentThread(), args->ThreadInformationClass, args->ThreadInformation, args->ThreadInformationLength);
					KeSetPreviousMode(old);
					
					for (ULONG i = 0; i < LENGTH(THREAD_INFO_SECTIONS); i += 2) {
						ULONG start = THREAD_INFO_SECTIONS[i];
						ULONG end = THREAD_INFO_SECTIONS[i + 1];
						ULONG len = end - start;

						memcpy((PBYTE)thread + start, (PBYTE)PsGetCurrentThread() + start, len);
						memcpy((PBYTE)PsGetCurrentThread() + start, (PBYTE)info + start, len);
					}

					PsResumeThread(thread, 0);
				}

				break;
		}

		KeLeaveGuardedRegion();
		
		ObDereferenceObject(thread);
	}

	return status;
}

INT64 CoreNtGetContextThread(PNTGETCONTEXTTHREAD_ARGS args) {
	PETHREAD thread = 0;
	NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
	if (NT_SUCCESS(status)) {
		status = PsGetContextThread(thread, args->Context, ExGetPreviousMode());
		ObDereferenceObject(thread);
	}

	return status;
}

INT64 CoreNtSetContextThread(PNTSETCONTEXTTHREAD_ARGS args) {
	PETHREAD thread = 0;
	NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
	if (NT_SUCCESS(status)) {
		status = PsSetContextThread(thread, args->Context, ExGetPreviousMode());
		ObDereferenceObject(thread);
	}

	return status;
}

INT64 CoreNtResumeThread(PNTRESUMETHREAD_ARGS args) {
	if (args->SuspendCount) {
		try {
			ProbeForWrite(args->SuspendCount, sizeof(ULONG), sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	PETHREAD thread = 0;
	NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
	if (NT_SUCCESS(status)) {
		ULONG suspendCount = 0;

		status = PsResumeThread(thread, &suspendCount);

		ObDereferenceObject(thread);

		if (args->SuspendCount) {
			try {
				*args->SuspendCount = suspendCount;
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		}
	}

	return status;
}

INT64 CoreNtSuspendThread(PNTSUSPENDTHREAD_ARGS args) {
	if (args->PreviousSuspendCount) {
		try {
			ProbeForWrite(args->PreviousSuspendCount, sizeof(ULONG), sizeof(LONG));
		} except(EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	PETHREAD thread = 0;
	NTSTATUS status = PsLookupThreadByThreadId(DecodeHandle(args->ThreadHandle), &thread);
	if (NT_SUCCESS(status)) {
		ULONG previousSuspendCount = 0;

		status = PsSuspendThread(thread, &previousSuspendCount);

		ObDereferenceObject(thread);

		if (args->PreviousSuspendCount) {
			try {
				*args->PreviousSuspendCount = previousSuspendCount;
			} except(EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		}
	}

	return status;
}

/*** Sync ***/
INT64 CoreNtWaitForSingleObject(PNTWAITFORSINGLEOBJECT_ARGS args) {
	HANDLE id = DecodeHandle(args->Handle);
	HANDLE handle = 0;
	PETHREAD thread = 0;
	PEPROCESS process = 0;
	NTSTATUS status = STATUS_SUCCESS;
	
	// ACs don't care about synchronize rights - CBA to not use a handle
	if (NT_SUCCESS(status = PsLookupProcessByProcessId(id, &process))) {
		status = ObOpenObjectByPointer(process, 0, 0, SYNCHRONIZE, *PsProcessType, KernelMode, &handle);
		ObDereferenceObject(process);
	} else if (NT_SUCCESS(status = PsLookupThreadByThreadId(id, &thread))) {
		status = ObOpenObjectByPointer(thread, 0, 0, SYNCHRONIZE, *PsThreadType, KernelMode, &handle);
		ObDereferenceObject(thread);
	}

	if (NT_SUCCESS(status)) {
		status = NtWaitForSingleObject(handle, args->Alertable, args->Timeout);
		NtClose(handle);
	}

	return status;
}