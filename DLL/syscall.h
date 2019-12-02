#pragma once

#define SYSCALL_UNIQUE (0x133)

#define HANDLE_SIGNATURE (1 << 31 | 1 << 29)
#define IsValidHandle(handle) (((SIZE_T)handle & HANDLE_SIGNATURE) && ((SIZE_T)handle % 4 == 0))
#define EncodeHandle(id) (HANDLE)((SIZE_T)id | HANDLE_SIGNATURE)
#define DecodeHandle(handle) (HANDLE)((SIZE_T)handle & ~HANDLE_SIGNATURE)

typedef struct _SYSCALL_DATA {
	DWORD Unique;
	DWORD Syscall;
	PVOID Arguments;
} SYSCALL_DATA, *PSYSCALL_DATA;

typedef enum _SYSCALL {
	/*** Process ***/
	SyscallNtOpenProcess,
	SyscallNtSuspendProcess,
	SyscallNtResumeProcess,
	SyscallNtQuerySystemInformationEx,
	SyscallNtQueryInformationProcess,
	SyscallNtSetInformationProcess,
	SyscallNtFlushInstructionCache,

	/*** Memory ***/
	SyscallNtAllocateVirtualMemory,
	SyscallNtFlushVirtualMemory,
	SyscallNtFreeVirtualMemory,
	SyscallNtLockVirtualMemory,
	SyscallNtUnlockVirtualMemory,
	SyscallNtProtectVirtualMemory,
	SyscallNtReadVirtualMemory,
	SyscallNtWriteVirtualMemory,
	SyscallNtQueryVirtualMemory,

	/*** Thread ***/
	SyscallNtOpenThread,
	SyscallNtQueryInformationThread,
	SyscallNtSetInformationThread,
	SyscallNtGetContextThread,
	SyscallNtSetContextThread,
	SyscallNtResumeThread,
	SyscallNtSuspendThread,

	/*** Sync ***/
	SyscallNtWaitForSingleObject
} SYSCALL;

/*** Process ***/
typedef struct _NTOPENPROCESS_ARGS {
	PHANDLE ProcessHandle;
	ACCESS_MASK DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	PCLIENT_ID ClientId;
} NTOPENPROCESS_ARGS, *PNTOPENPROCESS_ARGS;

typedef struct _NTSUSPENDPROCESS_ARGS {
	HANDLE ProcessHandle;
} NTSUSPENDPROCESS_ARGS, *PNTSUSPENDPROCESS_ARGS;

typedef struct _NTRESUMEPROCESS_ARGS {
	HANDLE ProcessHandle;
} NTRESUMEPROCESS_ARGS, *PNTRESUMEPROCESS_ARGS;

typedef struct _NTQUERYSYSTEMINFORMATIONEX_ARGS {
	SYSTEM_INFORMATION_CLASS SystemInformationClass;
	PVOID InputBuffer;
	ULONG InputBufferLength;
	PVOID SystemInformation;
	ULONG SystemInformationLength;
	PULONG ReturnLength;
} NTQUERYSYSTEMINFORMATIONEX_ARGS, *PNTQUERYSYSTEMINFORMATIONEX_ARGS;

typedef struct _NTQUERYINFORMATIONPROCESS_ARGS {
	HANDLE ProcessHandle;
	PROCESS_INFORMATION_CLASS ProcessInformationClass;
	PVOID ProcessInformation;
	ULONG ProcessInformationLength;
	PULONG ReturnLength;
} NTQUERYINFORMATIONPROCESS_ARGS, *PNTQUERYINFORMATIONPROCESS_ARGS;

typedef struct _NTSETINFORMATIONPROCESS_ARGS {
	HANDLE ProcessHandle;
	PROCESSINFOCLASS ProcessInformationClass;
	PVOID ProcessInformation;
	ULONG ProcessInformationLength;
} NTSETINFORMATIONPROCESS_ARGS, *PNTSETINFORMATIONPROCESS_ARGS;

typedef struct _NTFLUSHINSTRUCTIONCACHE_ARGS {
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	ULONG NumberOfBytesToFlush;
} NTFLUSHINSTRUCTIONCACHE_ARGS, *PNTFLUSHINSTRUCTIONCACHE_ARGS;

/*** Memory ***/
typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
	HANDLE ProcessHandle;
	PVOID *BaseAddress;
	SIZE_T ZeroBits;
	PSIZE_T RegionSize;
	ULONG AllocationType;
	ULONG Protect;
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;

typedef struct _NTFLUSHVIRTUALMEMORY_ARGS {
	HANDLE ProcessHandle;
	PVOID *BaseAddress;
	PSIZE_T RegionSize;
	PIO_STATUS_BLOCK IoStatus;
} NTFLUSHVIRTUALMEMORY_ARGS, *PNTFLUSHVIRTUALMEMORY_ARGS;

typedef struct _NTFREEVIRTUALMEMORY_ARGS {
	HANDLE ProcessHandle;
	PVOID *BaseAddress;
	PSIZE_T RegionSize;
	ULONG FreeType;
} NTFREEVIRTUALMEMORY_ARGS, *PNTFREEVIRTUALMEMORY_ARGS;

typedef struct _NTLOCKVIRTUALMEMORY_ARGS {
	HANDLE ProcessHandle;
	PVOID *BaseAddress;
	PSIZE_T RegionSize;
	ULONG LockOption;
} NTLOCKVIRTUALMEMORY_ARGS, *PNTLOCKVIRTUALMEMORY_ARGS;

typedef struct _NTUNLOCKVIRTUALMEMORY_ARGS {
	HANDLE ProcessHandle;
	PVOID *BaseAddress;
	PSIZE_T RegionSize;
	ULONG LockOption;
} NTUNLOCKVIRTUALMEMORY_ARGS, *PNTUNLOCKVIRTUALMEMORY_ARGS;

typedef struct _NTPROTECTVIRTUALMEMORY_ARGS {
	HANDLE ProcessHandle;
	PVOID *BaseAddress;
	PSIZE_T RegionSize;
	ULONG NewAccessProtection;
	PULONG OldAccessProtection;
} NTPROTECTVIRTUALMEMORY_ARGS, *PNTPROTECTVIRTUALMEMORY_ARGS;

typedef struct _NTREADVIRTUALMEMORY_ARGS {
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	PVOID Buffer;
	SIZE_T NumberOfBytesToRead;
	PSIZE_T NumberOfBytesRead;
} NTREADVIRTUALMEMORY_ARGS, *PNTREADVIRTUALMEMORY_ARGS;

typedef struct _NTWRITEVIRTUALMEMORY_ARGS {
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	PVOID Buffer;
	SIZE_T NumberOfBytesToWrite;
	PSIZE_T NumberOfBytesWritten;
} NTWRITEVIRTUALMEMORY_ARGS, *PNTWRITEVIRTUALMEMORY_ARGS;

typedef struct _NTQUERYVIRTUALMEMORY_ARGS {
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	MEMORY_INFORMATION_CLASS MemoryInformationClass;
	PVOID MemoryInformation;
	SIZE_T MemoryInformationLength;
	PSIZE_T ReturnLength;
} NTQUERYVIRTUALMEMORY_ARGS, *PNTQUERYVIRTUALMEMORY_ARGS;

/*** Thread ***/
typedef struct _NTOPENTHREAD_ARGS {
	PHANDLE ThreadHandle;
	ACCESS_MASK AccessMask;
	POBJECT_ATTRIBUTES ObjectAttributes;
	PCLIENT_ID ClientId;
} NTOPENTHREAD_ARGS, *PNTOPENTHREAD_ARGS;

typedef struct _NTQUERYINFORMATIONTHREAD_ARGS {
	HANDLE ThreadHandle;
	THREADINFOCLASS ThreadInformationClass;
	PVOID ThreadInformation;
	ULONG ThreadInformationLength;
	PULONG ReturnLength;
} NTQUERYINFORMATIONTHREAD_ARGS, *PNTQUERYINFORMATIONTHREAD_ARGS;

typedef struct _NTSETINFORMATIONTHREAD_ARGS {
	HANDLE ThreadHandle;
	THREADINFOCLASS ThreadInformationClass;
	PVOID ThreadInformation;
	ULONG ThreadInformationLength;
} NTSETINFORMATIONTHREAD_ARGS, *PNTSETINFORMATIONTHREAD_ARGS;

typedef struct _NTGETCONTEXTTHREAD_ARGS {
	HANDLE ThreadHandle;
	PCONTEXT Context;
} NTGETCONTEXTTHREAD_ARGS, *PNTGETCONTEXTTHREAD_ARGS;

typedef struct _NTSETCONTEXTTHREAD_ARGS {
	HANDLE ThreadHandle;
	PCONTEXT Context;
} NTSETCONTEXTTHREAD_ARGS, *PNTSETCONTEXTTHREAD_ARGS;

typedef struct _NTRESUMETHREAD_ARGS {
	HANDLE ThreadHandle;
	PULONG SuspendCount;
} NTRESUMETHREAD_ARGS, *PNTRESUMETHREAD_ARGS;

typedef struct _NTSUSPENDTHREAD_ARGS {
	HANDLE ThreadHandle;
	PULONG PreviousSuspendCount;
} NTSUSPENDTHREAD_ARGS, *PNTSUSPENDTHREAD_ARGS;

/*** Sync ***/
typedef struct _NTWAITFORSINGLEOBJECT_ARGS {
	HANDLE Handle;
	BOOLEAN Alertable;
	PLARGE_INTEGER Timeout;
} NTWAITFORSINGLEOBJECT_ARGS, *PNTWAITFORSINGLEOBJECT_ARGS;