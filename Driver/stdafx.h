#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>

#include "util.h"
#include "syscall.h"

#define printf(fmt, ...) DbgPrint("[dbg] "fmt, ##__VA_ARGS__)
#define HANDLE_SYSCALL(name, args) \
    case Syscall##name: {                                      \
        args safe = { 0 };                                     \
        try {                                                  \
            ProbeForRead(buffer, sizeof(args), sizeof(ULONG)); \
            safe = *(args *)buffer;                            \
        } except (EXCEPTION_EXECUTE_HANDLER) {                 \
            return GetExceptionCode();                         \
        }                                                      \
        return Core##name(&safe);                              \
    }

// Important thread info excluding most critical structures
#define THREAD_INFO_SIZE (0x6E4)
static ULONG THREAD_INFO_SECTIONS[] = { 0x78, 0x7C, 0xC3, 0xC5, 0x220, 0x228, 0x233, 0x234, 0x240, 0x250, 0x28C, 0x290, 0x2DC, 0x2E0, 0x5D8, 0x618, 0x680, 0x6A8, 0x6BC, THREAD_INFO_SIZE };

KPROCESSOR_MODE KeSetPreviousMode(KPROCESSOR_MODE mode);

/*** Process ***/
INT64 CoreNtOpenProcess(PNTOPENPROCESS_ARGS args);
INT64 CoreNtSuspendProcess(PNTSUSPENDPROCESS_ARGS args);
INT64 CoreNtResumeProcess(PNTRESUMEPROCESS_ARGS args);
INT64 CoreNtQuerySystemInformationEx(PNTQUERYSYSTEMINFORMATIONEX_ARGS args);
INT64 CoreNtQueryInformationProcess(PNTQUERYINFORMATIONPROCESS_ARGS args);
INT64 CoreNtSetInformationProcess(PNTSETINFORMATIONPROCESS_ARGS args);
INT64 CoreNtFlushInstructionCache(PNTFLUSHINSTRUCTIONCACHE_ARGS args);

/*** Memory ***/
INT64 CoreNtAllocateVirtualMemory(PNTALLOCATEVIRTUALMEMORY_ARGS args);
INT64 CoreNtFlushVirtualMemory(PNTFLUSHVIRTUALMEMORY_ARGS args);
INT64 CoreNtFreeVirtualMemory(PNTFREEVIRTUALMEMORY_ARGS args);
INT64 CoreNtLockVirtualMemory(PNTLOCKVIRTUALMEMORY_ARGS args);
INT64 CoreNtUnlockVirtualMemory(PNTUNLOCKVIRTUALMEMORY_ARGS args);
INT64 CoreNtProtectVirtualMemory(PNTPROTECTVIRTUALMEMORY_ARGS args);
INT64 CoreNtReadVirtualMemory(PNTREADVIRTUALMEMORY_ARGS args);
INT64 CoreNtWriteVirtualMemory(PNTWRITEVIRTUALMEMORY_ARGS args);
INT64 CoreNtQueryVirtualMemory(PNTQUERYVIRTUALMEMORY_ARGS args);

/*** Thread ***/
INT64 CoreNtOpenThread(PNTOPENTHREAD_ARGS args);
INT64 CoreNtQueryInformationThread(PNTQUERYINFORMATIONTHREAD_ARGS args);
INT64 CoreNtSetInformationThread(PNTSETINFORMATIONTHREAD_ARGS args);
INT64 CoreNtGetContextThread(PNTGETCONTEXTTHREAD_ARGS args);
INT64 CoreNtSetContextThread(PNTSETCONTEXTTHREAD_ARGS args);
INT64 CoreNtResumeThread(PNTRESUMETHREAD_ARGS args);
INT64 CoreNtSuspendThread(PNTSUSPENDTHREAD_ARGS args);

/*** Sync ***/
INT64 CoreNtWaitForSingleObject(PNTWAITFORSINGLEOBJECT_ARGS args);