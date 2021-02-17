#include "stdafx.h"

BOOL ProbeUserAddress(PVOID addr, SIZE_T size, ULONG alignment) {
	if (size == 0) {
		return TRUE;
	}
		
	ULONG_PTR current = (ULONG_PTR)addr;
	if (((ULONG_PTR)addr & (alignment - 1)) != 0) {
		return FALSE;
	}

	ULONG_PTR last = current + size - 1;
	if ((last < current) || (last >= MmUserProbeAddress)) {
		return FALSE;
	}

	return TRUE;
}

BOOL SafeCopy(PVOID dest, PVOID src, SIZE_T size) {
	SIZE_T returnSize = 0;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), src, PsGetCurrentProcess(), dest, size, KernelMode, &returnSize)) && returnSize == size) {
		return TRUE;
	}

	return FALSE;
}

BYTE GetInstructionLength(BYTE table[], PBYTE instruction) {
	BYTE i = table[*instruction++];
	return i < 0x10 ? i : GetInstructionLength(INSTRUCTION_TABLES[i - 0x10], instruction);
}

BOOL TrampolineHook(PVOID dest, PVOID src, PVOID *original) {
	BOOL ret = FALSE;

	BYTE length = 0;
	for (PBYTE inst = (PBYTE)src; length < JMP_SIZE; ) {
		BYTE l = GetInstructionLength(INSTRUCTION_TABLE, inst);
		if (!l) {
			printf("! bad instruction !\n");
			return ret;
		}

		inst += l;
		length += l;
	}

	BYTE jmp[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };
	PVOID copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, length + sizeof(jmp), 'HT');
	if (copy) {
		memcpy(copy, src, length);
		*(PVOID *)&jmp[6] = (PBYTE)src + length;
		memcpy((PBYTE)copy + length, jmp, sizeof(jmp));

		BYTE hook[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
		*(PVOID *)&hook[6] = dest;

		PMDL mdl = IoAllocateMdl(src, length, 0, 0, 0);
		if (mdl) {
			MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

			PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, 0, HighPagePriority);
			if (mapped) {
				memcpy(mapped, hook, length);
				MmUnmapLockedPages(mapped, mdl);

				ret = TRUE;
			} else {
				printf("! failed to map pages !\n");
			}

			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		} else {
			printf("! failed to allocate MDL !\n");
		}

		if (ret) {
			*original = copy;
			return ret;
		} else {
			ExFreePool(copy);
		}
	} else {
		printf("! failed to allocate gate !\n");
	}

	return ret;
}

BOOL UnTrampolineHook(PVOID src, PVOID original) {
	BOOL ret = FALSE;

	BYTE length = 0;
	for (PBYTE inst = (PBYTE)original; length < JMP_SIZE; ) {
		BYTE l = GetInstructionLength(INSTRUCTION_TABLE, inst);
		if (!l) {
			printf("! bad instruction !\n");
			return ret;
		}

		inst += l;
		length += l;
	}

	PMDL mdl = IoAllocateMdl(src, length, 0, 0, 0);
	if (mdl) {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

		PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, 0, HighPagePriority);
		if (mapped) {
			memcpy(mapped, original, length);
			MmUnmapLockedPages(mapped, mdl);
			ExFreePool(original);

			ret = TRUE;
		} else {
			printf("! failed to map pages !\n");
		}

		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	} else {
		printf("! failed to allocate MDL !\n");
	}

	return ret;
}

PCHAR LowerStr(PCHAR str) {
	for (PCHAR s = str; *s; ++s) {
		*s = (CHAR)tolower(*s);
	}
	return str;
}

BOOL CheckMask(PCHAR base, PCHAR pattern, PCHAR mask) {
	for (; *mask; ++base, ++pattern, ++mask) {
		if (*mask == 'x' && *base != *pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask) {
	length -= (DWORD)strlen(mask);
	for (DWORD i = 0; i <= length; ++i) {
		PVOID addr = &base[i];
		if (CheckMask(addr, pattern, mask)) {
			return addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask) {
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (*(PINT)section->Name == 'EGAP' || memcmp(section->Name, ".text", 5) == 0) {
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match) {
				break;
			}
		}
	}

	return match;
}

PVOID GetBaseAddress(PCHAR name, PULONG outSize) {
	PVOID addr = 0;

	ULONG size = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		printf("! ZwQuerySystemInformation for size failed: %x !\n", status);
		return addr;
	}

	PSYSTEM_MODULE_INFORMATION modules = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'ABG');
	if (!modules) {
		printf("! failed to allocate %d bytes for modules !\n", size);
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		printf("! ZwQuerySystemInformation failed: %x !\n", status);
		ExFreePool(modules);
		return addr;
	}

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		SYSTEM_MODULE m = modules->Modules[i];

		if (strstr(LowerStr((PCHAR)m.FullPathName), name)) {
			addr = m.ImageBase;
			if (outSize) {
				*outSize = m.ImageSize;
			}
			break;
		}
	}

	ExFreePool(modules);
	return addr;
}
