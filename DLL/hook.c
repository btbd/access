#include "stdafx.h"

BYTE GetInstructionLength(BYTE table[], PBYTE instruction) {
	BYTE i = table[*instruction++];
	return i < 0x10 ? i : GetInstructionLength(INSTRUCTION_TABLES[i - 0x10], instruction);
}

BOOL SetJMP(PVOID dest, PVOID src, BYTE nops) {
	DWORD protection = 0;
	if (!VirtualProtect(src, JMP_SIZE + nops, PAGE_EXECUTE_READWRITE, &protection)) {
		return FALSE;
	}

	BYTE jmp[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };
	*(PVOID *)&jmp[6] = dest;

	memcpy(src, jmp, JMP_SIZE);
	for (BYTE i = 0; i < nops; ++i) {
		*((PBYTE)src + JMP_SIZE + i) = 0x90;
	}

	VirtualProtect(src, JMP_SIZE + nops, protection, &protection);
	return TRUE;
}

BOOL TrampolineHook(PVOID dest, PVOID src, PVOID *original) {
	BYTE length = 0;
	for (PBYTE inst = (PBYTE)src; length < JMP_SIZE; ) {
		BYTE l = GetInstructionLength(INSTRUCTION_TABLE, inst);
		if (!l) {
			return FALSE;
		}

		inst += l;
		length += l;
	}

	PVOID copy = VirtualAlloc(0, (SIZE_T)length + JMP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!copy) {
		return FALSE;
	}

	memcpy(copy, src, length);
	if (!SetJMP((PBYTE)src + length, (PBYTE)copy + length, 0)) {
		VirtualFree(copy, 0, MEM_RELEASE);
		return FALSE;
	}

	*original = copy;
	if (!SetJMP(dest, src, length - JMP_SIZE)) {
		*original = 0;
		VirtualFree(copy, 0, MEM_RELEASE);
		return FALSE;
	}

	return TRUE;
}

BOOL UnTrampolineHook(PVOID src, PVOID original) {
	BYTE length = 0;
	for (PBYTE inst = (PBYTE)original; length < JMP_SIZE; ) {
		BYTE l = GetInstructionLength(INSTRUCTION_TABLE, inst);
		if (!l) {
			return FALSE;
		}

		inst += l;
		length += l;
	}

	DWORD protection = 0;
	if (!VirtualProtect(src, length, PAGE_EXECUTE_READWRITE, &protection)) {
		return FALSE;
	}

	memcpy(src, original, length);

	VirtualProtect(src, length, protection, &protection);
	VirtualFree(original, 0, MEM_RELEASE);
	return TRUE;
}