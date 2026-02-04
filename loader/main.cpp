#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach_vm.h>
#include <mach/mach_error.h>
#include <mach/vm_attributes.h>
#include <mach/vm_page_size.h>
#include <sys/stat.h>
#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "offset_finder.hpp"

#ifndef LC_DYLD_EXPORTS_TRIE
#define LC_DYLD_EXPORTS_TRIE 0x80000033
struct dyld_exports_trie_command {
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t dataoff;
	uint32_t datasize;
};
#endif

typedef const struct dyld_process_info_base *DyldProcessInfo;
extern "C" DyldProcessInfo _dyld_process_info_create(task_t task, uint64_t timestamp, kern_return_t *kernelError);
extern "C" void _dyld_process_info_for_each_image(DyldProcessInfo info, void (^callback)(uint64_t machHeaderAddress, const uuid_t uuid, const char *path));
extern "C" void _dyld_process_info_release(DyldProcessInfo info);

static bool logsEnabled = false;

static void logMessage(const char *fmt, ...) {
	if (!logsEnabled || !fmt) {
		return;
	}
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

static std::vector<int> parsePattern(const char *pattern) {
	std::vector<int> bytes;
	if (!pattern) {
		return bytes;
	}
	std::istringstream stream(pattern);
	std::string token;
	while (stream >> token) {
		if (token.find('?') != std::string::npos) {
			bytes.push_back(-1);
			continue;
		}
		bytes.push_back(std::stoi(token, nullptr, 16));
	}
	return bytes;
}

static std::optional<uint64_t> findPatternInBuffer(const std::vector<unsigned char> &buffer,
                                                   const std::vector<int> &pattern,
                                                   uint64_t baseAddr) {
	if (pattern.empty() || buffer.size() < pattern.size()) {
		return std::nullopt;
	}
	for (size_t i = 0; i + pattern.size() <= buffer.size(); ++i) {
		bool matched = true;
		for (size_t j = 0; j < pattern.size(); ++j) {
			const int byte = pattern[j];
			if (byte >= 0 && buffer[i + j] != static_cast<unsigned char>(byte)) {
				matched = false;
				break;
			}
		}
		if (matched) {
			return baseAddr + i;
		}
	}
	return std::nullopt;
}

class MuhDebugger {
public:
	bool attach(pid_t pid) {
		childPid_ = pid;
		logMessage("Attempting to attach to %d\n", childPid_);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		if (ptrace(PT_ATTACH, childPid_, 0, 0) < 0) {
#pragma clang diagnostic pop
			perror("ptrace(PT_ATTACH)");
			return false;
		}
		if (!waitForStopped()) {
			return false;
		}
		const kern_return_t kr = task_for_pid(mach_task_self(), childPid_, &taskPort_);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "task_for_pid failed: 0x%x (%s)\n", kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool detach() {
		if (childPid_ <= 0) {
			return true;
		}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		if (ptrace(PT_DETACH, childPid_, (caddr_t)1, 0) < 0) {
#pragma clang diagnostic pop
			perror("ptrace(PT_DETACH)");
			return false;
		}
		if (taskPort_ != MACH_PORT_NULL) {
			mach_port_deallocate(mach_task_self(), taskPort_);
			taskPort_ = MACH_PORT_NULL;
		}
		return true;
	}

	task_t taskPort() const {
		return taskPort_;
	}

	bool adjustMemoryProtection(uint64_t address, vm_prot_t protection, mach_vm_size_t size) {
		if (taskPort_ == MACH_PORT_NULL) {
			return false;
		}
		const mach_vm_size_t pageMask = static_cast<mach_vm_size_t>(vm_page_size - 1);
		const mach_vm_address_t start = address & ~pageMask;
		const mach_vm_address_t end = (address + size + pageMask) & ~pageMask;
		const mach_vm_size_t length = end > start ? end - start : 0;
		if (length == 0) {
			return false;
		}
		return mach_vm_protect(taskPort_, start, length, false, protection) == KERN_SUCCESS;
	}

	bool readMemory(uint64_t address, void *buffer, size_t size) {
		if (taskPort_ == MACH_PORT_NULL || !buffer || size == 0) {
			return false;
		}
		mach_vm_size_t outSize = 0;
		const kern_return_t kr = mach_vm_read_overwrite(
		    taskPort_, address, size, reinterpret_cast<mach_vm_address_t>(buffer), &outSize);
		return kr == KERN_SUCCESS && outSize == size;
	}

	bool readMemoryQuiet(uint64_t address, void *buffer, size_t size) {
		if (taskPort_ == MACH_PORT_NULL || !buffer || size == 0) {
			return false;
		}
		mach_vm_size_t outSize = 0;
		const kern_return_t kr = mach_vm_read_overwrite(
		    taskPort_, address, size, reinterpret_cast<mach_vm_address_t>(buffer), &outSize);
		return kr == KERN_SUCCESS && outSize == size;
	}

	bool writeMemory(uint64_t address, const void *buffer, size_t size) {
		if (taskPort_ == MACH_PORT_NULL || !buffer || size == 0) {
			return false;
		}
		return mach_vm_write(taskPort_, address, reinterpret_cast<vm_offset_t>(buffer),
		                     static_cast<mach_msg_type_number_t>(size)) == KERN_SUCCESS;
	}

	bool flushInstructionCache(uint64_t address, size_t size) {
		if (taskPort_ == MACH_PORT_NULL || size == 0) {
			return false;
		}
		vm_machine_attribute_val_t val = MATTR_VAL_CACHE_FLUSH;
		return mach_vm_machine_attribute(taskPort_, address, size, MATTR_CACHE, &val) == KERN_SUCCESS;
	}

	uintptr_t findRuntime() {
		mach_port_t objectName = MACH_PORT_NULL;
		kern_return_t kr = KERN_SUCCESS;
		auto processInfo = _dyld_process_info_create(taskPort_, 0, &kr);
		if (kr == KERN_SUCCESS && processInfo) {
			__block uintptr_t runtimeAddr = 0;
			_dyld_process_info_for_each_image(processInfo, ^(uint64_t address, const uuid_t, const char *path) {
				if (path && strcmp(path, "/usr/libexec/rosetta/runtime") == 0) {
					runtimeAddr = address;
				}
			});
			_dyld_process_info_release(processInfo);
			if (runtimeAddr != 0) {
				return runtimeAddr;
			}
		}

		mach_vm_address_t address = 0;
		mach_vm_size_t size = 0;
		vm_region_basic_info_data_64_t info{};
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
		objectName = MACH_PORT_NULL;
		while (mach_vm_region(taskPort_, &address, &size, VM_REGION_BASIC_INFO_64,
		                      (vm_region_info_t)&info, &count, &objectName) == KERN_SUCCESS) {
			if (objectName != MACH_PORT_NULL) {
				mach_port_deallocate(mach_task_self(), objectName);
				objectName = MACH_PORT_NULL;
			}
			if (info.protection & (VM_PROT_EXECUTE | VM_PROT_READ)) {
				uint32_t magicBytes = 0;
				if (readMemory(address, &magicBytes, sizeof(magicBytes)) && magicBytes == MH_MAGIC_64) {
					return address;
				}
			}
			address += size;
		}
		return 0;
	}

private:
	pid_t childPid_ = -1;
	task_t taskPort_ = MACH_PORT_NULL;

	bool waitForStopped() {
		int status = 0;
		if (waitpid(childPid_, &status, 0) == -1) {
			perror("waitpid");
			return false;
		}
		if (WIFSTOPPED(status)) {
			const int signal = WSTOPSIG(status);
			logMessage("Process stopped signal=%d\n", signal);
			return true;
		}
		return false;
	}
};

static uint64_t alignUp(uint64_t value, uint64_t alignment) {
	if (alignment == 0) {
		return value;
	}
	return (value + alignment - 1) & ~(alignment - 1);
}

static bool isFileRangeZero(const char *path, uint64_t offset, size_t size) {
	if (!path || size == 0) {
		return false;
	}
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		return false;
	}
	file.seekg(0, std::ios::end);
	const std::streampos fileSize = file.tellg();
	if (fileSize <= 0 || offset + size > static_cast<uint64_t>(fileSize)) {
		return false;
	}
	file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
	std::vector<unsigned char> buffer(size);
	if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
		return false;
	}
	for (const auto byte : buffer) {
		if (byte != 0) {
			return false;
		}
	}
	return true;
}

static std::string dirName(const char *path) {
	if (!path || !*path) {
		return ".";
	}
	const char *slash = strrchr(path, '/');
	if (!slash) {
		return ".";
	}
	if (slash == path) {
		return "/";
	}
	return std::string(path, static_cast<size_t>(slash - path));
}

static bool readMachOTextSectionWithSymbol(const char *path,
                                           const char *symbolName,
                                           std::vector<uint8_t> &text,
                                           uint64_t &entryOffset) {
	text.clear();
	entryOffset = 0;
	if (!path || !symbolName) {
		return false;
	}
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		return false;
	}
	file.seekg(0, std::ios::end);
	const std::streamoff fileSize = file.tellg();
	if (fileSize <= 0) {
		return false;
	}
	file.seekg(0, std::ios::beg);
	std::vector<uint8_t> data(static_cast<size_t>(fileSize));
	if (!file.read(reinterpret_cast<char *>(data.data()), data.size())) {
		return false;
	}
	if (data.size() < sizeof(mach_header_64)) {
		return false;
	}
	const auto *header = reinterpret_cast<const mach_header_64 *>(data.data());
	if (header->magic != MH_MAGIC_64) {
		return false;
	}
	if (sizeof(mach_header_64) + header->sizeofcmds > data.size()) {
		return false;
	}

	const uint8_t *cursor = data.data() + sizeof(mach_header_64);
	const uint8_t *end = cursor + header->sizeofcmds;
	uint64_t textOffset = 0;
	uint64_t textSize = 0;
	uint64_t textAddr = 0;
	uint32_t textSectionIndex = 0;
	uint32_t symoff = 0;
	uint32_t nsyms = 0;
	uint32_t stroff = 0;
	uint32_t strsize = 0;
	uint32_t sectionIndex = 1;

	for (uint32_t i = 0; i < header->ncmds; ++i) {
		if (cursor + sizeof(load_command) > end) {
			return false;
		}
		const auto *lc = reinterpret_cast<const load_command *>(cursor);
		if (lc->cmdsize < sizeof(load_command) || cursor + lc->cmdsize > end) {
			return false;
		}
		if (lc->cmd == LC_SEGMENT_64) {
			if (lc->cmdsize < sizeof(segment_command_64)) {
				return false;
			}
			const auto *seg = reinterpret_cast<const segment_command_64 *>(cursor);
			const uint8_t *sectCursor = cursor + sizeof(segment_command_64);
			for (uint32_t s = 0; s < seg->nsects; ++s) {
				if (sectCursor + sizeof(section_64) > cursor + lc->cmdsize) {
					return false;
				}
				const auto *sect = reinterpret_cast<const section_64 *>(sectCursor);
				if (strncmp(sect->sectname, "__text", sizeof(sect->sectname)) == 0) {
					textOffset = sect->offset;
					textSize = sect->size;
					textAddr = sect->addr;
					textSectionIndex = sectionIndex;
				}
				sectionIndex++;
				sectCursor += sizeof(section_64);
			}
		} else if (lc->cmd == LC_SYMTAB) {
			const auto *symtab = reinterpret_cast<const symtab_command *>(cursor);
			symoff = symtab->symoff;
			nsyms = symtab->nsyms;
			stroff = symtab->stroff;
			strsize = symtab->strsize;
		}
		cursor += lc->cmdsize;
	}

	if (textSize == 0 || textOffset + textSize > data.size()) {
		return false;
	}
	text.assign(data.begin() + textOffset, data.begin() + textOffset + textSize);

	if (symoff == 0 || nsyms == 0 || stroff == 0 || strsize == 0) {
		return false;
	}
	if (symoff + static_cast<uint64_t>(nsyms) * sizeof(nlist_64) > data.size()) {
		return false;
	}
	if (stroff + strsize > data.size()) {
		return false;
	}
	const char *strBase = reinterpret_cast<const char *>(data.data() + stroff);

	for (uint32_t i = 0; i < nsyms; ++i) {
		const auto *sym = reinterpret_cast<const nlist_64 *>(data.data() + symoff + i * sizeof(nlist_64));
		const uint32_t strIndex = sym->n_un.n_strx;
		if (strIndex >= strsize) {
			continue;
		}
		const char *name = strBase + strIndex;
		const size_t maxLen = strsize - strIndex;
		const size_t len = strnlen(name, maxLen);
		if (len == maxLen) {
			continue;
		}
		if (strcmp(name, symbolName) != 0) {
			continue;
		}
		if (textSectionIndex != 0 && sym->n_sect != 0 && sym->n_sect != textSectionIndex) {
			return false;
		}
		if (sym->n_value >= textAddr) {
			entryOffset = sym->n_value - textAddr;
		} else {
			entryOffset = sym->n_value;
		}
		if (entryOffset >= textSize) {
			return false;
		}
		return true;
	}
	return false;
}

static uint32_t encodeMovz(uint8_t reg, uint16_t imm16, uint8_t shift) {
	const uint32_t hw = static_cast<uint32_t>((shift / 16) & 0x3u);
	return 0xD2800000u | (static_cast<uint32_t>(imm16) << 5) | (hw << 21) | (reg & 0x1fu);
}

static uint32_t encodeMovk(uint8_t reg, uint16_t imm16, uint8_t shift) {
	const uint32_t hw = static_cast<uint32_t>((shift / 16) & 0x3u);
	return 0xF2800000u | (static_cast<uint32_t>(imm16) << 5) | (hw << 21) | (reg & 0x1fu);
}

static uint32_t encodeAddImm(uint8_t dst, uint8_t src, uint16_t imm12) {
	return 0x91000000u | (static_cast<uint32_t>(imm12 & 0x0fffu) << 10) |
	       ((src & 0x1fu) << 5) | (dst & 0x1fu);
}

static uint32_t encodeSubImm(uint8_t dst, uint8_t src, uint16_t imm12) {
	return 0xD1000000u | (static_cast<uint32_t>(imm12 & 0x0fffu) << 10) |
	       ((src & 0x1fu) << 5) | (dst & 0x1fu);
}

static uint32_t encodeStrImm(uint8_t rt, uint8_t rn, uint16_t immBytes) {
	const uint32_t imm12 = static_cast<uint32_t>((immBytes >> 3) & 0x0fffu);
	return 0xF9000000u | (imm12 << 10) | ((rn & 0x1fu) << 5) | (rt & 0x1fu);
}

static uint32_t encodeLdrImm(uint8_t rt, uint8_t rn, uint16_t immBytes) {
	const uint32_t imm12 = static_cast<uint32_t>((immBytes >> 3) & 0x0fffu);
	return 0xF9400000u | (imm12 << 10) | ((rn & 0x1fu) << 5) | (rt & 0x1fu);
}

static uint32_t encodeStpImm(uint8_t rt, uint8_t rt2, uint8_t rn, int16_t immBytes) {
	const int16_t imm7 = static_cast<int16_t>(immBytes >> 3);
	return 0xA9000000u | ((static_cast<uint32_t>(imm7) & 0x7fu) << 15) |
	       ((rt2 & 0x1fu) << 10) | ((rn & 0x1fu) << 5) | (rt & 0x1fu);
}

static uint32_t encodeLdpImm(uint8_t rt, uint8_t rt2, uint8_t rn, int16_t immBytes) {
	const int16_t imm7 = static_cast<int16_t>(immBytes >> 3);
	return 0xA9400000u | ((static_cast<uint32_t>(imm7) & 0x7fu) << 15) |
	       ((rt2 & 0x1fu) << 10) | ((rn & 0x1fu) << 5) | (rt & 0x1fu);
}

static uint32_t encodeBlr(uint8_t reg) {
	return 0xD63F0000u | (static_cast<uint32_t>(reg & 0x1fu) << 5);
}

static void encodeAbsoluteBranch(uint64_t target, uint8_t reg, uint32_t outInstrs[5]) {
	outInstrs[0] = encodeMovz(reg, static_cast<uint16_t>(target & 0xffffu), 0);
	outInstrs[1] = encodeMovk(reg, static_cast<uint16_t>((target >> 16) & 0xffffu), 16);
	outInstrs[2] = encodeMovk(reg, static_cast<uint16_t>((target >> 32) & 0xffffu), 32);
	outInstrs[3] = encodeMovk(reg, static_cast<uint16_t>((target >> 48) & 0xffffu), 48);
	outInstrs[4] = 0xD61F0000u | (static_cast<uint32_t>(reg & 0x1fu) << 5);
}

static int64_t signExtend64(int64_t value, int bits) {
	const int shift = 64 - bits;
	return (value << shift) >> shift;
}

static bool relocateInstruction(uint32_t instr, uint64_t origAddr, uint64_t newAddr, uint32_t &outInstr) {
	if ((instr & 0xFF000010u) == 0x54000000u) {
		int64_t imm19 = signExtend64((instr >> 5) & 0x7ffff, 19);
		const uint64_t target = origAddr + (imm19 << 2);
		const int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr);
		if (diff % 4 != 0) {
			return false;
		}
		const int64_t newImm = diff >> 2;
		if (newImm < -(1LL << 18) || newImm >= (1LL << 18)) {
			return false;
		}
		outInstr = (instr & 0xFF00001Fu) | ((static_cast<uint32_t>(newImm) & 0x7ffffu) << 5);
		return true;
	}
	if ((instr & 0x7C000000u) == 0x14000000u) {
		int64_t imm26 = signExtend64(instr & 0x03ffffffu, 26);
		const uint64_t target = origAddr + (imm26 << 2);
		const int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr);
		if (diff % 4 != 0) {
			return false;
		}
		const int64_t newImm = diff >> 2;
		if (newImm < -(1LL << 25) || newImm >= (1LL << 25)) {
			return false;
		}
		outInstr = 0x14000000u | (static_cast<uint32_t>(newImm) & 0x03ffffffu);
		return true;
	}
	if ((instr & 0xFC000000u) == 0x94000000u) {
		int64_t imm26 = signExtend64(instr & 0x03ffffffu, 26);
		const uint64_t target = origAddr + (imm26 << 2);
		const int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr);
		if (diff % 4 != 0) {
			return false;
		}
		const int64_t newImm = diff >> 2;
		if (newImm < -(1LL << 25) || newImm >= (1LL << 25)) {
			return false;
		}
		outInstr = 0x94000000u | (static_cast<uint32_t>(newImm) & 0x03ffffffu);
		return true;
	}
	if ((instr & 0x7F000000u) == 0x34000000u) {
		int64_t imm19 = signExtend64((instr >> 5) & 0x7ffff, 19);
		const uint64_t target = origAddr + (imm19 << 2);
		const int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr);
		if (diff % 4 != 0) {
			return false;
		}
		const int64_t newImm = diff >> 2;
		if (newImm < -(1LL << 18) || newImm >= (1LL << 18)) {
			return false;
		}
		outInstr = (instr & 0xFF00001Fu) | ((static_cast<uint32_t>(newImm) & 0x7ffffu) << 5);
		return true;
	}
	if ((instr & 0x7F000000u) == 0x36000000u || (instr & 0x7F000000u) == 0x37000000u) {
		int64_t imm14 = signExtend64((instr >> 5) & 0x3fffu, 14);
		const uint64_t target = origAddr + (imm14 << 2);
		const int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr);
		if (diff % 4 != 0) {
			return false;
		}
		const int64_t newImm = diff >> 2;
		if (newImm < -(1LL << 13) || newImm >= (1LL << 13)) {
			return false;
		}
		outInstr = (instr & 0xFFF8001Fu) | ((static_cast<uint32_t>(newImm) & 0x3fffu) << 5);
		return true;
	}
	if ((instr & 0x9F000000u) == 0x10000000u) {
		const uint32_t immlo = (instr >> 29) & 0x3u;
		const uint32_t immhi = (instr >> 5) & 0x7ffffu;
		int64_t imm = signExtend64(static_cast<int64_t>((immhi << 2) | immlo), 21);
		const uint64_t target = origAddr + static_cast<uint64_t>(imm);
		const int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr);
		if (diff < -(1LL << 20) || diff >= (1LL << 20)) {
			return false;
		}
		const uint32_t newImmlo = static_cast<uint32_t>(diff) & 0x3u;
		const uint32_t newImmhi = (static_cast<uint32_t>(diff) >> 2) & 0x7ffffu;
		outInstr = (instr & 0x9F00001Fu) | (newImmlo << 29) | (newImmhi << 5);
		return true;
	}
	if ((instr & 0x9F000000u) == 0x90000000u) {
		const uint32_t immlo = (instr >> 29) & 0x3u;
		const uint32_t immhi = (instr >> 5) & 0x7ffffu;
		int64_t imm = signExtend64(static_cast<int64_t>((immhi << 2) | immlo), 21);
		const uint64_t target = (origAddr & ~0xfffull) + (static_cast<uint64_t>(imm) << 12);
		const uint64_t newBase = newAddr & ~0xfffull;
		const int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(newBase);
		if (diff % 0x1000 != 0) {
			return false;
		}
		const int64_t newImm = diff >> 12;
		if (newImm < -(1LL << 20) || newImm >= (1LL << 20)) {
			return false;
		}
		const uint32_t newImmlo = static_cast<uint32_t>(newImm) & 0x3u;
		const uint32_t newImmhi = (static_cast<uint32_t>(newImm) >> 2) & 0x7ffffu;
		outInstr = (instr & 0x9F00001Fu) | (newImmlo << 29) | (newImmhi << 5);
		return true;
	}
	{
		const uint32_t op = instr & 0xFF000000u;
		if (op == 0x18000000u || op == 0x58000000u || op == 0x98000000u) {
			int64_t imm19 = signExtend64((instr >> 5) & 0x7ffff, 19);
			const uint64_t target = origAddr + (imm19 << 2);
			const int64_t diff = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr);
			if (diff % 4 != 0) {
				return false;
			}
			const int64_t newImm = diff >> 2;
			if (newImm < -(1LL << 18) || newImm >= (1LL << 18)) {
				return false;
			}
			outInstr = (instr & 0xFF00001Fu) | ((static_cast<uint32_t>(newImm) & 0x7ffffu) << 5);
			return true;
		}
	}
	outInstr = instr;
	return true;
}

constexpr size_t kHelperInlineDirectFormatFrameSize = 0x160;
constexpr size_t kHelperInlineDirectFormatBufferOffset = 0x60;
constexpr size_t kHelperInlineDirectFormatBufferSize = 0x100;
constexpr size_t kHelperInlineDirectFormatOrigOffset = 0x6C;
constexpr size_t kHelperInlineDirectFormatBodySize = kHelperInlineDirectFormatOrigOffset + 40;

static void fillNops(std::vector<uint8_t> &buffer) {
	static const uint8_t nop[4] = {0x1F, 0x20, 0x03, 0xD5};
	for (size_t i = 0; i + 3 < buffer.size(); i += 4) {
		memcpy(buffer.data() + i, nop, sizeof(nop));
	}
}

static bool buildHelperInlineDirectFormatStub(uint32_t originalInstr0,
                                              uint32_t originalInstr1,
                                              uint32_t originalInstr2,
                                              uint32_t originalInstr3,
                                              uint32_t originalInstr4,
                                              uint64_t stubAddr,
                                              uint64_t returnAddr,
                                              const std::vector<uint8_t> &formatterBlob,
                                              uint64_t formatterEntryOffset,
                                              std::vector<uint8_t> &outStub) {
	if (formatterBlob.empty()) {
		return false;
	}
	if (kHelperInlineDirectFormatBufferOffset + kHelperInlineDirectFormatBufferSize > kHelperInlineDirectFormatFrameSize) {
		return false;
	}
	std::vector<uint32_t> instrs;
	instrs.reserve(64);

	instrs.push_back(encodeSubImm(31, 31, kHelperInlineDirectFormatFrameSize));
	instrs.push_back(encodeStpImm(0, 1, 31, 0x00));
	instrs.push_back(encodeStpImm(2, 3, 31, 0x10));
	instrs.push_back(encodeStpImm(4, 5, 31, 0x20));
	instrs.push_back(encodeStpImm(6, 7, 31, 0x30));
	instrs.push_back(encodeStrImm(8, 31, 0x40));
	instrs.push_back(encodeStpImm(16, 17, 31, 0x48));
	instrs.push_back(encodeStrImm(30, 31, 0x58));

	instrs.push_back(encodeAddImm(0, 31, kHelperInlineDirectFormatBufferOffset));
	instrs.push_back(encodeLdrImm(1, 31, 0x48));
	instrs.push_back(encodeLdrImm(2, 31, 0x00));
	instrs.push_back(encodeLdrImm(3, 31, 0x08));
	instrs.push_back(encodeLdrImm(4, 31, 0x10));
	instrs.push_back(encodeLdrImm(5, 31, 0x18));

	const size_t bodySize = kHelperInlineDirectFormatBodySize;
	const size_t blobOffset = alignUp(bodySize, 4);
	if (formatterEntryOffset >= formatterBlob.size()) {
		return false;
	}
	const uint64_t formatterAddr = stubAddr + blobOffset + formatterEntryOffset;
	instrs.push_back(encodeMovz(16, static_cast<uint16_t>(formatterAddr & 0xffffu), 0));
	instrs.push_back(encodeMovk(16, static_cast<uint16_t>((formatterAddr >> 16) & 0xffffu), 16));
	instrs.push_back(encodeMovk(16, static_cast<uint16_t>((formatterAddr >> 32) & 0xffffu), 32));
	instrs.push_back(encodeMovk(16, static_cast<uint16_t>((formatterAddr >> 48) & 0xffffu), 48));
	instrs.push_back(encodeBlr(16));

	instrs.push_back(encodeLdrImm(30, 31, 0x58));
	instrs.push_back(encodeLdpImm(16, 17, 31, 0x48));
	instrs.push_back(encodeLdrImm(8, 31, 0x40));
	instrs.push_back(encodeLdpImm(6, 7, 31, 0x30));
	instrs.push_back(encodeLdpImm(4, 5, 31, 0x20));
	instrs.push_back(encodeLdpImm(2, 3, 31, 0x10));
	instrs.push_back(encodeLdpImm(0, 1, 31, 0x00));
	instrs.push_back(encodeAddImm(31, 31, kHelperInlineDirectFormatFrameSize));

	const size_t prologueBytes = instrs.size() * sizeof(uint32_t);
	if (prologueBytes != kHelperInlineDirectFormatOrigOffset) {
		return false;
	}

	instrs.push_back(originalInstr0);
	instrs.push_back(originalInstr1);
	instrs.push_back(originalInstr2);
	instrs.push_back(originalInstr3);
	instrs.push_back(originalInstr4);

	uint32_t branchInstrs[5] = {};
	encodeAbsoluteBranch(returnAddr, 17, branchInstrs);
	for (const auto instr : branchInstrs) {
		instrs.push_back(instr);
	}

	const size_t byteCount = instrs.size() * sizeof(uint32_t);
	if (byteCount != kHelperInlineDirectFormatBodySize) {
		return false;
	}
	const size_t totalSize = blobOffset + formatterBlob.size();
	outStub.assign(totalSize, 0);
	fillNops(outStub);
	memcpy(outStub.data(), instrs.data(), byteCount);
	memcpy(outStub.data() + blobOffset, formatterBlob.data(), formatterBlob.size());
	return true;
}

static std::optional<uint64_t> findHelperSyscallInProcess(MuhDebugger &dbg) {
	const auto pattern = parsePattern(
		"17 08 08 12 F7 7E 18 53 FF 06 00 71 ?? ?? ?? ?? FF 0A 00 71 ?? ?? ?? ?? FF 0E 00 71");
	if (pattern.empty()) {
		return std::nullopt;
	}

	mach_vm_address_t address = 0;
	mach_vm_size_t size = 0;
	vm_region_basic_info_data_64_t info{};
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t objectName = MACH_PORT_NULL;
	const mach_port_t taskPort = dbg.taskPort();

	while (mach_vm_region(taskPort, &address, &size, VM_REGION_BASIC_INFO_64,
	                      (vm_region_info_t)&info, &count, &objectName) == KERN_SUCCESS) {
		if (objectName != MACH_PORT_NULL) {
			mach_port_deallocate(mach_task_self(), objectName);
			objectName = MACH_PORT_NULL;
		}

		if (info.protection & VM_PROT_EXECUTE) {
			const size_t patLen = pattern.size();
			const size_t chunkSize = 1ull << 20;
			mach_vm_address_t offset = 0;
			while (offset < size) {
				const mach_vm_size_t remaining = size - offset;
				const mach_vm_size_t toRead = remaining > chunkSize ? chunkSize : remaining;
				std::vector<unsigned char> buffer(static_cast<size_t>(toRead));
				if (dbg.readMemoryQuiet(address + offset, buffer.data(), static_cast<size_t>(toRead))) {
					if (auto found = findPatternInBuffer(buffer, pattern, address + offset)) {
						return found;
					}
				}
				if (toRead <= patLen) {
					break;
				}
				offset += toRead - static_cast<mach_vm_size_t>(patLen - 1);
			}
		}
		address += size;
		count = VM_REGION_BASIC_INFO_COUNT_64;
	}

	return std::nullopt;
}

static bool findExecRegionForAddress(MuhDebugger &dbg,
                                     uint64_t address,
                                     mach_vm_address_t &regionStart,
                                     mach_vm_size_t &regionSize,
                                     vm_prot_t &regionProt) {
	mach_vm_address_t query = address;
	vm_region_basic_info_data_64_t info{};
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t objectName = MACH_PORT_NULL;
	const kern_return_t kr = mach_vm_region(dbg.taskPort(), &query, &regionSize, VM_REGION_BASIC_INFO_64,
	                                        (vm_region_info_t)&info, &count, &objectName);
	if (objectName != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), objectName);
	}
	if (kr != KERN_SUCCESS) {
		return false;
	}
	if (!(info.protection & VM_PROT_EXECUTE)) {
		return false;
	}
	regionStart = query;
	regionProt = info.protection;
	return true;
}

static std::optional<uint64_t> findZeroCaveInRegion(MuhDebugger &dbg,
                                                    uint64_t regionStart,
                                                    uint64_t regionSize,
                                                    uint64_t minAddr,
                                                    size_t minSize,
                                                    size_t alignment) {
	if (regionSize == 0 || minSize == 0) {
		return std::nullopt;
	}
	if (minAddr < regionStart) {
		minAddr = regionStart;
	}
	const size_t aligned = alignment ? alignment : 1;
	const uint64_t regionEnd = regionStart + regionSize;
	const uint64_t scanStart = minAddr;
	const size_t chunkSize = 1ull << 20;
	uint64_t runStart = 0;
	size_t runLen = 0;
	uint64_t cursor = scanStart;
	while (cursor < regionEnd) {
		const mach_vm_size_t remaining = regionEnd - cursor;
		const mach_vm_size_t toRead = remaining > chunkSize ? chunkSize : remaining;
		std::vector<unsigned char> buffer(static_cast<size_t>(toRead));
		if (!dbg.readMemoryQuiet(cursor, buffer.data(), static_cast<size_t>(toRead))) {
			cursor += toRead;
			runLen = 0;
			continue;
		}
		for (size_t idx = 0; idx < buffer.size(); ++idx) {
			if (buffer[idx] == 0) {
				if (runLen == 0) {
					runStart = cursor + idx;
				}
				runLen++;
			} else {
				if (runLen >= minSize) {
					const uint64_t candidate = alignUp(runStart, aligned);
					if (candidate + minSize <= runStart + runLen) {
						return candidate;
					}
				}
				runLen = 0;
			}
		}
		cursor += toRead;
	}
	if (runLen >= minSize) {
		const uint64_t candidate = alignUp(runStart, aligned);
		if (candidate + minSize <= runStart + runLen) {
			return candidate;
		}
	}
	return std::nullopt;
}

static std::optional<uint64_t> findTrailingZeroCaveInRegion(MuhDebugger &dbg,
                                                            uint64_t regionStart,
                                                            uint64_t regionSize,
                                                            size_t minSize,
                                                            size_t alignment) {
	if (regionSize == 0 || minSize == 0 || regionSize < minSize) {
		return std::nullopt;
	}
	const uint64_t regionEnd = regionStart + regionSize;
	const size_t chunkSize = 1ull << 20;
	uint64_t remaining = regionSize;
	size_t runLen = 0;
	uint64_t runStart = regionEnd;
	while (remaining > 0) {
		const uint64_t readEnd = regionStart + remaining;
		const size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunkSize, remaining));
		const uint64_t readStart = readEnd - toRead;
		std::vector<unsigned char> buffer(toRead);
		if (!dbg.readMemoryQuiet(readStart, buffer.data(), buffer.size())) {
			break;
		}
		for (size_t idx = 0; idx < buffer.size(); ++idx) {
			const size_t revIndex = buffer.size() - 1 - idx;
			if (buffer[revIndex] == 0) {
				runLen++;
				runStart = readStart + revIndex;
			} else {
				remaining = 0;
				break;
			}
		}
		if (remaining != 0) {
			remaining -= toRead;
		}
	}
	if (runLen < minSize) {
		return std::nullopt;
	}
	const uint64_t candidate = alignUp(runStart, alignment ? alignment : 1);
	if (candidate + minSize > regionEnd) {
		return std::nullopt;
	}
	return candidate;
}

struct HelperInlineState {
	uint64_t stubAddr = 0;
};

static bool setupHelperInlineHook(MuhDebugger &dbg,
                                  uint64_t helperSyscallAddr,
                                  uint64_t runtimeBase,
                                  const std::vector<uint8_t> &formatBlob,
                                  uint64_t formatEntryOffset,
                                  HelperInlineState &state) {
	mach_vm_address_t regionStart = 0;
	mach_vm_size_t regionSize = 0;
	vm_prot_t regionProt = 0;
	if (!findExecRegionForAddress(dbg, helperSyscallAddr, regionStart, regionSize, regionProt)) {
		fprintf(stderr, "Failed to locate executable region for helper_syscall.\n");
		return false;
	}
	const char *runtimePath = "/usr/libexec/rosetta/runtime";
	if (formatBlob.empty()) {
		fprintf(stderr, "Inline helper C blob is empty.\n");
		return false;
	}
	if (formatEntryOffset >= formatBlob.size()) {
		fprintf(stderr, "Inline helper C entry offset is out of range.\n");
		return false;
	}
	const size_t stubSize = alignUp(kHelperInlineDirectFormatBodySize, 4) + formatBlob.size();
	const auto trailingCave = findTrailingZeroCaveInRegion(dbg, regionStart, regionSize, stubSize, 8);
	std::optional<uint64_t> caveAddr;
	if (trailingCave && runtimeBase != 0) {
		const uint64_t fileOffset = *trailingCave - runtimeBase;
		if (isFileRangeZero(runtimePath, fileOffset, stubSize)) {
			caveAddr = trailingCave;
		}
	}
	if (!caveAddr) {
		auto candidate = findZeroCaveInRegion(dbg, regionStart, regionSize, helperSyscallAddr, stubSize, 8);
		while (candidate && runtimeBase != 0) {
			const uint64_t fileOffset = *candidate - runtimeBase;
			if (isFileRangeZero(runtimePath, fileOffset, stubSize)) {
				caveAddr = candidate;
				break;
			}
			const uint64_t nextStart = *candidate + 8;
			candidate = findZeroCaveInRegion(dbg, regionStart, regionSize, nextStart, stubSize, 8);
		}
		if (!caveAddr && candidate) {
			caveAddr = candidate;
		}
	}
	if (!caveAddr) {
		fprintf(stderr, "Failed to locate executable code cave for inline helper hook.\n");
		return false;
	}
	const uint64_t stubAddr = *caveAddr;

	uint32_t originalInstr0 = 0;
	uint32_t originalInstr1 = 0;
	uint32_t originalInstr2 = 0;
	uint32_t originalInstr3 = 0;
	uint32_t originalInstr4 = 0;
	if (!dbg.readMemory(helperSyscallAddr, &originalInstr0, sizeof(originalInstr0))) {
		fprintf(stderr, "Failed to read helper_syscall prologue for inline hook.\n");
		return false;
	}
	if (!dbg.readMemory(helperSyscallAddr + sizeof(uint32_t), &originalInstr1, sizeof(originalInstr1))) {
		fprintf(stderr, "Failed to read helper_syscall prologue for inline hook.\n");
		return false;
	}
	if (!dbg.readMemory(helperSyscallAddr + 2 * sizeof(uint32_t), &originalInstr2, sizeof(originalInstr2))) {
		fprintf(stderr, "Failed to read helper_syscall prologue for inline hook.\n");
		return false;
	}
	if (!dbg.readMemory(helperSyscallAddr + 3 * sizeof(uint32_t), &originalInstr3, sizeof(originalInstr3))) {
		fprintf(stderr, "Failed to read helper_syscall prologue for inline hook.\n");
		return false;
	}
	if (!dbg.readMemory(helperSyscallAddr + 4 * sizeof(uint32_t), &originalInstr4, sizeof(originalInstr4))) {
		fprintf(stderr, "Failed to read helper_syscall prologue for inline hook.\n");
		return false;
	}

	uint32_t relocated0 = 0;
	uint32_t relocated1 = 0;
	uint32_t relocated2 = 0;
	uint32_t relocated3 = 0;
	uint32_t relocated4 = 0;
	const uint64_t relocateBase = stubAddr + kHelperInlineDirectFormatOrigOffset;
	if (!relocateInstruction(originalInstr0, helperSyscallAddr, relocateBase, relocated0) ||
	    !relocateInstruction(originalInstr1, helperSyscallAddr + 4, relocateBase + 4, relocated1) ||
	    !relocateInstruction(originalInstr2, helperSyscallAddr + 8, relocateBase + 8, relocated2) ||
	    !relocateInstruction(originalInstr3, helperSyscallAddr + 12, relocateBase + 12, relocated3) ||
	    !relocateInstruction(originalInstr4, helperSyscallAddr + 16, relocateBase + 16, relocated4)) {
		fprintf(stderr, "Failed to relocate helper_syscall prologue for inline hook.\n");
		return false;
	}

	std::vector<uint8_t> stub;
	if (!buildHelperInlineDirectFormatStub(relocated0, relocated1, relocated2, relocated3, relocated4,
	                                       stubAddr, helperSyscallAddr + 20, formatBlob, formatEntryOffset, stub)) {
		fprintf(stderr, "Failed to build helper inline C stub.\n");
		return false;
	}

	if (!dbg.adjustMemoryProtection(stubAddr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, stub.size())) {
		fprintf(stderr, "Failed to adjust protection for helper inline stub.\n");
		return false;
	}
	if (!dbg.writeMemory(stubAddr, stub.data(), stub.size())) {
		fprintf(stderr, "Failed to write helper inline stub.\n");
		return false;
	}
	(void)dbg.flushInstructionCache(stubAddr, stub.size());
	if (!dbg.adjustMemoryProtection(stubAddr, VM_PROT_READ | VM_PROT_EXECUTE, stub.size())) {
		fprintf(stderr, "Failed to restore protection for helper inline stub.\n");
		return false;
	}

	const uint64_t targetAddr = stubAddr;
	uint32_t patchInstrs[5] = {};
	encodeAbsoluteBranch(targetAddr, 17, patchInstrs);
	if (!dbg.adjustMemoryProtection(helperSyscallAddr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, sizeof(patchInstrs))) {
		fprintf(stderr, "Failed to adjust protection for helper_syscall patch.\n");
		return false;
	}
	if (!dbg.writeMemory(helperSyscallAddr, patchInstrs, sizeof(patchInstrs))) {
		fprintf(stderr, "Failed to patch helper_syscall entry for inline hook.\n");
		return false;
	}
	(void)dbg.flushInstructionCache(helperSyscallAddr, sizeof(patchInstrs));
	if (!dbg.adjustMemoryProtection(helperSyscallAddr, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(patchInstrs))) {
		fprintf(stderr, "Failed to restore protection for helper_syscall patch.\n");
		return false;
	}

	state.stubAddr = stubAddr;

	uint32_t patchedInstrs[5] = {};
	if (dbg.readMemory(helperSyscallAddr, patchedInstrs, sizeof(patchedInstrs))) {
		logMessage("helper_inline patched instrs=0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
		    patchedInstrs[0], patchedInstrs[1], patchedInstrs[2], patchedInstrs[3], patchedInstrs[4]);
	}
	return true;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "%s <path to program>\n", argv[0]);
		return 1;
	}

	logsEnabled = getenv("ASTROWINE_LOGS") != nullptr;
	const bool inlineHelperHook = getenv("ASTROWINE_HELPER_INLINE") != nullptr;
	const bool inlineCStubRequested = getenv("ASTROWINE_HELPER_INLINE_C") != nullptr;
	const char *inlineCPathEnv = getenv("ASTROWINE_HELPER_INLINE_C_PATH");
	if (!inlineHelperHook || !inlineCStubRequested) {
		fprintf(stderr, "Set ASTROWINE_HELPER_INLINE=1 and ASTROWINE_HELPER_INLINE_C=1 to enable hooks.\n");
		return 1;
	}

	logMessage("Launching debugger.\n");

	pid_t child = fork();
	if (child == 0) {
		if (ptrace(PT_TRACE_ME, 0, nullptr, 0) == -1) {
			perror("child: ptrace(PT_TRACE_ME)");
			return 1;
		}
		logMessage("child: launching into program: %s\n", argv[1]);
		execv(argv[1], &argv[1]);
		return 1;
	}

	MuhDebugger dbg;
	if (!dbg.attach(child)) {
		fprintf(stderr, "Failed to attach to process\n");
		return 1;
	}
	logMessage("Attached successfully\n");

	OffsetFinder offsetFinder;
	offsetFinder.setDefaultOffsets();
	if (!offsetFinder.determineOffsets()) {
		fprintf(stderr, "Failed to locate helper patterns in Rosetta runtime.\n");
		dbg.detach();
		return 1;
	}
	logMessage("Found rosetta runtime helper offsets successfully!\n");
	logMessage("offset_helper_syscall=%llx\n", offsetFinder.offsetHelperSyscall_);

	uint64_t runtimeBase = dbg.findRuntime();
	uint64_t helperSyscallAddr = 0;
	if (auto inProcessHelper = findHelperSyscallInProcess(dbg)) {
		const uint64_t helperAddr = *inProcessHelper;
		helperSyscallAddr = helperAddr;
		if (offsetFinder.offsetHelperSyscall_ != 0) {
			runtimeBase = helperAddr - offsetFinder.offsetHelperSyscall_;
		}
	} else if (runtimeBase != 0) {
		helperSyscallAddr = runtimeBase + offsetFinder.offsetHelperSyscall_;
	}

	logMessage("Rosetta runtime base: 0x%llx\n", static_cast<unsigned long long>(runtimeBase));
	if (runtimeBase == 0 || helperSyscallAddr == 0) {
		fprintf(stderr, "Rosetta runtime not found; running without hooks.\n");
		dbg.detach();
		return 1;
	}
	logMessage("helper_syscall address: 0x%llx\n", helperSyscallAddr);

	std::vector<uint8_t> inlineBlob;
	uint64_t inlineEntryOffset = 0;
	std::string blobPath;
	if (inlineCPathEnv && *inlineCPathEnv) {
		blobPath = inlineCPathEnv;
	} else {
		blobPath = dirName(argv[0]);
		blobPath += "/helper_syscall_inline_c.o";
	}
	if (!readMachOTextSectionWithSymbol(blobPath.c_str(), "_rosetta_helper_syscall_inline",
	                                    inlineBlob, inlineEntryOffset)) {
		fprintf(stderr, "Failed to load inline helper C text from %s\n", blobPath.c_str());
		dbg.detach();
		return 1;
	}
	logMessage("inline_c blob loaded from %s (%zu bytes, entry 0x%llx)\n",
	    blobPath.c_str(), inlineBlob.size(), static_cast<unsigned long long>(inlineEntryOffset));

	HelperInlineState helperInlineState;
	if (!setupHelperInlineHook(dbg, helperSyscallAddr, runtimeBase, inlineBlob, inlineEntryOffset, helperInlineState)) {
		fprintf(stderr, "Inline helper hook failed.\n");
		dbg.detach();
		return 1;
	}
	logMessage("helper_inline stub at 0x%llx\n", static_cast<unsigned long long>(helperInlineState.stubAddr));

	if (!dbg.detach()) {
		fprintf(stderr, "Failed to detach debugger\n");
		return 1;
	}
	return 0;
}
