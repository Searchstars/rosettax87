#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <thread>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach/vm_attributes.h>
#include <sys/stat.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include "offset_finder.hpp"
#include "../payload/rosetta_inline_shared.h"

typedef const struct dyld_process_info_base *DyldProcessInfo;
extern "C" DyldProcessInfo _dyld_process_info_create(task_t task, uint64_t timestamp, kern_return_t *kernelError);
extern "C" void _dyld_process_info_for_each_image(DyldProcessInfo info, void (^callback)(uint64_t machHeaderAddress, const uuid_t uuid, const char *path));
extern "C" void _dyld_process_info_release(DyldProcessInfo info);

const char *logsEnabled = nullptr;
static bool hookLogsEnabled = true;
static bool hookLogInitialized = false;
static int hookLogFd = -1;
static int hookLogSinkFd = STDERR_FILENO;
constexpr uint64_t kInlineMapCapacity = 1ull << 18;
constexpr uint64_t kInlineListCapacity = 1ull << 18;
constexpr uint64_t kWineCtrlScanMaxBytesDefault = 2048ull << 20;
constexpr uint64_t kWineCtrlScanMaxMillisDefault = 6000;
constexpr uint64_t kWineCtrlScanDelayMillisDefault = 200;
constexpr uint64_t kWineCtrlScanRetryCountDefault = 0;
constexpr uint64_t kInlineStateSampleMillisDefault = 0;
constexpr uint64_t kInlineStateSampleCountDefault = 1;

static void initHookLog() {
	if (hookLogInitialized) {
		return;
	}
	hookLogInitialized = true;

	const char *env = getenv("ASTROWINE_HOOK_LOGS");
	if (env && strcmp(env, "0") == 0) {
		hookLogsEnabled = false;
		return;
	}

	const char *logPath = getenv("ASTROWINE_HOOK_LOG_PATH");
	if (logPath && *logPath) {
		const int fd = open(logPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (fd >= 0) {
			hookLogSinkFd = fd;
		}
	}

	int pipeFds[2];
	if (pipe(pipeFds) == 0) {
		hookLogFd = pipeFds[1];
		const int readFd = pipeFds[0];
		const int flags = fcntl(hookLogFd, F_GETFL, 0);
		if (flags != -1) {
			(void)fcntl(hookLogFd, F_SETFL, flags | O_NONBLOCK);
		}
		std::thread([readFd]() {
			char buffer[4096];
			while (true) {
				const ssize_t bytes = read(readFd, buffer, sizeof(buffer));
				if (bytes <= 0) {
					break;
				}
				ssize_t offset = 0;
				while (offset < bytes) {
					const ssize_t written = write(hookLogSinkFd, buffer + offset, static_cast<size_t>(bytes - offset));
					if (written < 0) {
						if (errno == EINTR) {
							continue;
						}
						break;
					}
					offset += written;
				}
			}
			close(readFd);
		}).detach();
	} else {
		hookLogFd = hookLogSinkFd;
	}
}

static void hookLog(const char *fmt, ...) {
	initHookLog();
	if (!hookLogsEnabled) {
		return;
	}

	char buffer[512];
	va_list args;
	va_start(args, fmt);
	const int len = vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	if (len <= 0) {
		return;
	}

	const size_t toWrite = static_cast<size_t>(len < static_cast<int>(sizeof(buffer)) ? len : static_cast<int>(sizeof(buffer)));
	const ssize_t written = write(hookLogFd, buffer, toWrite);
	if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		return;
	}
}

#define LOG(fmt, ...)                   \
    do {                                \
        if (logsEnabled) {              \
            printf(fmt, ##__VA_ARGS__); \
        }                               \
    } while (0)

static bool readFileAt(const char *path, uint64_t offset, void *buffer, size_t size) {
	if (!path || !buffer || size == 0) {
		return false;
	}
	const int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return false;
	}
	const ssize_t bytes = pread(fd, buffer, size, static_cast<off_t>(offset));
	close(fd);
	return bytes == static_cast<ssize_t>(size);
}

static uint64_t parseEnvU64(const char *name, uint64_t fallback) {
	const char *value = getenv(name);
	if (!value || !*value) {
		return fallback;
	}
	char *end = nullptr;
	const unsigned long long parsed = strtoull(value, &end, 0);
	if (end == value) {
		return fallback;
	}
	return static_cast<uint64_t>(parsed);
}

static bool readMachOTextSectionWithSymbols(const char *path,
                                            const char *symbolA,
                                            uint64_t &offsetA,
                                            const char *symbolB,
                                            uint64_t &offsetB,
                                            std::vector<uint8_t> &out) {
	bool foundA = false;
	bool foundB = false;
	offsetA = 0;
	offsetB = 0;
	if (!path || !symbolA || !symbolB) {
		return false;
	}
	struct stat st {};
	if (stat(path, &st) != 0 || st.st_size <= 0) {
		return false;
	}
	mach_header_64 header {};
	if (!readFileAt(path, 0, &header, sizeof(header))) {
		return false;
	}
	if (header.magic != MH_MAGIC_64 || header.ncmds == 0 || header.sizeofcmds == 0) {
		return false;
	}
	if (header.sizeofcmds > static_cast<uint32_t>(st.st_size)) {
		return false;
	}
	std::vector<uint8_t> cmds(header.sizeofcmds);
	if (!readFileAt(path, sizeof(header), cmds.data(), cmds.size())) {
		return false;
	}
	uint64_t textOffset = 0;
	uint64_t textSize = 0;
	uint64_t textAddr = 0;
	uint32_t textSectionIndex = 0;
	const symtab_command *symtab = nullptr;
	size_t offset = 0;
	uint32_t sectionIndex = 1;
	for (uint32_t i = 0; i < header.ncmds && offset + sizeof(load_command) <= cmds.size(); ++i) {
		const auto *cmd = reinterpret_cast<const load_command *>(cmds.data() + offset);
		if (cmd->cmdsize < sizeof(load_command) || offset + cmd->cmdsize > cmds.size()) {
			return false;
		}
		if (cmd->cmd == LC_SEGMENT_64 && cmd->cmdsize >= sizeof(segment_command_64)) {
			const auto *seg = reinterpret_cast<const segment_command_64 *>(cmd);
			const auto *sect = reinterpret_cast<const section_64 *>(seg + 1);
			for (uint32_t s = 0; s < seg->nsects; ++s) {
				if (reinterpret_cast<const uint8_t *>(sect + 1) > cmds.data() + offset + cmd->cmdsize) {
					return false;
				}
				const bool isTextSeg = (strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) == 0) ||
				                       (seg->segname[0] == '\0' && strncmp(sect->segname, "__TEXT", sizeof(sect->segname)) == 0);
				if (isTextSeg && strncmp(sect->sectname, "__text", sizeof(sect->sectname)) == 0) {
					textOffset = sect->offset;
					textSize = sect->size;
					textAddr = sect->addr;
					textSectionIndex = sectionIndex;
				}
				++sect;
				++sectionIndex;
			}
		} else if (cmd->cmd == LC_SYMTAB && cmd->cmdsize >= sizeof(symtab_command)) {
			symtab = reinterpret_cast<const symtab_command *>(cmd);
		}
		offset += cmd->cmdsize;
	}
	if (textSize == 0 || textOffset + textSize > static_cast<uint64_t>(st.st_size)) {
		return false;
	}
	out.resize(static_cast<size_t>(textSize));
	if (!readFileAt(path, textOffset, out.data(), out.size())) {
		return false;
	}
	if (!symtab || symtab->nsyms == 0 || symtab->stroff == 0 || symtab->stroff > static_cast<uint32_t>(st.st_size)) {
		return false;
	}
	const uint64_t symtabSize = static_cast<uint64_t>(symtab->nsyms) * sizeof(nlist_64);
	if (symtab->symoff + symtabSize > static_cast<uint64_t>(st.st_size)) {
		return false;
	}
	std::vector<nlist_64> symbols(symtab->nsyms);
	if (!readFileAt(path, symtab->symoff, symbols.data(), symtabSize)) {
		return false;
	}
	const uint64_t strTableSize = static_cast<uint64_t>(st.st_size) - symtab->stroff;
	std::vector<char> strings(strTableSize);
	if (!readFileAt(path, symtab->stroff, strings.data(), strings.size())) {
		return false;
	}
	for (const auto &sym : symbols) {
		if ((sym.n_type & N_TYPE) != N_SECT || sym.n_sect != textSectionIndex) {
			continue;
		}
		if (sym.n_un.n_strx == 0 || sym.n_un.n_strx >= strings.size()) {
			continue;
		}
		const char *name = strings.data() + sym.n_un.n_strx;
		if (strcmp(name, symbolA) == 0) {
			if (sym.n_value < textAddr) {
				return false;
			}
			offsetA = sym.n_value - textAddr;
			if (offsetA >= textSize) {
				return false;
			}
			foundA = true;
			if (foundB) {
				return true;
			}
			continue;
		}
		if (strcmp(name, symbolB) == 0) {
			if (sym.n_value < textAddr) {
				return false;
			}
			offsetB = sym.n_value - textAddr;
			if (offsetB >= textSize) {
				return false;
			}
			foundB = true;
			if (foundA) {
				return true;
			}
		}
	}
	return false;
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
	return std::string(path, slash);
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

static uint32_t encodeMovz(uint8_t reg, uint16_t imm16, uint8_t shift) {
	const uint32_t hw = static_cast<uint32_t>((shift / 16) & 0x3u);
	return 0xD2800000u | (static_cast<uint32_t>(imm16) << 5) | (hw << 21) | (reg & 0x1fu);
}

static uint32_t encodeMovk(uint8_t reg, uint16_t imm16, uint8_t shift) {
	const uint32_t hw = static_cast<uint32_t>((shift / 16) & 0x3u);
	return 0xF2800000u | (static_cast<uint32_t>(imm16) << 5) | (hw << 21) | (reg & 0x1fu);
}

static uint32_t encodeAddImm(uint8_t dst, uint8_t src, uint16_t imm12) {
	return 0x91000000u | (static_cast<uint32_t>(imm12 & 0x0fffu) << 10) | ((src & 0x1fu) << 5) | (dst & 0x1fu);
}

static uint32_t encodeSubImm(uint8_t dst, uint8_t src, uint16_t imm12) {
	return 0xD1000000u | (static_cast<uint32_t>(imm12 & 0x0fffu) << 10) | ((src & 0x1fu) << 5) | (dst & 0x1fu);
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

static uint32_t encodeRet() {
	return 0xD65F03C0u;
}

static void encodeAbsoluteBranch(uint64_t target, uint8_t reg, uint32_t outInstrs[5]) {
	outInstrs[0] = encodeMovz(reg, static_cast<uint16_t>(target & 0xffffu), 0);
	outInstrs[1] = encodeMovk(reg, static_cast<uint16_t>((target >> 16) & 0xffffu), 16);
	outInstrs[2] = encodeMovk(reg, static_cast<uint16_t>((target >> 32) & 0xffffu), 32);
	outInstrs[3] = encodeMovk(reg, static_cast<uint16_t>((target >> 48) & 0xffffu), 48);
	outInstrs[4] = 0xD61F0000u | (static_cast<uint32_t>(reg & 0x1fu) << 5); // br xN
}

static int64_t signExtend64(int64_t value, int bits) {
	const int shift = 64 - bits;
	return (value << shift) >> shift;
}

static bool relocateInstruction(uint32_t instr, uint64_t origAddr, uint64_t newAddr, uint32_t &outInstr) {
	// B.cond
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
	// B (unconditional)
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
	// BL (call)
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
	// CBZ/CBNZ
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
	// TBZ/TBNZ
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
	// ADR
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
	// ADRP
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
	// LDR literal (32/64) or LDRSW literal
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
	// Other instructions: unchanged
	outInstr = instr;
	return true;
}

constexpr size_t kHelperInlineDirectFormatFrameSize = 0x160;
constexpr size_t kHelperInlineDirectFormatBufferOffset = 0x60;
constexpr size_t kHelperInlineDirectFormatBufferSize = 0x100;
constexpr size_t kHelperInlineDirectFormatOrigOffset = 0x74;
constexpr size_t kHelperInlineDirectFormatBodySize = kHelperInlineDirectFormatOrigOffset + 40;
constexpr size_t kHelperInlineWrapperRetOffset = 0x60;
constexpr size_t kHelperInlineWrapperBodySize = 0x94;
constexpr size_t kHelperInlineWrapperTrampSize = 40;

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

	// Stack frame includes saved regs + output buffer.
	instrs.push_back(encodeSubImm(31, 31, kHelperInlineDirectFormatFrameSize));
	instrs.push_back(encodeStpImm(0, 1, 31, 0x00));
	instrs.push_back(encodeStpImm(2, 3, 31, 0x10));
	instrs.push_back(encodeStpImm(4, 5, 31, 0x20));
	instrs.push_back(encodeStpImm(6, 7, 31, 0x30));
	instrs.push_back(encodeStrImm(8, 31, 0x40));
	instrs.push_back(encodeStpImm(16, 17, 31, 0x48));
	instrs.push_back(encodeStrImm(30, 31, 0x58));

	instrs.push_back(encodeAddImm(0, 31, kHelperInlineDirectFormatBufferOffset)); // x0 = buffer
	instrs.push_back(encodeLdrImm(1, 31, 0x00)); // x1 = saved x0
	instrs.push_back(encodeLdrImm(2, 31, 0x08)); // x2 = saved x1
	instrs.push_back(encodeLdrImm(3, 31, 0x10)); // x3 = saved x2
	instrs.push_back(encodeLdrImm(4, 31, 0x18)); // x4 = saved x3
	instrs.push_back(encodeLdrImm(5, 31, 0x20)); // x5 = saved x4
	instrs.push_back(encodeLdrImm(6, 31, 0x28)); // x6 = saved x5
	instrs.push_back(encodeLdrImm(7, 31, 0x58)); // x7 = saved x30 (return address)

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

static void patchMovSequence(std::vector<uint32_t> &instrs, size_t index, int reg, uint64_t value) {
	instrs[index + 0] = encodeMovz(reg, static_cast<uint16_t>(value & 0xffffu), 0);
	instrs[index + 1] = encodeMovk(reg, static_cast<uint16_t>((value >> 16) & 0xffffu), 16);
	instrs[index + 2] = encodeMovk(reg, static_cast<uint16_t>((value >> 32) & 0xffffu), 32);
	instrs[index + 3] = encodeMovk(reg, static_cast<uint16_t>((value >> 48) & 0xffffu), 48);
}

static bool buildHelperInlineWrapperStub(uint32_t originalInstr0,
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
	if (formatterEntryOffset >= formatterBlob.size()) {
		return false;
	}

	std::vector<uint32_t> instrs;
	instrs.reserve(96);

	// Save volatile regs + output scratch.
	instrs.push_back(encodeSubImm(31, 31, kHelperInlineDirectFormatFrameSize));
	instrs.push_back(encodeStpImm(0, 1, 31, 0x00));
	instrs.push_back(encodeStpImm(2, 3, 31, 0x10));
	instrs.push_back(encodeStpImm(4, 5, 31, 0x20));
	instrs.push_back(encodeStpImm(6, 7, 31, 0x30));
	instrs.push_back(encodeStrImm(8, 31, 0x40));
	instrs.push_back(encodeStpImm(16, 17, 31, 0x48));
	instrs.push_back(encodeStrImm(30, 31, 0x58));

	// Call trampoline (original function).
	const size_t trampMovIndex = instrs.size();
	instrs.push_back(encodeMovz(16, 0, 0));
	instrs.push_back(encodeMovk(16, 0, 16));
	instrs.push_back(encodeMovk(16, 0, 32));
	instrs.push_back(encodeMovk(16, 0, 48));
	instrs.push_back(encodeBlr(16));

	// Save return value.
	instrs.push_back(encodeStrImm(0, 31, kHelperInlineWrapperRetOffset));

	// Prepare args for inline payload.
	instrs.push_back(encodeAddImm(0, 31, kHelperInlineWrapperRetOffset)); // x0 = scratch
	instrs.push_back(encodeLdrImm(1, 31, 0x00));                          // x1 = saved x0
	instrs.push_back(encodeLdrImm(2, 31, 0x08));                          // x2 = saved x1
	instrs.push_back(encodeLdrImm(3, 31, 0x10));                          // x3 = saved x2
	instrs.push_back(encodeLdrImm(4, 31, 0x18));                          // x4 = saved x3
	instrs.push_back(encodeLdrImm(5, 31, 0x20));                          // x5 = saved x4
	instrs.push_back(encodeLdrImm(6, 31, 0x28));                          // x6 = saved x5
	instrs.push_back(encodeLdrImm(7, 31, kHelperInlineWrapperRetOffset)); // x7 = return value

	const size_t payloadMovIndex = instrs.size();
	instrs.push_back(encodeMovz(16, 0, 0));
	instrs.push_back(encodeMovk(16, 0, 16));
	instrs.push_back(encodeMovk(16, 0, 32));
	instrs.push_back(encodeMovk(16, 0, 48));
	instrs.push_back(encodeBlr(16));

	// Restore regs (x0 overwritten later with return value).
	instrs.push_back(encodeLdrImm(30, 31, 0x58));
	instrs.push_back(encodeLdpImm(16, 17, 31, 0x48));
	instrs.push_back(encodeLdrImm(8, 31, 0x40));
	instrs.push_back(encodeLdpImm(6, 7, 31, 0x30));
	instrs.push_back(encodeLdpImm(4, 5, 31, 0x20));
	instrs.push_back(encodeLdpImm(2, 3, 31, 0x10));
	instrs.push_back(encodeLdpImm(0, 1, 31, 0x00));
	instrs.push_back(encodeLdrImm(0, 31, kHelperInlineWrapperRetOffset)); // restore return value
	instrs.push_back(encodeAddImm(31, 31, kHelperInlineDirectFormatFrameSize));
	instrs.push_back(encodeRet());

	const size_t bodySize = instrs.size() * sizeof(uint32_t);
	if (bodySize != kHelperInlineWrapperBodySize) {
		return false;
	}
	const size_t trampOffset = alignUp(bodySize, 4);
	const size_t trampSize = kHelperInlineWrapperTrampSize;
	const size_t blobOffset = alignUp(trampOffset + trampSize, 4);
	const size_t totalSize = blobOffset + formatterBlob.size();
	outStub.assign(totalSize, 0);
	fillNops(outStub);

	const uint64_t trampolineAddr = stubAddr + trampOffset;
	const uint64_t payloadAddr = stubAddr + blobOffset + formatterEntryOffset;
	patchMovSequence(instrs, trampMovIndex, 16, trampolineAddr);
	patchMovSequence(instrs, payloadMovIndex, 16, payloadAddr);
	memcpy(outStub.data(), instrs.data(), bodySize);

	// Build trampoline: relocated prologue + branch to return address.
	std::vector<uint32_t> tramp;
	tramp.reserve(16);
	tramp.push_back(originalInstr0);
	tramp.push_back(originalInstr1);
	tramp.push_back(originalInstr2);
	tramp.push_back(originalInstr3);
	tramp.push_back(originalInstr4);
	uint32_t branchInstrs[5] = {};
	encodeAbsoluteBranch(returnAddr, 17, branchInstrs);
	for (const auto instr : branchInstrs) {
		tramp.push_back(instr);
	}
	memcpy(outStub.data() + trampOffset, tramp.data(), tramp.size() * sizeof(uint32_t));
	memcpy(outStub.data() + blobOffset, formatterBlob.data(), formatterBlob.size());
	return true;
}

class MuhDebugger {
public:
	~MuhDebugger() {
		if (taskPort_ != MACH_PORT_NULL) {
			mach_port_deallocate(mach_task_self(), taskPort_);
		}
	}

	bool attach(pid_t pid) {
		childPid_ = pid;
		LOG("Attempting to attach to %d\n", childPid_);
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
		LOG("Program stopped due to debugger being attached\n");

		if (!continueExecution()) {
			fprintf(stderr, "Failed to continue execution\n");
			return false;
		}
		if (task_for_pid(mach_task_self(), childPid_, &taskPort_) != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get task port for pid %d\n", childPid_);
			return false;
		}
		LOG("Program stopped due to execv into rosetta process.\n");
		LOG("Started debugging process %d using port %d\n", childPid_, taskPort_);
		return true;
	}

	bool detach() {
		if (ptrace(PT_DETACH, childPid_, (caddr_t)1, 0) < 0) {
			perror("ptrace(PT_DETACH)");
			return false;
		}
		LOG("Debugger detached.\n");
		return true;
	}

	task_t taskPort() const {
		return taskPort_;
	}

	pid_t pid() const {
		return childPid_;
	}

	bool runForMillis(uint64_t millis) {
		if (ptrace(PT_CONTINUE, childPid_, (caddr_t)1, 0) < 0) {
			perror("ptrace(PT_CONTINUE)");
			return false;
		}
		if (millis) {
			std::this_thread::sleep_for(std::chrono::milliseconds(millis));
		}
		if (kill(childPid_, SIGSTOP) < 0) {
			perror("kill(SIGSTOP)");
			return false;
		}
		return waitForStopped();
	}

	bool adjustMemoryProtection(uint64_t address, vm_prot_t protection, mach_vm_size_t size) {
		const vm_size_t pageSize = 0x1000;
		mach_vm_address_t region = address & ~(pageSize - 1);
		size = ((address + size + pageSize - 1) & ~(pageSize - 1)) - region;

		LOG("Adjusting memory protection at 0x%llx - 0x%llx\n", (uint64_t)region, (uint64_t)(region + size));

		const kern_return_t kr = mach_vm_protect(taskPort_, region, size, false, protection);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to adjust memory protection at 0x%llx - 0x%llx (error 0x%x: %s)\n",
			        (uint64_t)region, (uint64_t)(region + size), kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool readMemory(uint64_t address, void *buffer, size_t size) {
		mach_vm_size_t readSize;
		const kern_return_t kr = mach_vm_read_overwrite(taskPort_, address, size, (mach_vm_address_t)buffer, &readSize);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to read memory at 0x%llx (error 0x%x: %s)\n", address, kr, mach_error_string(kr));
			return false;
		}
		return readSize == size;
	}

	bool readMemoryQuiet(uint64_t address, void *buffer, size_t size) {
		mach_vm_size_t readSize = 0;
		const kern_return_t kr = mach_vm_read_overwrite(taskPort_, address, size, (mach_vm_address_t)buffer, &readSize);
		return kr == KERN_SUCCESS && readSize == size;
	}

	bool writeMemory(uint64_t address, const void *buffer, size_t size) {
		const kern_return_t kr = mach_vm_write(taskPort_, address, (vm_offset_t)buffer, size);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to write memory at 0x%llx (error 0x%x: %s)\n", address, kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool flushInstructionCache(uint64_t address, size_t size) {
		const vm_size_t pageSize = 0x1000;
		const mach_vm_address_t region = address & ~(static_cast<mach_vm_address_t>(pageSize - 1));
		const mach_vm_size_t regionSize =
			((address + size + pageSize - 1) & ~(static_cast<mach_vm_address_t>(pageSize - 1))) - region;
		int value = MATTR_VAL_CACHE_FLUSH;
		const kern_return_t kr = mach_vm_machine_attribute(taskPort_, region, regionSize, MATTR_CACHE, &value);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to flush icache at 0x%llx (error 0x%x: %s)\n",
			        static_cast<unsigned long long>(region), kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool allocateMemory(uint64_t size, uint64_t &address) {
		const vm_size_t pageSize = 0x1000;
		const uint64_t aligned = (size + pageSize - 1) & ~(static_cast<uint64_t>(pageSize - 1));
		mach_vm_address_t addr = 0;
		const kern_return_t kr = mach_vm_allocate(taskPort_, &addr, aligned, VM_FLAGS_ANYWHERE);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to allocate %llu bytes in target (error 0x%x: %s)\n",
			        static_cast<unsigned long long>(aligned), kr, mach_error_string(kr));
			return false;
		}
		address = addr;
		return true;
	}

	auto findRuntime() -> uintptr_t {
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
		mach_vm_size_t size;
		vm_region_basic_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
		objectName = MACH_PORT_NULL;
		kr = KERN_SUCCESS;
		__block std::vector<uintptr_t> moduleList;

		processInfo = _dyld_process_info_create(taskPort_, 0, &kr);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get dyld process info (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return 0;
		}
		_dyld_process_info_for_each_image(processInfo, ^(uint64_t address, const uuid_t, const char *) { moduleList.push_back(address); });
		_dyld_process_info_release(processInfo);

		while (true) {
			if (mach_vm_region(taskPort_, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &objectName) != KERN_SUCCESS) {
				break;
			}

			if (info.protection & (VM_PROT_EXECUTE | VM_PROT_READ)) {
				if (std::find_if(moduleList.begin(), moduleList.end(), [address](const uintptr_t &moduleAddress) { return address == moduleAddress; }) == moduleList.end()) {
					uint32_t magicBytes;
					if (readMemory(address, &magicBytes, sizeof(magicBytes)) && magicBytes == MH_MAGIC_64) {
						return address;
					}
				}
			}

			address += size;
		}

		return 0;
	}

private:
	bool waitForStopped() {
		int status;
		if (waitpid(childPid_, &status, 0) == -1) {
			perror("waitpid");
			return false;
		}
		if (WIFSTOPPED(status)) {
			int signal = WSTOPSIG(status);
			LOG("Process stopped signal=%d\n", signal);
			return true;
		}
		if (WIFEXITED(status)) {
			LOG("Process exited status=%d\n", WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			LOG("Process terminated signal=%d\n", WTERMSIG(status));
		}
		return false;
	}

	bool continueExecution() {
		if (ptrace(PT_CONTINUE, childPid_, (caddr_t)1, 0) < 0) {
			perror("ptrace(PT_CONTINUE)");
			return false;
		}

		LOG("continueExecution...\n");

		return waitForStopped();
	}

	pid_t childPid_ = -1;
	task_t taskPort_ = MACH_PORT_NULL;
};

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

static std::optional<uint64_t> findPatternInProcess(MuhDebugger &dbg,
                                                    const uint8_t *pattern,
                                                    size_t patternSize,
                                                    uint64_t maxBytes,
                                                    uint64_t maxMillis) {
	if (!pattern || patternSize == 0) {
		return std::nullopt;
	}
	const size_t chunkSize = 1ull << 20;
	mach_vm_address_t address = 0;
	uint64_t scanned = 0;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(maxMillis);
	while (true) {
		if (maxMillis && std::chrono::steady_clock::now() > deadline) {
			break;
		}
		if (maxBytes && scanned >= maxBytes) {
			break;
		}
		mach_vm_size_t regionSize = 0;
		vm_region_basic_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
		mach_port_t objectName = MACH_PORT_NULL;
		const kern_return_t kr = mach_vm_region(dbg.taskPort(), &address, &regionSize,
		                                        VM_REGION_BASIC_INFO_64,
		                                        reinterpret_cast<vm_region_info_t>(&info),
		                                        &count, &objectName);
		if (kr != KERN_SUCCESS) {
			break;
		}
		if (objectName != MACH_PORT_NULL) {
			mach_port_deallocate(mach_task_self(), objectName);
		}
		if (!(info.protection & VM_PROT_READ)) {
			address += regionSize;
			continue;
		}

		std::vector<uint8_t> buffer(chunkSize + patternSize);
		size_t carry = 0;
		for (mach_vm_size_t offset = 0; offset < regionSize; offset += chunkSize) {
			if (maxMillis && std::chrono::steady_clock::now() > deadline) {
				return std::nullopt;
			}
			if (maxBytes && scanned >= maxBytes) {
				return std::nullopt;
			}
			const mach_vm_size_t toRead = std::min<mach_vm_size_t>(chunkSize, regionSize - offset);
			if (!dbg.readMemoryQuiet(address + offset, buffer.data() + carry, static_cast<size_t>(toRead))) {
				carry = 0;
				scanned += toRead;
				continue;
			}
			const size_t total = carry + static_cast<size_t>(toRead);
			if (total >= patternSize) {
				const size_t limit = total - patternSize + 1;
				for (size_t i = 0; i < limit; ++i) {
					if (memcmp(buffer.data() + i, pattern, patternSize) == 0) {
						return static_cast<uint64_t>(address + offset) + i - carry;
					}
				}
			}
			carry = 0;
			if (patternSize > 1 && total >= patternSize - 1) {
				carry = patternSize - 1;
				memmove(buffer.data(), buffer.data() + total - carry, carry);
			}
			scanned += toRead;
		}
		address += regionSize;
	}
	return std::nullopt;
}

static std::optional<uint64_t> findWineControlBlock(MuhDebugger &dbg) {
	const uint64_t magic0 = ROSETTA_WINE_CONTROL_MAGIC0;
	const uint64_t magic1 = ROSETTA_WINE_CONTROL_MAGIC1;
	uint8_t pattern[16] = {};
	memcpy(pattern, &magic0, sizeof(magic0));
	memcpy(pattern + sizeof(magic0), &magic1, sizeof(magic1));
	const uint64_t maxBytes = parseEnvU64("ASTROWINE_WINE_CTRL_SCAN_MAX_MB",
	                                      kWineCtrlScanMaxBytesDefault >> 20) << 20;
	const uint64_t maxMillis = parseEnvU64("ASTROWINE_WINE_CTRL_SCAN_MAX_MS",
	                                       kWineCtrlScanMaxMillisDefault);
	return findPatternInProcess(dbg, pattern, sizeof(pattern), maxBytes, maxMillis);
}

static std::optional<uint64_t> allocateInlineState(MuhDebugger &dbg,
                                                   uint64_t mapCapacity,
                                                   uint64_t listCapacity) {
	if (!mapCapacity || !listCapacity) {
		return std::nullopt;
	}
	const size_t stateSize =
		sizeof(rosetta_inline_state_header) +
		mapCapacity * sizeof(rosetta_inline_map_entry) +
		listCapacity * sizeof(uint64_t);
	uint64_t addr = 0;
	if (!dbg.allocateMemory(stateSize, addr)) {
		return std::nullopt;
	}
	rosetta_inline_state_header header{};
	header.magic = ROSETTA_INLINE_STATE_MAGIC;
	header.version = ROSETTA_INLINE_STATE_VERSION;
	header.initialized = 1;
	header.lock = 0;
	header.map_capacity = mapCapacity;
	header.map_count = 0;
	header.list_capacity = listCapacity;
	header.list_count = 0;
	if (!dbg.writeMemory(addr, &header, sizeof(header))) {
		return std::nullopt;
	}
	return addr;
}

static bool readInlineStateHeader(MuhDebugger &dbg,
                                  uint64_t addr,
                                  rosetta_inline_state_header &out) {
	if (!addr) {
		return false;
	}
	if (!dbg.readMemory(addr, &out, sizeof(out))) {
		return false;
	}
	if (out.magic != ROSETTA_INLINE_STATE_MAGIC ||
	    out.version != ROSETTA_INLINE_STATE_VERSION) {
		return false;
	}
	return true;
}

static bool patchInlineAddressMarker(std::vector<uint8_t> &blob,
                                     uint64_t marker,
                                     uint64_t value) {
	if (blob.empty()) {
		return false;
	}
	uint32_t markerInstrs[4] = {};
	markerInstrs[0] = encodeMovz(15, static_cast<uint16_t>(marker & 0xffffu), 0);
	markerInstrs[1] = encodeMovk(15, static_cast<uint16_t>((marker >> 16) & 0xffffu), 16);
	markerInstrs[2] = encodeMovk(15, static_cast<uint16_t>((marker >> 32) & 0xffffu), 32);
	markerInstrs[3] = encodeMovk(15, static_cast<uint16_t>((marker >> 48) & 0xffffu), 48);

	uint32_t valueInstrs[4] = {};
	valueInstrs[0] = encodeMovz(15, static_cast<uint16_t>(value & 0xffffu), 0);
	valueInstrs[1] = encodeMovk(15, static_cast<uint16_t>((value >> 16) & 0xffffu), 16);
	valueInstrs[2] = encodeMovk(15, static_cast<uint16_t>((value >> 32) & 0xffffu), 32);
	valueInstrs[3] = encodeMovk(15, static_cast<uint16_t>((value >> 48) & 0xffffu), 48);

	uint8_t markerBytes[sizeof(markerInstrs)] = {};
	memcpy(markerBytes, markerInstrs, sizeof(markerInstrs));

	for (size_t i = 0; i + sizeof(markerInstrs) <= blob.size(); i += 4) {
		if (memcmp(blob.data() + i, markerBytes, sizeof(markerInstrs)) == 0) {
			memcpy(blob.data() + i, valueInstrs, sizeof(valueInstrs));
			return true;
		}
	}
	return false;
}

static bool setupHelperInlineHook(MuhDebugger &dbg,
                                  uint64_t helperAddr,
                                  uint64_t runtimeBase,
                                  const std::vector<uint8_t> &formatBlob,
                                  uint64_t formatEntryOffset,
                                  const char *label) {
	const char *tag = label ? label : "helper";
	mach_vm_address_t regionStart = 0;
	mach_vm_size_t regionSize = 0;
	vm_prot_t regionProt = 0;
	if (!findExecRegionForAddress(dbg, helperAddr, regionStart, regionSize, regionProt)) {
		fprintf(stderr, "%s: Failed to locate executable region for helper entry.\n", tag);
		return false;
	}
	if (formatBlob.empty()) {
		fprintf(stderr, "%s: Inline formatter blob is empty.\n", tag);
		return false;
	}
	if (formatEntryOffset >= formatBlob.size()) {
		fprintf(stderr, "%s: Inline formatter entry offset is out of range.\n", tag);
		return false;
	}
	const char *runtimePath = "/usr/libexec/rosetta/runtime";
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
		auto candidate = findZeroCaveInRegion(dbg, regionStart, regionSize, helperAddr, stubSize, 8);
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
		fprintf(stderr, "%s: Failed to locate executable code cave for inline helper hook.\n", tag);
		return false;
	}
	const uint64_t stubAddr = *caveAddr;

	uint32_t originalInstr0 = 0;
	uint32_t originalInstr1 = 0;
	uint32_t originalInstr2 = 0;
	uint32_t originalInstr3 = 0;
	uint32_t originalInstr4 = 0;
	if (!dbg.readMemory(helperAddr, &originalInstr0, sizeof(originalInstr0))) {
		fprintf(stderr, "%s: Failed to read helper prologue for inline hook.\n", tag);
		return false;
	}
	if (!dbg.readMemory(helperAddr + sizeof(uint32_t), &originalInstr1, sizeof(originalInstr1))) {
		fprintf(stderr, "%s: Failed to read helper prologue for inline hook.\n", tag);
		return false;
	}
	if (!dbg.readMemory(helperAddr + 2 * sizeof(uint32_t), &originalInstr2, sizeof(originalInstr2))) {
		fprintf(stderr, "%s: Failed to read helper prologue for inline hook.\n", tag);
		return false;
	}
	if (!dbg.readMemory(helperAddr + 3 * sizeof(uint32_t), &originalInstr3, sizeof(originalInstr3))) {
		fprintf(stderr, "%s: Failed to read helper prologue for inline hook.\n", tag);
		return false;
	}
	if (!dbg.readMemory(helperAddr + 4 * sizeof(uint32_t), &originalInstr4, sizeof(originalInstr4))) {
		fprintf(stderr, "%s: Failed to read helper prologue for inline hook.\n", tag);
		return false;
	}

	uint32_t relocated0 = 0;
	uint32_t relocated1 = 0;
	uint32_t relocated2 = 0;
	uint32_t relocated3 = 0;
	uint32_t relocated4 = 0;
	const uint64_t relocateBase = stubAddr + kHelperInlineDirectFormatOrigOffset;
	if (!relocateInstruction(originalInstr0, helperAddr, relocateBase, relocated0) ||
	    !relocateInstruction(originalInstr1, helperAddr + 4, relocateBase + 4, relocated1) ||
	    !relocateInstruction(originalInstr2, helperAddr + 8, relocateBase + 8, relocated2) ||
	    !relocateInstruction(originalInstr3, helperAddr + 12, relocateBase + 12, relocated3) ||
	    !relocateInstruction(originalInstr4, helperAddr + 16, relocateBase + 16, relocated4)) {
		fprintf(stderr, "%s: Failed to relocate helper prologue for inline hook.\n", tag);
		return false;
	}

	std::vector<uint8_t> stub;
	if (!buildHelperInlineDirectFormatStub(relocated0, relocated1, relocated2, relocated3, relocated4,
	                                       stubAddr, helperAddr + 20, formatBlob, formatEntryOffset, stub)) {
		fprintf(stderr, "%s: Failed to build helper inline formatted stub.\n", tag);
		return false;
	}

	if (!dbg.adjustMemoryProtection(stubAddr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, stub.size())) {
		fprintf(stderr, "%s: Failed to adjust protection for helper inline stub.\n", tag);
		return false;
	}
	if (!dbg.writeMemory(stubAddr, stub.data(), stub.size())) {
		fprintf(stderr, "%s: Failed to write helper inline stub.\n", tag);
		return false;
	}
	(void)dbg.flushInstructionCache(stubAddr, stub.size());
	if (!dbg.adjustMemoryProtection(stubAddr, VM_PROT_READ | VM_PROT_EXECUTE, stub.size())) {
		fprintf(stderr, "%s: Failed to restore protection for helper inline stub.\n", tag);
		return false;
	}

	uint32_t patchInstrs[5] = {};
	encodeAbsoluteBranch(stubAddr, 17, patchInstrs);
	if (!dbg.adjustMemoryProtection(helperAddr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, sizeof(patchInstrs))) {
		fprintf(stderr, "%s: Failed to adjust protection for helper patch.\n", tag);
		return false;
	}
	if (!dbg.writeMemory(helperAddr, patchInstrs, sizeof(patchInstrs))) {
		fprintf(stderr, "%s: Failed to patch helper entry for inline hook.\n", tag);
		return false;
	}
	(void)dbg.flushInstructionCache(helperAddr, sizeof(patchInstrs));
	if (!dbg.adjustMemoryProtection(helperAddr, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(patchInstrs))) {
		fprintf(stderr, "%s: Failed to restore protection for helper patch.\n", tag);
		return false;
	}

	hookLog("%s inline stub at 0x%llx\n", tag, static_cast<unsigned long long>(stubAddr));
	return true;
}

static bool setupHelperInlineWrapperHook(MuhDebugger &dbg,
                                         uint64_t helperAddr,
                                         uint64_t runtimeBase,
                                         const std::vector<uint8_t> &formatBlob,
                                         uint64_t formatEntryOffset,
                                         const char *label) {
	const char *tag = label ? label : "helper";
	mach_vm_address_t regionStart = 0;
	mach_vm_size_t regionSize = 0;
	vm_prot_t regionProt = 0;
	if (!findExecRegionForAddress(dbg, helperAddr, regionStart, regionSize, regionProt)) {
		fprintf(stderr, "%s: Failed to locate executable region for helper entry.\n", tag);
		return false;
	}
	if (formatBlob.empty()) {
		fprintf(stderr, "%s: Inline formatter blob is empty.\n", tag);
		return false;
	}
	if (formatEntryOffset >= formatBlob.size()) {
		fprintf(stderr, "%s: Inline formatter entry offset is out of range.\n", tag);
		return false;
	}
	const char *runtimePath = "/usr/libexec/rosetta/runtime";
	const size_t stubSize = kHelperInlineWrapperBodySize + kHelperInlineWrapperTrampSize + formatBlob.size();
	const auto trailingCave = findTrailingZeroCaveInRegion(dbg, regionStart, regionSize, stubSize, 8);
	std::optional<uint64_t> caveAddr;
	if (trailingCave && runtimeBase != 0) {
		const uint64_t fileOffset = *trailingCave - runtimeBase;
		if (isFileRangeZero(runtimePath, fileOffset, stubSize)) {
			caveAddr = trailingCave;
		}
	}
	if (!caveAddr) {
		auto candidate = findZeroCaveInRegion(dbg, regionStart, regionSize, helperAddr, stubSize, 8);
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
		fprintf(stderr, "%s: Failed to locate executable code cave for inline wrapper hook.\n", tag);
		return false;
	}
	const uint64_t stubAddr = *caveAddr;

	uint32_t originalInstr0 = 0;
	uint32_t originalInstr1 = 0;
	uint32_t originalInstr2 = 0;
	uint32_t originalInstr3 = 0;
	uint32_t originalInstr4 = 0;
	if (!dbg.readMemory(helperAddr, &originalInstr0, sizeof(originalInstr0)) ||
	    !dbg.readMemory(helperAddr + sizeof(uint32_t), &originalInstr1, sizeof(originalInstr1)) ||
	    !dbg.readMemory(helperAddr + 2 * sizeof(uint32_t), &originalInstr2, sizeof(originalInstr2)) ||
	    !dbg.readMemory(helperAddr + 3 * sizeof(uint32_t), &originalInstr3, sizeof(originalInstr3)) ||
	    !dbg.readMemory(helperAddr + 4 * sizeof(uint32_t), &originalInstr4, sizeof(originalInstr4))) {
		fprintf(stderr, "%s: Failed to read helper prologue for inline wrapper hook.\n", tag);
		return false;
	}

	uint32_t relocated0 = 0;
	uint32_t relocated1 = 0;
	uint32_t relocated2 = 0;
	uint32_t relocated3 = 0;
	uint32_t relocated4 = 0;
	const uint64_t relocateBase = stubAddr + alignUp(kHelperInlineWrapperBodySize, 4);
	if (!relocateInstruction(originalInstr0, helperAddr, relocateBase, relocated0) ||
	    !relocateInstruction(originalInstr1, helperAddr + 4, relocateBase + 4, relocated1) ||
	    !relocateInstruction(originalInstr2, helperAddr + 8, relocateBase + 8, relocated2) ||
	    !relocateInstruction(originalInstr3, helperAddr + 12, relocateBase + 12, relocated3) ||
	    !relocateInstruction(originalInstr4, helperAddr + 16, relocateBase + 16, relocated4)) {
		fprintf(stderr, "%s: Failed to relocate helper prologue for inline wrapper hook.\n", tag);
		return false;
	}

	std::vector<uint8_t> stub;
	if (!buildHelperInlineWrapperStub(relocated0, relocated1, relocated2, relocated3, relocated4,
	                                  stubAddr, helperAddr + 20, formatBlob, formatEntryOffset, stub)) {
		fprintf(stderr, "%s: Failed to build helper inline wrapper stub.\n", tag);
		return false;
	}

	if (!dbg.adjustMemoryProtection(stubAddr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, stub.size())) {
		fprintf(stderr, "%s: Failed to adjust protection for helper inline wrapper stub.\n", tag);
		return false;
	}
	if (!dbg.writeMemory(stubAddr, stub.data(), stub.size())) {
		fprintf(stderr, "%s: Failed to write helper inline wrapper stub.\n", tag);
		return false;
	}
	(void)dbg.flushInstructionCache(stubAddr, stub.size());
	if (!dbg.adjustMemoryProtection(stubAddr, VM_PROT_READ | VM_PROT_EXECUTE, stub.size())) {
		fprintf(stderr, "%s: Failed to restore protection for helper inline wrapper stub.\n", tag);
		return false;
	}

	uint32_t patchInstrs[5] = {};
	encodeAbsoluteBranch(stubAddr, 17, patchInstrs);
	if (!dbg.adjustMemoryProtection(helperAddr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, sizeof(patchInstrs))) {
		fprintf(stderr, "%s: Failed to adjust protection for helper patch.\n", tag);
		return false;
	}
	if (!dbg.writeMemory(helperAddr, patchInstrs, sizeof(patchInstrs))) {
		fprintf(stderr, "%s: Failed to patch helper entry for inline wrapper hook.\n", tag);
		return false;
	}
	(void)dbg.flushInstructionCache(helperAddr, sizeof(patchInstrs));
	if (!dbg.adjustMemoryProtection(helperAddr, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(patchInstrs))) {
		fprintf(stderr, "%s: Failed to restore protection for helper patch.\n", tag);
		return false;
	}

	hookLog("%s inline wrapper stub at 0x%llx\n", tag, static_cast<unsigned long long>(stubAddr));
	return true;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "%s <path to program>\n", argv[0]);
		return 1;
	}

	logsEnabled = getenv("ASTROWINE_LOGS");
	const bool inlineHelperHook = getenv("ASTROWINE_HELPER_INLINE") != nullptr;
	const bool inlineCStubRequested = getenv("ASTROWINE_HELPER_INLINE_C") != nullptr;
	const bool disableJitWrapper = getenv("ASTROWINE_DISABLE_JIT_WRAPPER") != nullptr;
	const bool disableWineCtrlScan = getenv("ASTROWINE_DISABLE_WINE_CTRL_SCAN") != nullptr;
	const bool disableSyscallHook = getenv("ASTROWINE_DISABLE_SYSCALL_HOOK") != nullptr;
	const char *inlineCPathEnv = getenv("ASTROWINE_HELPER_INLINE_C_PATH");

	if (!inlineHelperHook || !inlineCStubRequested) {
		fprintf(stderr, "ASTROWINE_HELPER_INLINE=1 and ASTROWINE_HELPER_INLINE_C=1 are required.\n");
		return 1;
	}

	LOG("Launching debugger.\n");

	pid_t child = fork();
	if (child == 0) {
		if (ptrace(PT_TRACE_ME, 0, nullptr, 0) == -1) {
			perror("child: ptrace(PT_TRACE_ME)");
			return 1;
		}
		LOG("child: launching into program: %s\n", argv[1]);
		execv(argv[1], &argv[1]);
		return 1;
	}

	MuhDebugger dbg;
	if (!dbg.attach(child)) {
		fprintf(stderr, "Failed to attach to process\n");
		return 1;
	}
	LOG("Attached successfully\n");

	OffsetFinder offsetFinder;
	offsetFinder.setDefaultOffsets();
	if (!offsetFinder.determineOffsets()) {
		fprintf(stderr, "Failed to locate helper patterns in Rosetta runtime.\n");
		dbg.detach();
		return 0;
	}
	LOG("Found rosetta runtime helper offsets successfully!\n");
	LOG("offset_helper_syscall=%llx\n", offsetFinder.offsetHelperSyscall_);
	LOG("offset_jit_translate=%llx\n", offsetFinder.offsetJitTranslate_);
	if (!disableJitWrapper && offsetFinder.offsetJitTranslate_ == 0) {
		fprintf(stderr, "Failed to locate jit translation pattern in Rosetta runtime.\n");
		dbg.detach();
		return 1;
	}

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

	LOG("Rosetta runtime base: 0x%llx\n", static_cast<unsigned long long>(runtimeBase));

	if (runtimeBase == 0 || helperSyscallAddr == 0) {
		fprintf(stderr, "Rosetta runtime not found; running without hooks.\n");
		dbg.detach();
		return 0;
	}

	LOG("helper_syscall address: 0x%llx\n", helperSyscallAddr);
	uint64_t jitTranslateAddr = 0;
	if (!disableJitWrapper && offsetFinder.offsetJitTranslate_ != 0) {
		jitTranslateAddr = runtimeBase + offsetFinder.offsetJitTranslate_;
		LOG("jit_translate address: 0x%llx\n", static_cast<unsigned long long>(jitTranslateAddr));
	} else if (disableJitWrapper) {
		LOG("jit_translate wrapper disabled by ASTROWINE_DISABLE_JIT_WRAPPER\n");
	}

	std::string blobPath;
	if (inlineCPathEnv && *inlineCPathEnv) {
		blobPath = inlineCPathEnv;
	} else {
		blobPath = dirName(argv[0]);
		blobPath += "/rosetta_inline_payload.o";
	}

	std::vector<uint8_t> inlineFormatBlob;
	uint64_t inlineSyscallOffset = 0;
	uint64_t inlineResolveOffset = 0;
	if (!readMachOTextSectionWithSymbols(blobPath.c_str(),
	                                     "_rosetta_helper_syscall_inline",
	                                     inlineSyscallOffset,
	                                     "_rosetta_helper_resolve_inline",
	                                     inlineResolveOffset,
	                                     inlineFormatBlob)) {
		fprintf(stderr, "Failed to load inline helper C text from %s\n", blobPath.c_str());
		dbg.detach();
		return 1;
	}
	LOG("inline_c blob loaded from %s (%zu bytes, syscall 0x%llx resolve 0x%llx)\n",
	    blobPath.c_str(), inlineFormatBlob.size(),
	    static_cast<unsigned long long>(inlineSyscallOffset),
	    static_cast<unsigned long long>(inlineResolveOffset));

	auto stateAddrOpt = allocateInlineState(dbg, kInlineMapCapacity, kInlineListCapacity);
	if (!stateAddrOpt) {
		fprintf(stderr, "Failed to allocate inline state buffer in target.\n");
		dbg.detach();
		return 1;
	}
	const uint64_t stateAddr = *stateAddrOpt;
	LOG("inline state buffer at 0x%llx\n", static_cast<unsigned long long>(stateAddr));

	std::optional<uint64_t> wineCtrlAddrOpt;
	bool didDelayStop = false;
	if (!disableWineCtrlScan) {
		const uint64_t delayMs = parseEnvU64("ASTROWINE_WINE_CTRL_SCAN_DELAY_MS",
		                                     kWineCtrlScanDelayMillisDefault);
		const uint64_t retryCount = parseEnvU64("ASTROWINE_WINE_CTRL_SCAN_RETRY_COUNT",
		                                        kWineCtrlScanRetryCountDefault);
		if (delayMs) {
			LOG("Delaying wine control block scan by %llums\n",
			    static_cast<unsigned long long>(delayMs));
			if (!dbg.runForMillis(delayMs)) {
				LOG("Failed to delay wine control block scan; process may have exited.\n");
			} else {
				didDelayStop = true;
			}
		}
		wineCtrlAddrOpt = findWineControlBlock(dbg);
		for (uint64_t attempt = 0; !wineCtrlAddrOpt && attempt < retryCount; ++attempt) {
			if (delayMs) {
				LOG("Retrying wine control block scan after %llums (attempt %llu)\n",
				    static_cast<unsigned long long>(delayMs),
				    static_cast<unsigned long long>(attempt + 1));
				if (!dbg.runForMillis(delayMs)) {
					LOG("Failed to delay wine control block scan; process may have exited.\n");
					break;
				} else {
					didDelayStop = true;
				}
			}
			wineCtrlAddrOpt = findWineControlBlock(dbg);
		}
	}
	const uint64_t wineCtrlAddr = wineCtrlAddrOpt ? *wineCtrlAddrOpt : 0;
	if (wineCtrlAddr) {
		LOG("wine control block at 0x%llx\n", static_cast<unsigned long long>(wineCtrlAddr));
	} else if (disableWineCtrlScan) {
		LOG("wine control block scan disabled by ASTROWINE_DISABLE_WINE_CTRL_SCAN\n");
	} else {
		LOG("wine control block not found (range checks disabled).\n");
	}

	if (!patchInlineAddressMarker(inlineFormatBlob, ROSETTA_INLINE_STATE_ADDR_MARKER, stateAddr)) {
		fprintf(stderr, "Failed to patch inline payload state marker.\n");
		dbg.detach();
		return 1;
	}
	if (!patchInlineAddressMarker(inlineFormatBlob, ROSETTA_INLINE_WINE_ADDR_MARKER, wineCtrlAddr)) {
		fprintf(stderr, "Failed to patch inline payload wine marker.\n");
		dbg.detach();
		return 1;
	}

	if (!disableSyscallHook) {
		if (!setupHelperInlineHook(dbg, helperSyscallAddr, runtimeBase, inlineFormatBlob, inlineSyscallOffset, "helper_syscall")) {
			fprintf(stderr, "Inline helper_syscall hook failed.\n");
			dbg.detach();
			return 1;
		}
	} else {
		LOG("helper_syscall hook disabled by ASTROWINE_DISABLE_SYSCALL_HOOK\n");
	}
	if (!disableJitWrapper) {
		if (!setupHelperInlineWrapperHook(dbg, jitTranslateAddr, runtimeBase, inlineFormatBlob, inlineResolveOffset, "jit_translate")) {
			fprintf(stderr, "Inline jit_translate wrapper hook failed.\n");
			dbg.detach();
			return 1;
		}
	}

	const uint64_t sampleMs = parseEnvU64("ASTROWINE_INLINE_STATE_SAMPLE_MS",
	                                      kInlineStateSampleMillisDefault);
	const uint64_t sampleCount = parseEnvU64("ASTROWINE_INLINE_STATE_SAMPLE_COUNT",
	                                         kInlineStateSampleCountDefault);
	bool didSampleStop = false;
	if (sampleMs && sampleCount) {
		for (uint64_t i = 0; i < sampleCount; ++i) {
			LOG("Sampling inline state after %llums (sample %llu)\n",
			    static_cast<unsigned long long>(sampleMs),
			    static_cast<unsigned long long>(i + 1));
			if (!dbg.runForMillis(sampleMs)) {
				LOG("Failed to sample inline state; process may have exited.\n");
				break;
			}
			didSampleStop = true;
			rosetta_inline_state_header header{};
			if (readInlineStateHeader(dbg, stateAddr, header)) {
				LOG("inline state: map_count=%llu list_count=%llu\n",
				    static_cast<unsigned long long>(header.map_count),
				    static_cast<unsigned long long>(header.list_count));
			} else {
				LOG("inline state: failed to read header.\n");
			}
		}
	}

	if (!dbg.detach()) {
		fprintf(stderr, "Failed to detach debugger\n");
		return 1;
	}
	if (didDelayStop || didSampleStop) {
		if (kill(dbg.pid(), SIGCONT) < 0 && errno != ESRCH) {
			perror("kill(SIGCONT)");
		} else {
			LOG("Resumed target after delayed scan.\n");
		}
	}

	return 0;
}
