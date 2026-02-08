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
#include <optional>
#include <string>
#include <vector>

#include "offset_finder.hpp"

typedef const struct dyld_process_info_base *DyldProcessInfo;
extern "C" DyldProcessInfo _dyld_process_info_create(task_t task, uint64_t timestamp, kern_return_t *kernelError);
extern "C" void _dyld_process_info_for_each_image(DyldProcessInfo info, void (^callback)(uint64_t machHeaderAddress, const uuid_t uuid, const char *path));
extern "C" void _dyld_process_info_release(DyldProcessInfo info);

const char *logsEnabled = nullptr;
static bool hookLogsEnabled = false;
static bool hookLogInitialized = false;
static int hookLogFd = -1;
static int hookLogSinkFd = STDERR_FILENO;

static void initHookLog() {
	if (hookLogInitialized) {
		return;
	}
	hookLogInitialized = true;

	const char *env = getenv("ASTROWINE_HOOK_LOGS");
	const char *logPath = getenv("ASTROWINE_HOOK_LOG_PATH");

	// Keep hook logging quiet by default; enable only when explicitly requested.
	hookLogsEnabled = false;
	if (env && strcmp(env, "0") != 0) {
		hookLogsEnabled = true;
	}
	if (logPath && *logPath) {
		hookLogsEnabled = true;
	}
	if (!hookLogsEnabled) {
		hookLogsEnabled = false;
		return;
	}

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

static bool envFlagEnabled(const char *name, bool defaultValue) {
	const char *value = getenv(name);
	if (!value || !*value) {
		return defaultValue;
	}
	if (strcmp(value, "0") == 0 ||
	    strcmp(value, "false") == 0 || strcmp(value, "FALSE") == 0 || strcmp(value, "False") == 0 ||
	    strcmp(value, "no") == 0 || strcmp(value, "NO") == 0 || strcmp(value, "No") == 0 ||
	    strcmp(value, "off") == 0 || strcmp(value, "OFF") == 0 || strcmp(value, "Off") == 0) {
		return false;
	}
	return true;
}

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

static uint64_t alignDown(uint64_t value, uint64_t alignment) {
	if (alignment == 0) {
		return value;
	}
	return value & ~(alignment - 1);
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

static uint32_t encodeCbzW(uint8_t reg, int32_t immBytes) {
	// imm19 is signed and scaled by 4.
	const int32_t imm19 = immBytes >> 2;
	return 0x34000000u | ((static_cast<uint32_t>(imm19) & 0x7ffffu) << 5) | (reg & 0x1fu);
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
constexpr size_t kHelperInlineDirectFormatOrigOffset = 0x6C;
constexpr size_t kHelperInlineDirectFormatBodySize = kHelperInlineDirectFormatOrigOffset + 40;

// Syscall helper stubs need access to the full x86->arm register mapping at helper entry,
// so they reserve a larger save area and pass a pointer to it into the C payload.
constexpr size_t kHelperSyscallInlineFrameSize = 0x1A0;
constexpr size_t kHelperSyscallInlineSaveAreaSize = 0xA0;
constexpr size_t kHelperSyscallInlineBufferOffset = kHelperSyscallInlineSaveAreaSize;
constexpr size_t kHelperSyscallInlineBufferSize = 0x100;

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
                                              bool useSvcArg,
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
	if (useSvcArg) {
		instrs.push_back(encodeLdrImm(1, 31, 0x48)); // x1 = saved x16 (svc)
		instrs.push_back(encodeLdrImm(2, 31, 0x00)); // x2 = saved x0
		instrs.push_back(encodeLdrImm(3, 31, 0x08)); // x3 = saved x1
		instrs.push_back(encodeLdrImm(4, 31, 0x10)); // x4 = saved x2
		instrs.push_back(encodeLdrImm(5, 31, 0x18)); // x5 = saved x3
	} else {
		instrs.push_back(encodeLdrImm(1, 31, 0x00)); // x1 = saved x0
		instrs.push_back(encodeLdrImm(2, 31, 0x08)); // x2 = saved x1
		instrs.push_back(encodeLdrImm(3, 31, 0x10)); // x3 = saved x2
		instrs.push_back(encodeLdrImm(4, 31, 0x18)); // x4 = saved x3
		instrs.push_back(encodeLdrImm(5, 31, 0x20)); // x5 = saved x4
	}

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

// Must match payload/rosetta_inline_payload.c.
static constexpr uint64_t kAstroWineStateMagic = 0x0031545357525453ull; // "STRWST1\0" LE
static constexpr uint32_t kAstroWineStateVersion = 1u;

static constexpr uint64_t kAstroWineWineShmPtrDefault = 0x7ffe1100ull; // user_shared_data (0x7ffe0000) + 0x1000 + 0x100

enum AstroWineStateFlags : uint32_t {
	ASTROWINE_STATE_FLAG_LOG_SYSCALL = 1u << 0,
	ASTROWINE_STATE_FLAG_LOG_RESOLVE = 1u << 1,
	ASTROWINE_STATE_FLAG_INTERCEPT = 1u << 2,
};

struct AstroWineStateHeader {
	uint64_t magic;
	uint32_t version;
	uint32_t lock;
	uint32_t count;
	uint32_t capacity;
	uint64_t native_threshold_x86;
	uint64_t wine_shm_ptr;
	uint32_t flags;
	uint32_t _pad;
};
static_assert(sizeof(AstroWineStateHeader) == 48, "AstroWineStateHeader layout mismatch");

static bool buildHelperSyscallInterceptStub(uint32_t originalInstrs[5],
                                            uint64_t helperAddr,
                                            uint64_t stubAddr,
                                            uint64_t returnAddr,
                                            uint64_t payloadBaseAddr,
                                            uint64_t payloadEntryOffset,
                                            uint64_t stateAddr,
                                            uint64_t runtimeExitRetAddr,
                                            bool relocateOriginal,
                                            std::vector<uint8_t> &outStub) {
	if (!payloadBaseAddr) return false;

	std::vector<uint32_t> instrs;
	instrs.reserve(96);

	// Save regs + output buffer.
	instrs.push_back(encodeSubImm(31, 31, kHelperSyscallInlineFrameSize));
	instrs.push_back(encodeStpImm(0, 1, 31, 0x00));
	instrs.push_back(encodeStpImm(2, 3, 31, 0x10));
	instrs.push_back(encodeStpImm(4, 5, 31, 0x20));
	instrs.push_back(encodeStpImm(6, 7, 31, 0x30));
	instrs.push_back(encodeStpImm(8, 9, 31, 0x40));
	instrs.push_back(encodeStpImm(10, 11, 31, 0x50));
	instrs.push_back(encodeStpImm(12, 13, 31, 0x60));
	instrs.push_back(encodeStpImm(14, 15, 31, 0x70));
	instrs.push_back(encodeStpImm(16, 17, 31, 0x80));
	instrs.push_back(encodeStrImm(30, 31, 0x90));

	// Call payload: (out, state, sysnum, lr, regs_ptr) -> returns non-zero to skip original helper.
	instrs.push_back(encodeAddImm(0, 31, kHelperSyscallInlineBufferOffset)); // x0 = buffer
	{
		const uint64_t state = stateAddr;
		instrs.push_back(encodeMovz(1, static_cast<uint16_t>(state & 0xffffu), 0));
		instrs.push_back(encodeMovk(1, static_cast<uint16_t>((state >> 16) & 0xffffu), 16));
		instrs.push_back(encodeMovk(1, static_cast<uint16_t>((state >> 32) & 0xffffu), 32));
		instrs.push_back(encodeMovk(1, static_cast<uint16_t>((state >> 48) & 0xffffu), 48));
	}
	instrs.push_back(encodeLdrImm(2, 31, 0x00)); // x2 = saved x0 (sysnum)
	instrs.push_back(encodeLdrImm(3, 31, 0x90)); // x3 = saved x30 (return addr)
	instrs.push_back(encodeAddImm(4, 31, 0x00)); // x4 = regs_ptr (saved x0..x15)

	const size_t payloadAddrIdx = instrs.size();
	instrs.push_back(0); // movz x16, ...
	instrs.push_back(0); // movk x16, ...
	instrs.push_back(0); // movk x16, ...
	instrs.push_back(0); // movk x16, ...
	instrs.push_back(encodeBlr(16));

	const size_t cbzIdx = instrs.size();
	instrs.push_back(0); // cbz w0, continue

	// Intercept path: restore regs, dealloc frame, and jump to runtime_exit_ret.
	auto emitRestoreAndExitRet = [&instrs, runtimeExitRetAddr]() {
		instrs.push_back(encodeLdrImm(30, 31, 0x90));
		instrs.push_back(encodeLdpImm(16, 17, 31, 0x80));
		instrs.push_back(encodeLdpImm(14, 15, 31, 0x70));
		instrs.push_back(encodeLdpImm(12, 13, 31, 0x60));
		instrs.push_back(encodeLdpImm(10, 11, 31, 0x50));
		instrs.push_back(encodeLdpImm(8, 9, 31, 0x40));
		instrs.push_back(encodeLdpImm(6, 7, 31, 0x30));
		instrs.push_back(encodeLdpImm(4, 5, 31, 0x20));
		instrs.push_back(encodeLdpImm(2, 3, 31, 0x10));
		instrs.push_back(encodeLdpImm(0, 1, 31, 0x00));
		instrs.push_back(encodeAddImm(31, 31, kHelperSyscallInlineFrameSize));

		uint32_t branchInstrs[5] = {};
		encodeAbsoluteBranch(runtimeExitRetAddr, 17, branchInstrs);
		for (const auto instr : branchInstrs) instrs.push_back(instr);
	};
	emitRestoreAndExitRet();

	const size_t continueLabelIdx = instrs.size();

	// Continue path: restore regs, dealloc frame, run relocated original instructions, then jump back.
	instrs.push_back(encodeLdrImm(30, 31, 0x90));
	instrs.push_back(encodeLdpImm(16, 17, 31, 0x80));
	instrs.push_back(encodeLdpImm(14, 15, 31, 0x70));
	instrs.push_back(encodeLdpImm(12, 13, 31, 0x60));
	instrs.push_back(encodeLdpImm(10, 11, 31, 0x50));
	instrs.push_back(encodeLdpImm(8, 9, 31, 0x40));
	instrs.push_back(encodeLdpImm(6, 7, 31, 0x30));
	instrs.push_back(encodeLdpImm(4, 5, 31, 0x20));
	instrs.push_back(encodeLdpImm(2, 3, 31, 0x10));
	instrs.push_back(encodeLdpImm(0, 1, 31, 0x00));
	instrs.push_back(encodeAddImm(31, 31, kHelperSyscallInlineFrameSize));

	for (size_t i = 0; i < 5; ++i) {
		uint32_t instr = originalInstrs[i];
		if (relocateOriginal) {
			const uint64_t origAddr = helperAddr + i * 4;
			const uint64_t newAddr = stubAddr + instrs.size() * 4;
			uint32_t relocated = 0;
			if (!relocateInstruction(instr, origAddr, newAddr, relocated)) {
				return false;
			}
			instr = relocated;
		} else {
			instr = 0xD503201Fu; // nop
		}
		instrs.push_back(instr);
	}

	{
		uint32_t branchInstrs[5] = {};
		encodeAbsoluteBranch(returnAddr, 17, branchInstrs);
		for (const auto instr : branchInstrs) instrs.push_back(instr);
	}

	// Patch CBZ to jump over the intercept path to the continue label when w0 == 0.
	{
		const int32_t cbzAddr = static_cast<int32_t>(cbzIdx * 4);
		const int32_t contAddr = static_cast<int32_t>(continueLabelIdx * 4);
		const int32_t diff = contAddr - cbzAddr;
		instrs[cbzIdx] = encodeCbzW(0, diff);
	}

	const size_t bodyBytes = instrs.size() * sizeof(uint32_t);
	{
		const uint64_t payloadAddr = payloadBaseAddr + payloadEntryOffset;
		instrs[payloadAddrIdx + 0] = encodeMovz(16, static_cast<uint16_t>(payloadAddr & 0xffffu), 0);
		instrs[payloadAddrIdx + 1] = encodeMovk(16, static_cast<uint16_t>((payloadAddr >> 16) & 0xffffu), 16);
		instrs[payloadAddrIdx + 2] = encodeMovk(16, static_cast<uint16_t>((payloadAddr >> 32) & 0xffffu), 32);
		instrs[payloadAddrIdx + 3] = encodeMovk(16, static_cast<uint16_t>((payloadAddr >> 48) & 0xffffu), 48);
	}
	outStub.assign(bodyBytes, 0);
	fillNops(outStub);
	memcpy(outStub.data(), instrs.data(), bodyBytes);
	return true;
}

static bool buildHelperResolveMapStub(uint32_t originalInstrs[5],
                                      uint64_t helperAddr,
                                      uint64_t stubAddr,
                                      uint64_t returnAddr,
                                      uint64_t payloadBaseAddr,
                                      uint64_t payloadEntryOffset,
                                      uint64_t stateAddr,
                                      bool relocateOriginal,
                                      std::vector<uint8_t> &outStub) {
	if (!payloadBaseAddr) return false;

	std::vector<uint32_t> instrs;
	instrs.reserve(96);

	// Save regs + output buffer.
	instrs.push_back(encodeSubImm(31, 31, kHelperInlineDirectFormatFrameSize));
	instrs.push_back(encodeStpImm(0, 1, 31, 0x00));
	instrs.push_back(encodeStpImm(2, 3, 31, 0x10));
	instrs.push_back(encodeStpImm(4, 5, 31, 0x20));
	instrs.push_back(encodeStpImm(6, 7, 31, 0x30));
	instrs.push_back(encodeStrImm(8, 31, 0x40));
	instrs.push_back(encodeStpImm(16, 17, 31, 0x48));
	instrs.push_back(encodeStrImm(30, 31, 0x58));

	// Call an internal trampoline which runs the relocated original prologue and jumps into the helper body.
	// We use BLR so LR points back into this stub.
	// We'll patch trampoline address after we know final offsets; since it's inside the same stub,
	// we can compute it based on the current instruction count and the fixed sequence below.
	const size_t trampolineAddrIdx = instrs.size();
	instrs.push_back(0); // movz x17, ...
	instrs.push_back(0); // movk x17, ...
	instrs.push_back(0); // movk x17, ...
	instrs.push_back(0); // movk x17, ...
	instrs.push_back(encodeBlr(17));

	// Save return value (overwrite saved x0 so restore path returns correctly).
	instrs.push_back(encodeStrImm(0, 31, 0x00));

	// Call payload: (out, state, x86_addr, arm_addr).
	instrs.push_back(encodeAddImm(0, 31, kHelperInlineDirectFormatBufferOffset)); // x0 = buffer
	{
		const uint64_t state = stateAddr;
		instrs.push_back(encodeMovz(1, static_cast<uint16_t>(state & 0xffffu), 0));
		instrs.push_back(encodeMovk(1, static_cast<uint16_t>((state >> 16) & 0xffffu), 16));
		instrs.push_back(encodeMovk(1, static_cast<uint16_t>((state >> 32) & 0xffffu), 32));
		instrs.push_back(encodeMovk(1, static_cast<uint16_t>((state >> 48) & 0xffffu), 48));
	}
	instrs.push_back(encodeLdrImm(2, 31, 0x08)); // x2 = saved x1 (x86 addr)
	instrs.push_back(encodeLdrImm(3, 31, 0x00)); // x3 = saved x0 (arm addr)
	instrs.push_back(encodeAddImm(4, 22, 0));    // x4 = live x22 (candidate x86 addr in helper context)
	instrs.push_back(encodeAddImm(5, 23, 0));    // x5 = live x23 (stub section base / alt candidate)

	const size_t payloadAddrIdx = instrs.size();
	instrs.push_back(0); // movz x16, ...
	instrs.push_back(0); // movk x16, ...
	instrs.push_back(0); // movk x16, ...
	instrs.push_back(0); // movk x16, ...
	instrs.push_back(encodeBlr(16));

	// Restore regs and return.
	instrs.push_back(encodeLdrImm(30, 31, 0x58));
	instrs.push_back(encodeLdpImm(16, 17, 31, 0x48));
	instrs.push_back(encodeLdrImm(8, 31, 0x40));
	instrs.push_back(encodeLdpImm(6, 7, 31, 0x30));
	instrs.push_back(encodeLdpImm(4, 5, 31, 0x20));
	instrs.push_back(encodeLdpImm(2, 3, 31, 0x10));
	instrs.push_back(encodeLdpImm(0, 1, 31, 0x00));
	instrs.push_back(encodeAddImm(31, 31, kHelperInlineDirectFormatFrameSize));
	instrs.push_back(0xD65F03C0u); // ret

	// Trampoline starts here.
	const size_t trampolineInstrIndex = instrs.size();
	const uint64_t trampolineAddr = stubAddr + trampolineInstrIndex * 4;

	for (size_t i = 0; i < 5; ++i) {
		uint32_t instr = originalInstrs[i];
		if (relocateOriginal) {
			const uint64_t origAddr = helperAddr + i * 4;
			const uint64_t newAddr = stubAddr + instrs.size() * 4;
			uint32_t relocated = 0;
			if (!relocateInstruction(instr, origAddr, newAddr, relocated)) {
				return false;
			}
			instr = relocated;
		} else {
			instr = 0xD503201Fu; // nop
		}
		instrs.push_back(instr);
	}
	{
		uint32_t branchInstrs[5] = {};
		encodeAbsoluteBranch(returnAddr, 17, branchInstrs);
		for (const auto instr : branchInstrs) instrs.push_back(instr);
	}

	// Patch trampoline address load (movz/movk into x17).
	{
		const uint64_t t = trampolineAddr;
		instrs[trampolineAddrIdx + 0] = encodeMovz(17, static_cast<uint16_t>(t & 0xffffu), 0);
		instrs[trampolineAddrIdx + 1] = encodeMovk(17, static_cast<uint16_t>((t >> 16) & 0xffffu), 16);
		instrs[trampolineAddrIdx + 2] = encodeMovk(17, static_cast<uint16_t>((t >> 32) & 0xffffu), 32);
		instrs[trampolineAddrIdx + 3] = encodeMovk(17, static_cast<uint16_t>((t >> 48) & 0xffffu), 48);
	}

	const size_t bodyBytes = instrs.size() * sizeof(uint32_t);
	{
		const uint64_t payloadAddr = payloadBaseAddr + payloadEntryOffset;
		instrs[payloadAddrIdx + 0] = encodeMovz(16, static_cast<uint16_t>(payloadAddr & 0xffffu), 0);
		instrs[payloadAddrIdx + 1] = encodeMovk(16, static_cast<uint16_t>((payloadAddr >> 16) & 0xffffu), 16);
		instrs[payloadAddrIdx + 2] = encodeMovk(16, static_cast<uint16_t>((payloadAddr >> 32) & 0xffffu), 32);
		instrs[payloadAddrIdx + 3] = encodeMovk(16, static_cast<uint16_t>((payloadAddr >> 48) & 0xffffu), 48);
	}
	outStub.assign(bodyBytes, 0);
	fillNops(outStub);
	memcpy(outStub.data(), instrs.data(), bodyBytes);
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
		LOG("Waiting for child exec stop (PT_TRACE_ME)...\n");
		if (!waitForStopped()) return false;

		if (task_for_pid(mach_task_self(), childPid_, &taskPort_) != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get task port for pid %d\n", childPid_);
			return false;
		}
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

struct TrailingZeroRun {
	uint64_t start;
	uint64_t end;
	size_t length;
};

static std::optional<TrailingZeroRun> findTrailingZeroRunInRegion(MuhDebugger &dbg,
                                                                  uint64_t regionStart,
                                                                  uint64_t regionSize) {
	if (regionSize == 0) {
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
	if (runLen == 0) {
		return std::nullopt;
	}
	return TrailingZeroRun{runStart, regionEnd, runLen};
}

enum class InlineHelperHookKind {
	Syscall,
	Resolve,
};

static bool installHelperInlineHookAt(MuhDebugger &dbg,
                                      InlineHelperHookKind kind,
                                      uint64_t helperAddr,
                                      uint64_t stubAddr,
                                      uint64_t payloadBaseAddr,
                                      uint64_t payloadEntryOffset,
                                      uint64_t stateAddr,
                                      uint64_t runtimeExitRetAddr,
                                      const char *label) {
	const char *tag = label ? label : "helper";
	if (!payloadBaseAddr) {
		fprintf(stderr, "%s: Payload base address is 0.\n", tag);
		return false;
	}

	uint32_t originalInstrs[5] = {};
	for (size_t i = 0; i < 5; ++i) {
		if (!dbg.readMemory(helperAddr + i * sizeof(uint32_t), &originalInstrs[i], sizeof(uint32_t))) {
			fprintf(stderr, "%s: Failed to read helper entry for inline hook.\n", tag);
			return false;
		}
	}

	const uint64_t returnAddr = helperAddr + 20;

	std::vector<uint8_t> stub;
	if (kind == InlineHelperHookKind::Syscall) {
		if (!buildHelperSyscallInterceptStub(originalInstrs, helperAddr, stubAddr, returnAddr, payloadBaseAddr,
		                                     payloadEntryOffset, stateAddr, runtimeExitRetAddr, true, stub)) {
			fprintf(stderr, "%s: Failed to build syscall helper stub.\n", tag);
			return false;
		}
	} else {
		if (!buildHelperResolveMapStub(originalInstrs, helperAddr, stubAddr, returnAddr, payloadBaseAddr,
		                               payloadEntryOffset, stateAddr, true, stub)) {
			fprintf(stderr, "%s: Failed to build resolve helper stub.\n", tag);
			return false;
		}
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

	hookLog("%s inline stub at 0x%llx (%zu bytes)\n", tag, static_cast<unsigned long long>(stubAddr), stub.size());
	return true;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "%s <path to program>\n", argv[0]);
		return 1;
	}

	logsEnabled = getenv("ASTROWINE_LOGS");
	const bool inlineHelperHook = envFlagEnabled("ASTROWINE_HELPER_INLINE", true);
	const bool inlineCStubRequested = envFlagEnabled("ASTROWINE_HELPER_INLINE_C", true);
	const char *inlineCPathEnv = getenv("ASTROWINE_HELPER_INLINE_C_PATH");
	const bool payloadLogSyscall = envFlagEnabled("ASTROWINE_PAYLOAD_LOG_SYSCALL", false);
	const bool payloadLogResolve = envFlagEnabled("ASTROWINE_PAYLOAD_LOG_RESOLVE", false);
	const bool payloadIntercept = envFlagEnabled("ASTROWINE_SYSCALL_INTERCEPT", true);
	const bool payloadWineShm = envFlagEnabled("ASTROWINE_WINE_SHM", true);
	const bool waitChild = envFlagEnabled("ASTROWINE_WAIT_CHILD", false);
	const char *nativeThresholdEnv = getenv("ASTROWINE_NATIVE_THRESHOLD_X86");

	if (!inlineHelperHook || !inlineCStubRequested) {
		LOG("Hooks disabled by env, forwarding directly to target.\n");
		execv(argv[1], &argv[1]);
		perror("execv");
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
	LOG("offset_helper_resolve=%llx\n", offsetFinder.offsetHelperResolveAddr_);
	if (offsetFinder.offsetHelperResolveAddr_ == 0) {
		fprintf(stderr, "Failed to locate helper_resolve pattern in Rosetta runtime.\n");
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
	const uint64_t helperResolveAddr = runtimeBase + offsetFinder.offsetHelperResolveAddr_;
	LOG("helper_resolve address: 0x%llx\n", static_cast<unsigned long long>(helperResolveAddr));

	auto runtimeExitRetSectionOffset = []() -> std::optional<uint64_t> {
		const char *path = "/usr/libexec/rosetta/runtime";
		mach_header_64 header{};
		if (!readFileAt(path, 0, &header, sizeof(header))) return std::nullopt;
		if (header.magic != MH_MAGIC_64 || header.ncmds == 0 || header.sizeofcmds == 0) return std::nullopt;
		std::vector<uint8_t> cmds(header.sizeofcmds);
		if (!readFileAt(path, sizeof(header), cmds.data(), cmds.size())) return std::nullopt;
		size_t offset = 0;
		for (uint32_t i = 0; i < header.ncmds && offset + sizeof(load_command) <= cmds.size(); ++i) {
			const auto *cmd = reinterpret_cast<const load_command *>(cmds.data() + offset);
			if (cmd->cmdsize < sizeof(load_command) || offset + cmd->cmdsize > cmds.size()) return std::nullopt;
			if (cmd->cmd == LC_SEGMENT_64 && cmd->cmdsize >= sizeof(segment_command_64)) {
				const auto *seg = reinterpret_cast<const segment_command_64 *>(cmd);
				const auto *sect = reinterpret_cast<const section_64 *>(seg + 1);
				for (uint32_t s = 0; s < seg->nsects; ++s) {
					if (reinterpret_cast<const uint8_t *>(sect + 1) > cmds.data() + offset + cmd->cmdsize) return std::nullopt;
					if (strncmp(sect->sectname, "runtime_exit_ret", sizeof(sect->sectname)) == 0) {
						return sect->addr;
					}
					++sect;
				}
			}
			offset += cmd->cmdsize;
		}
		return std::nullopt;
	}();

	auto runtimeTextUsedEndOffset = []() -> std::optional<uint64_t> {
		const char *path = "/usr/libexec/rosetta/runtime";
		mach_header_64 header{};
		if (!readFileAt(path, 0, &header, sizeof(header))) return std::nullopt;
		if (header.magic != MH_MAGIC_64 || header.ncmds == 0 || header.sizeofcmds == 0) return std::nullopt;
		std::vector<uint8_t> cmds(header.sizeofcmds);
		if (!readFileAt(path, sizeof(header), cmds.data(), cmds.size())) return std::nullopt;
		uint64_t usedEnd = 0;
		size_t offset = 0;
		for (uint32_t i = 0; i < header.ncmds && offset + sizeof(load_command) <= cmds.size(); ++i) {
			const auto *cmd = reinterpret_cast<const load_command *>(cmds.data() + offset);
			if (cmd->cmdsize < sizeof(load_command) || offset + cmd->cmdsize > cmds.size()) return std::nullopt;
			if (cmd->cmd == LC_SEGMENT_64 && cmd->cmdsize >= sizeof(segment_command_64)) {
				const auto *seg = reinterpret_cast<const segment_command_64 *>(cmd);
				if (strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) != 0) {
					offset += cmd->cmdsize;
					continue;
				}
				const auto *sect = reinterpret_cast<const section_64 *>(seg + 1);
				for (uint32_t s = 0; s < seg->nsects; ++s) {
					if (reinterpret_cast<const uint8_t *>(sect + 1) > cmds.data() + offset + cmd->cmdsize) return std::nullopt;
					const uint64_t end = sect->addr + sect->size;
					if (end > usedEnd) usedEnd = end;
					++sect;
				}
			}
			offset += cmd->cmdsize;
		}
		if (usedEnd == 0) return std::nullopt;
		return usedEnd;
	}();

	uint64_t runtimeExitRetAddr = 0;
	if (runtimeExitRetSectionOffset) {
		runtimeExitRetAddr = runtimeBase + *runtimeExitRetSectionOffset;
		LOG("runtime_exit_ret address: 0x%llx\n", static_cast<unsigned long long>(runtimeExitRetAddr));
	} else {
		// Fallback for unexpected runtime layouts.
		runtimeExitRetAddr = runtimeBase + 0x22400;
		LOG("runtime_exit_ret address (fallback): 0x%llx\n", static_cast<unsigned long long>(runtimeExitRetAddr));
	}

	if (runtimeTextUsedEndOffset) {
		LOG("__TEXT used end offset: 0x%llx\n", static_cast<unsigned long long>(*runtimeTextUsedEndOffset));
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

	// Allocate all executable code (2 helper stubs + C payload blob) from a single trailing-zero run
	// in Rosetta runtime's executable mapping. This avoids "last cave wins" fragmentation.
	uint64_t payloadBaseAddr = 0;
	uint64_t helperSyscallStubAddr = 0;
	uint64_t helperResolveStubAddr = 0;
	{
		const char *runtimePath = "/usr/libexec/rosetta/runtime";
		const size_t blobSize = inlineFormatBlob.size();

		// Size pass: build stubs with no relocation so we know how much space to reserve.
		uint32_t dummyInstrs[5] = {};
		std::vector<uint8_t> syscallSizeStub;
		std::vector<uint8_t> resolveSizeStub;
		const uint64_t dummyStubAddr = 0;
		const uint64_t dummyPayloadBase = 0x1000;
		const uint64_t dummyStateAddr = 0;
		if (!buildHelperSyscallInterceptStub(dummyInstrs, helperSyscallAddr, dummyStubAddr, helperSyscallAddr + 20,
		                                     dummyPayloadBase, inlineSyscallOffset, dummyStateAddr, runtimeExitRetAddr,
		                                     false, syscallSizeStub)) {
			fprintf(stderr, "payload: Failed to build syscall stub for sizing.\n");
			dbg.detach();
			return 1;
		}
		if (!buildHelperResolveMapStub(dummyInstrs, helperResolveAddr, dummyStubAddr, helperResolveAddr + 20,
		                               dummyPayloadBase, inlineResolveOffset, dummyStateAddr, false, resolveSizeStub)) {
			fprintf(stderr, "payload: Failed to build resolve stub for sizing.\n");
			dbg.detach();
			return 1;
		}

		mach_vm_address_t regionStart = 0;
		mach_vm_size_t regionSize = 0;
		vm_prot_t regionProt = 0;
		if (!findExecRegionForAddress(dbg, helperSyscallAddr, regionStart, regionSize, regionProt)) {
			fprintf(stderr, "payload: Failed to locate executable region for payload/stubs.\n");
			dbg.detach();
			return 1;
		}

		const auto trailingRun = findTrailingZeroRunInRegion(dbg, regionStart, regionSize);
		if (!trailingRun) {
			fprintf(stderr, "payload: Failed to locate a trailing zero run in executable runtime region.\n");
			dbg.detach();
			return 1;
		}

			const uint64_t runStart = trailingRun->start;
			const uint64_t runEnd = trailingRun->end;
			uint64_t front = runStart;
			if (runtimeTextUsedEndOffset && runtimeBase != 0) {
				const uint64_t safeMinAddr = runtimeBase + *runtimeTextUsedEndOffset;
				if (safeMinAddr > front) front = safeMinAddr;
			}
			front = alignUp(front, 8);
			uint64_t back = runEnd;
			LOG("runtime trailing-zero run: [0x%llx, 0x%llx) len=0x%zx, front=0x%llx, need blob=0x%zx syscall_stub=0x%zx resolve_stub=0x%zx\n",
			    static_cast<unsigned long long>(runStart),
			    static_cast<unsigned long long>(runEnd),
			    trailingRun->length,
			    static_cast<unsigned long long>(front),
			    blobSize,
			    syscallSizeStub.size(),
			    resolveSizeStub.size());

		auto allocFront = [&](size_t size, uint64_t &outAddr) -> bool {
			const uint64_t addr = alignUp(front, 8);
			if (addr + size > back) return false;
			outAddr = addr;
			front = addr + size;
			return true;
		};
		auto allocBack = [&](size_t size, uint64_t &outAddr) -> bool {
			const uint64_t addr = alignDown(back - size, 8);
			if (addr < front) return false;
			outAddr = addr;
			back = addr;
			return true;
		};

		if (!allocFront(syscallSizeStub.size(), helperSyscallStubAddr)) {
			fprintf(stderr, "payload: Not enough trailing-zero space for helper_syscall stub.\n");
			dbg.detach();
			return 1;
		}
		if (!allocFront(resolveSizeStub.size(), helperResolveStubAddr)) {
			fprintf(stderr, "payload: Not enough trailing-zero space for helper_resolve stub.\n");
			dbg.detach();
			return 1;
		}
			if (!allocBack(blobSize, payloadBaseAddr)) {
				fprintf(stderr, "payload: Not enough trailing-zero space for payload blob.\n");
				dbg.detach();
				return 1;
			}

		auto ensureFileZero = [&](const char *what, uint64_t addr, size_t size) -> bool {
			if (runtimeBase == 0) return true;
			if (addr < runtimeBase) return false;
			const uint64_t fileOffset = addr - runtimeBase;
			if (!isFileRangeZero(runtimePath, fileOffset, size)) {
				fprintf(stderr, "%s: Target range is not file-zero (addr 0x%llx file_off 0x%llx size %zu)\n",
				        what,
				        static_cast<unsigned long long>(addr),
				        static_cast<unsigned long long>(fileOffset),
				        size);
				return false;
			}
			return true;
		};

			if (!ensureFileZero("payload", payloadBaseAddr, blobSize) ||
			    !ensureFileZero("helper_syscall", helperSyscallStubAddr, syscallSizeStub.size()) ||
			    !ensureFileZero("helper_resolve", helperResolveStubAddr, resolveSizeStub.size())) {
				dbg.detach();
				return 1;
			}

		if (!dbg.adjustMemoryProtection(payloadBaseAddr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, blobSize)) {
			fprintf(stderr, "payload: Failed to adjust protection for payload blob.\n");
			dbg.detach();
			return 1;
		}
		if (!dbg.writeMemory(payloadBaseAddr, inlineFormatBlob.data(), inlineFormatBlob.size())) {
			fprintf(stderr, "payload: Failed to write payload blob.\n");
			dbg.detach();
			return 1;
		}
		(void)dbg.flushInstructionCache(payloadBaseAddr, blobSize);
		if (!dbg.adjustMemoryProtection(payloadBaseAddr, VM_PROT_READ | VM_PROT_EXECUTE, blobSize)) {
			fprintf(stderr, "payload: Failed to restore protection for payload blob.\n");
			dbg.detach();
			return 1;
		}

		hookLog("payload blob at 0x%llx (%zu bytes)\n",
		        static_cast<unsigned long long>(payloadBaseAddr),
		        blobSize);
		hookLog("helper_syscall stub reserved at 0x%llx (%zu bytes)\n",
		        static_cast<unsigned long long>(helperSyscallStubAddr),
		        syscallSizeStub.size());
		hookLog("helper_resolve stub reserved at 0x%llx (%zu bytes)\n",
		        static_cast<unsigned long long>(helperResolveStubAddr),
		        resolveSizeStub.size());
	}

	// Allocate and initialize the payload state in the target process.
	uint64_t stateAddr = 0;
	{
		const char *stateSizeEnv = getenv("ASTROWINE_STATE_SIZE");
		const uint64_t stateSize = stateSizeEnv ? strtoull(stateSizeEnv, nullptr, 0) : 0x200000;
		mach_vm_address_t addr = 0;
		kern_return_t kr = KERN_FAILURE;

		// Rosetta runtime wants to reserve large contiguous regions for AOT/JIT mappings.
		// Avoid fragmenting low address space by defaulting to a high fixed mapping.
		const char *stateAddrEnv = getenv("ASTROWINE_STATE_ADDR");
		if (stateAddrEnv && *stateAddrEnv) {
			addr = static_cast<mach_vm_address_t>(strtoull(stateAddrEnv, nullptr, 0));
			kr = mach_vm_allocate(dbg.taskPort(), &addr, stateSize, VM_FLAGS_FIXED);
			if (kr != KERN_SUCCESS) {
				fprintf(stderr, "Failed to allocate fixed state memory at 0x%llx (error 0x%x: %s)\n",
				        static_cast<unsigned long long>(addr), kr, mach_error_string(kr));
				dbg.detach();
				return 1;
			}
		} else {
			const uint64_t candidates[] = {
				0x700000000000ull,
				0x6f0000000000ull,
				0x600000000000ull,
				0x500000000000ull,
				0x400000000000ull,
			};
			bool allocated = false;
			for (const auto base : candidates) {
				addr = static_cast<mach_vm_address_t>(base);
				kr = mach_vm_allocate(dbg.taskPort(), &addr, stateSize, VM_FLAGS_FIXED);
				if (kr == KERN_SUCCESS) {
					allocated = true;
					break;
				}
			}
			if (!allocated) {
				addr = 0;
				kr = mach_vm_allocate(dbg.taskPort(), &addr, stateSize, VM_FLAGS_ANYWHERE);
			}
			if (kr != KERN_SUCCESS) {
				fprintf(stderr, "Failed to allocate state memory in target (error 0x%x: %s)\n", kr, mach_error_string(kr));
				dbg.detach();
				return 1;
			}
		}
		stateAddr = addr;
		AstroWineStateHeader header{};
		header.magic = kAstroWineStateMagic;
		header.version = kAstroWineStateVersion;
		header.lock = 0;
		header.count = 0;
		const uint64_t available = stateSize > sizeof(header) ? (stateSize - sizeof(header)) : 0;
		const uint64_t perEntry = sizeof(uint64_t) * 2 + sizeof(uint8_t);
		const uint64_t cap = perEntry ? (available / perEntry) : 0;
		header.capacity = cap > 0xffffffffu ? 0xffffffffu : static_cast<uint32_t>(cap);
		// 0 uses seccomp-like address filtering; non-zero forces a simple < threshold policy.
		header.native_threshold_x86 = (nativeThresholdEnv && *nativeThresholdEnv)
		                                  ? strtoull(nativeThresholdEnv, nullptr, 0)
		                                  : 0;
		header.wine_shm_ptr = payloadWineShm ? kAstroWineWineShmPtrDefault : 0;
		header.flags = 0;
		if (payloadLogSyscall) header.flags |= ASTROWINE_STATE_FLAG_LOG_SYSCALL;
		if (payloadLogResolve) header.flags |= ASTROWINE_STATE_FLAG_LOG_RESOLVE;
		if (payloadIntercept) header.flags |= ASTROWINE_STATE_FLAG_INTERCEPT;
		if (!dbg.writeMemory(stateAddr, &header, sizeof(header))) {
			fprintf(stderr, "Failed to initialize state header in target.\n");
			dbg.detach();
			return 1;
		}
		LOG("payload state at 0x%llx (size 0x%llx cap %u flags 0x%x wine_shm %s threshold 0x%llx)\n",
		    static_cast<unsigned long long>(stateAddr),
		    static_cast<unsigned long long>(stateSize),
		    header.capacity,
		    header.flags,
		    header.wine_shm_ptr ? "on" : "off",
		    static_cast<unsigned long long>(header.native_threshold_x86));
	}

	if (!installHelperInlineHookAt(dbg, InlineHelperHookKind::Syscall, helperSyscallAddr, helperSyscallStubAddr,
	                               payloadBaseAddr, inlineSyscallOffset, stateAddr, runtimeExitRetAddr, "helper_syscall")) {
		fprintf(stderr, "Inline helper_syscall hook failed.\n");
		dbg.detach();
		return 1;
	}
	if (!installHelperInlineHookAt(dbg, InlineHelperHookKind::Resolve, helperResolveAddr, helperResolveStubAddr,
	                               payloadBaseAddr, inlineResolveOffset, stateAddr, runtimeExitRetAddr, "helper_resolve")) {
		fprintf(stderr, "Inline helper_resolve hook failed.\n");
		dbg.detach();
		return 1;
	}

	if (!dbg.detach()) {
		fprintf(stderr, "Failed to detach debugger\n");
		return 1;
	}

	if (waitChild) {
		int status = 0;
		(void)waitpid(child, &status, 0);
	}

	return 0;
}
