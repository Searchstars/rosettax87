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
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach_vm.h>
#include <mach/vm_attributes.h>
#include <sys/stat.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "offset_finder.hpp"

class MuhDebugger;

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

const char *logsEnabled = nullptr;
static bool hookLogsEnabled = true;
static bool hookLogInitialized = false;
static int hookLogFd = -1;
static int hookLogSinkFd = STDERR_FILENO;

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

static const char *getenvPrefer(const char *primary, const char *fallback) {
	const char *value = getenv(primary);
	if (value) {
		return value;
	}
	return getenv(fallback);
}

static std::optional<uint64_t> findPatternInFile(const char *path, const std::vector<uint8_t> &pattern) {
	if (!path || pattern.empty()) {
		return std::nullopt;
	}
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		return std::nullopt;
	}
	file.seekg(0, std::ios::end);
	const std::streampos size = file.tellg();
	file.seekg(0, std::ios::beg);
	if (size <= 0) {
		return std::nullopt;
	}
	std::vector<unsigned char> buffer(static_cast<size_t>(size));
	if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
		return std::nullopt;
	}
	const size_t patSize = pattern.size();
	if (buffer.size() < patSize) {
		return std::nullopt;
	}
	for (size_t i = 0; i + patSize <= buffer.size(); ++i) {
		bool match = true;
		for (size_t j = 0; j < patSize; ++j) {
			if (buffer[i + j] != pattern[j]) {
				match = false;
				break;
			}
		}
		if (match) {
			return static_cast<uint64_t>(i);
		}
	}
	return std::nullopt;
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

struct MachSegmentInfo {
	std::string name;
	uint64_t vmaddr = 0;
	uint64_t vmsize = 0;
	uint64_t fileoff = 0;
	uint64_t filesize = 0;
	vm_prot_t initprot = 0;
};

struct MachSectionInfo {
	std::string segname;
	std::string sectname;
	uint64_t addr = 0;
	uint64_t size = 0;
	uint64_t offset = 0;
};

struct SharedCacheMapping {
	uint64_t address = 0;
	uint64_t size = 0;
	uint64_t fileOffset = 0;
	uint32_t maxProt = 0;
	uint32_t initProt = 0;
};

struct SharedCacheImage {
	uint64_t address = 0;
	uint64_t modTime = 0;
	uint64_t inode = 0;
	uint32_t pathFileOffset = 0;
	uint32_t pad = 0;
};

static bool loadFileBuffer(const char *path, std::vector<unsigned char> &buffer) {
	if (!path) {
		return false;
	}
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		return false;
	}
	file.seekg(0, std::ios::end);
	const std::streampos size = file.tellg();
	file.seekg(0, std::ios::beg);
	if (size <= 0) {
		return false;
	}
	buffer.resize(static_cast<size_t>(size));
	return static_cast<bool>(file.read(reinterpret_cast<char *>(buffer.data()), size));
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

static bool readFileAll(const char *path, std::vector<uint8_t> &out) {
	struct stat st {};
	if (!path || stat(path, &st) != 0 || st.st_size <= 0) {
		return false;
	}
	if (st.st_size > static_cast<off_t>(1024 * 1024)) {
		return false;
	}
	out.resize(static_cast<size_t>(st.st_size));
	if (!readFileAt(path, 0, out.data(), out.size())) {
		out.clear();
		return false;
	}
	return true;
}

static bool readMachOTextSection(const char *path, std::vector<uint8_t> &out) {
	if (!path) {
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
	size_t offset = 0;
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
					if (sect->size == 0 || sect->offset + sect->size > static_cast<uint64_t>(st.st_size)) {
						return false;
					}
					out.resize(static_cast<size_t>(sect->size));
					return readFileAt(path, sect->offset, out.data(), out.size());
				}
				++sect;
			}
		}
		offset += cmd->cmdsize;
	}
	return false;
}

static bool readMachOTextSectionWithSymbol(const char *path,
                                           const char *symbolName,
                                           std::vector<uint8_t> &out,
                                           uint64_t &symbolOffset) {
	symbolOffset = 0;
	if (!path || !symbolName) {
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
		if (strcmp(name, symbolName) == 0) {
			if (sym.n_value < textAddr) {
				return false;
			}
			symbolOffset = sym.n_value - textAddr;
			if (symbolOffset >= textSize) {
				return false;
			}
			return true;
		}
	}
	return false;
}

static std::string extractMachName(const char *raw, size_t maxLen) {
	const size_t len = strnlen(raw, maxLen);
	return std::string(raw, raw + len);
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

static bool parseMachO(const std::vector<unsigned char> &buffer,
                       std::vector<MachSegmentInfo> &segments,
                       std::vector<MachSectionInfo> &sections) {
	if (buffer.size() < sizeof(mach_header_64)) {
		return false;
	}
	const auto *header = reinterpret_cast<const mach_header_64 *>(buffer.data());
	if (header->magic != MH_MAGIC_64) {
		return false;
	}
	uint64_t offset = sizeof(mach_header_64);
	for (uint32_t i = 0; i < header->ncmds; ++i) {
		if (offset + sizeof(load_command) > buffer.size()) {
			return false;
		}
		const auto *cmd = reinterpret_cast<const load_command *>(buffer.data() + offset);
		if (cmd->cmd == LC_SEGMENT_64) {
			if (offset + sizeof(segment_command_64) > buffer.size()) {
				return false;
			}
			const auto *seg = reinterpret_cast<const segment_command_64 *>(buffer.data() + offset);
			MachSegmentInfo segInfo;
			segInfo.name = extractMachName(seg->segname, sizeof(seg->segname));
			segInfo.vmaddr = seg->vmaddr;
			segInfo.vmsize = seg->vmsize;
			segInfo.fileoff = seg->fileoff;
			segInfo.filesize = seg->filesize;
			segInfo.initprot = seg->initprot;
			segments.push_back(segInfo);

			const uint64_t sectionsOffset = offset + sizeof(segment_command_64);
			const uint64_t needed = sectionsOffset + static_cast<uint64_t>(seg->nsects) * sizeof(section_64);
			if (needed > buffer.size()) {
				return false;
			}
			const auto *sec = reinterpret_cast<const section_64 *>(buffer.data() + sectionsOffset);
			for (uint32_t s = 0; s < seg->nsects; ++s) {
				MachSectionInfo secInfo;
				secInfo.segname = extractMachName(sec[s].segname, sizeof(sec[s].segname));
				secInfo.sectname = extractMachName(sec[s].sectname, sizeof(sec[s].sectname));
				secInfo.addr = sec[s].addr;
				secInfo.size = sec[s].size;
				secInfo.offset = sec[s].offset;
				sections.push_back(secInfo);
			}
		}
		offset += cmd->cmdsize;
		if (offset > buffer.size()) {
			return false;
		}
	}
	return true;
}

static std::optional<uint64_t> machHeaderSize(const std::vector<unsigned char> &buffer) {
	if (buffer.size() < sizeof(mach_header_64)) {
		return std::nullopt;
	}
	const auto *header = reinterpret_cast<const mach_header_64 *>(buffer.data());
	if (header->magic != MH_MAGIC_64) {
		return std::nullopt;
	}
	return sizeof(mach_header_64) + header->sizeofcmds;
}

static std::optional<uint64_t> findSegmentVmaddr(const std::vector<MachSegmentInfo> &segments, const char *name) {
	if (!name) {
		return std::nullopt;
	}
	for (const auto &seg : segments) {
		if (seg.name == name) {
			return seg.vmaddr;
		}
	}
	return std::nullopt;
}

static std::optional<uint64_t> fileOffsetToVmAddr(const std::vector<MachSegmentInfo> &segments, uint64_t fileOffset) {
	for (const auto &seg : segments) {
		if (fileOffset >= seg.fileoff && fileOffset < seg.fileoff + seg.filesize) {
			return seg.vmaddr + (fileOffset - seg.fileoff);
		}
	}
	return std::nullopt;
}

static bool rangeOverlaps(uint64_t start, uint64_t size, const std::vector<std::pair<uint64_t, uint64_t>> &ranges) {
	const uint64_t end = start + size;
	for (const auto &range : ranges) {
		if (start < range.second && end > range.first) {
			return true;
		}
	}
	return false;
}

static uint64_t alignUp(uint64_t value, uint64_t alignment) {
	if (alignment == 0) {
		return value;
	}
	return (value + alignment - 1) & ~(alignment - 1);
}

static std::optional<uint64_t> findZeroCave(const std::vector<unsigned char> &buffer,
                                            const std::vector<MachSegmentInfo> &segments,
                                            const std::vector<MachSectionInfo> &sections,
                                            size_t minSize,
                                            size_t alignment,
                                            vm_prot_t requiredProt,
                                            bool avoidSections,
                                            uint64_t minFileOffset) {
	const size_t aligned = alignment ? alignment : 1;
	std::optional<uint64_t> best;
	for (const auto &seg : segments) {
		if ((seg.initprot & requiredProt) != requiredProt) {
			continue;
		}
		if (seg.filesize == 0) {
			continue;
		}
		const uint64_t segStart = seg.fileoff;
		const uint64_t segEnd = seg.fileoff + seg.filesize;
		if (segEnd > buffer.size()) {
			continue;
		}
		std::vector<std::pair<uint64_t, uint64_t>> usedRanges;
		if (avoidSections) {
			for (const auto &sec : sections) {
				if (sec.segname != seg.name) {
					continue;
				}
				if (sec.offset == 0 || sec.size == 0) {
					continue;
				}
				usedRanges.emplace_back(sec.offset, sec.offset + sec.size);
			}
			std::sort(usedRanges.begin(), usedRanges.end());
		}
		uint64_t i = segStart;
		if (minFileOffset > i) {
			i = minFileOffset;
		}
		while (i < segEnd) {
			if (buffer[i] != 0) {
				++i;
				continue;
			}
			uint64_t j = i + 1;
			while (j < segEnd && buffer[j] == 0) {
				++j;
			}
			uint64_t runStart = i;
			uint64_t runEnd = j;
			uint64_t candidate = alignUp(runStart, aligned);
			if (candidate < minFileOffset) {
				candidate = alignUp(minFileOffset, aligned);
			}
			if (avoidSections && !usedRanges.empty()) {
				bool moved = true;
				while (moved) {
					moved = false;
					for (const auto &range : usedRanges) {
						if (candidate >= runEnd) {
							break;
						}
						if (candidate < range.second && (candidate + minSize) > range.first) {
							candidate = alignUp(range.second, aligned);
							moved = true;
						}
					}
				}
			}
			if (candidate + minSize <= runEnd) {
				best = candidate;
			}
			i = j;
		}
	}
	return best;
}

struct DyldInfo {
	uint32_t rebase_off = 0;
	uint32_t rebase_size = 0;
	uint32_t bind_off = 0;
	uint32_t bind_size = 0;
	uint32_t weak_bind_off = 0;
	uint32_t weak_bind_size = 0;
	uint32_t lazy_bind_off = 0;
	uint32_t lazy_bind_size = 0;
	uint32_t export_off = 0;
	uint32_t export_size = 0;
	bool valid = false;
};

struct LoadedImage {
	uint64_t remoteBase = 0;
	uint64_t slide = 0;
	uint64_t minVmaddr = 0;
	uint64_t maxVmaddr = 0;
	uint64_t textVmaddr = 0;
	std::vector<MachSegmentInfo> segments;
	std::vector<MachSectionInfo> sections;
	DyldInfo dyldInfo;
};

struct RemoteImageInfo {
	uint64_t base = 0;
	std::string path;
};

struct RemoteImageCache {
	std::vector<MachSegmentInfo> segments;
	DyldInfo dyldInfo;
	std::vector<uint8_t> exportTrie;
	uint64_t textVmaddr = 0;
	bool valid = false;
};

struct ImageFileCache {
	std::vector<unsigned char> buffer;
	std::vector<MachSegmentInfo> segments;
	DyldInfo dyldInfo;
	uint64_t textVmaddr = 0;
	bool parsed = false;
};

static bool parseDyldInfo(const std::vector<unsigned char> &buffer, DyldInfo &info) {
	if (buffer.size() < sizeof(mach_header_64)) {
		return false;
	}
	const auto *header = reinterpret_cast<const mach_header_64 *>(buffer.data());
	if (header->magic != MH_MAGIC_64) {
		return false;
	}
	uint64_t offset = sizeof(mach_header_64);
	for (uint32_t i = 0; i < header->ncmds; ++i) {
		if (offset + sizeof(load_command) > buffer.size()) {
			return false;
		}
		const auto *cmd = reinterpret_cast<const load_command *>(buffer.data() + offset);
		if (cmd->cmd == LC_DYLD_INFO_ONLY || cmd->cmd == LC_DYLD_INFO) {
			if (offset + sizeof(dyld_info_command) > buffer.size()) {
				return false;
			}
			const auto *dyld = reinterpret_cast<const dyld_info_command *>(buffer.data() + offset);
			info.rebase_off = dyld->rebase_off;
			info.rebase_size = dyld->rebase_size;
			info.bind_off = dyld->bind_off;
			info.bind_size = dyld->bind_size;
			info.weak_bind_off = dyld->weak_bind_off;
			info.weak_bind_size = dyld->weak_bind_size;
			info.lazy_bind_off = dyld->lazy_bind_off;
			info.lazy_bind_size = dyld->lazy_bind_size;
			info.export_off = dyld->export_off;
			info.export_size = dyld->export_size;
			info.valid = true;
		} else if (cmd->cmd == LC_DYLD_EXPORTS_TRIE) {
			if (offset + sizeof(load_command) + 8 > buffer.size()) {
				return false;
			}
			const auto *fields = reinterpret_cast<const uint32_t *>(buffer.data() + offset);
			const uint32_t cmdSize = fields[1];
			if (offset + cmdSize > buffer.size()) {
				return false;
			}
			info.export_off = fields[2];
			info.export_size = fields[3];
			info.valid = true;
		}
		offset += cmd->cmdsize;
		if (offset > buffer.size()) {
			return false;
		}
	}
	return info.valid;
}

static bool loadRemoteImageCache(MuhDebugger &dbg, const RemoteImageInfo &image, RemoteImageCache &cache);

static bool readUleb128(const uint8_t *start, const uint8_t *end, uint64_t &value, size_t &used) {
	value = 0;
	used = 0;
	uint64_t shift = 0;
	const uint8_t *p = start;
	while (p < end) {
		const uint8_t byte = *p++;
		value |= static_cast<uint64_t>(byte & 0x7fu) << shift;
		used++;
		if ((byte & 0x80u) == 0) {
			return true;
		}
		shift += 7;
		if (shift > 63) {
			return false;
		}
	}
	return false;
}

static bool readSleb128(const uint8_t *start, const uint8_t *end, int64_t &value, size_t &used) {
	value = 0;
	used = 0;
	uint64_t shift = 0;
	const uint8_t *p = start;
	uint8_t byte = 0;
	while (p < end) {
		byte = *p++;
		value |= static_cast<int64_t>(byte & 0x7fu) << shift;
		used++;
		shift += 7;
		if ((byte & 0x80u) == 0) {
			break;
		}
		if (shift > 63) {
			return false;
		}
	}
	if ((byte & 0x40u) != 0) {
		value |= -1LL << shift;
	}
	return true;
}

static std::optional<uint64_t> findTextVmaddr(const std::vector<MachSegmentInfo> &segments) {
	for (const auto &seg : segments) {
		if (seg.name == "__TEXT") {
			return seg.vmaddr;
		}
	}
	return std::nullopt;
}

static bool trieFindSymbol(const uint8_t *trie,
                           size_t trieSize,
                           uint64_t nodeOffset,
                           const char *symbol,
                           uint64_t &address,
                           uint64_t &flags) {
	if (!symbol) {
		return false;
	}
	if (nodeOffset >= trieSize) {
		return false;
	}
	const uint8_t *node = trie + nodeOffset;
	const uint8_t *end = trie + trieSize;
	uint64_t terminalSize = 0;
	size_t used = 0;
	if (!readUleb128(node, end, terminalSize, used)) {
		return false;
	}
	const uint8_t *p = node + used;
	if (p + terminalSize > end) {
		return false;
	}
	const bool isTerminal = terminalSize != 0;
	if (*symbol == '\0' && isTerminal) {
		uint64_t termFlags = 0;
		size_t flagsUsed = 0;
		if (!readUleb128(p, end, termFlags, flagsUsed)) {
			return false;
		}
		const uint8_t *q = p + flagsUsed;
		uint64_t termAddr = 0;
		size_t addrUsed = 0;
		if (!readUleb128(q, end, termAddr, addrUsed)) {
			return false;
		}
		if ((termFlags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0) {
			return false;
		}
		address = termAddr;
		flags = termFlags;
		return true;
	}
	const uint8_t *children = p + terminalSize;
	if (children >= end) {
		return false;
	}
	uint8_t childCount = *children++;
	for (uint8_t i = 0; i < childCount; ++i) {
		const char *edge = reinterpret_cast<const char *>(children);
		const size_t edgeLen = strnlen(edge, static_cast<size_t>(end - children));
		if (children + edgeLen >= end) {
			return false;
		}
		children += edgeLen + 1;
		uint64_t childNodeOffset = 0;
		size_t childUsed = 0;
		if (!readUleb128(children, end, childNodeOffset, childUsed)) {
			return false;
		}
		children += childUsed;
		if (strncmp(symbol, edge, edgeLen) == 0) {
			if (trieFindSymbol(trie, trieSize, childNodeOffset, symbol + edgeLen, address, flags)) {
				return true;
			}
		}
	}
	return false;
}

static bool findExportedSymbolInBuffer(const std::vector<unsigned char> &buffer,
                                       const std::string &symbol,
                                       uint64_t &address,
                                       uint64_t &textVmaddr) {
	DyldInfo info;
	if (!parseDyldInfo(buffer, info) || !info.valid || info.export_size == 0) {
		return false;
	}
	std::vector<MachSegmentInfo> segments;
	std::vector<MachSectionInfo> sections;
	if (!parseMachO(buffer, segments, sections)) {
		return false;
	}
	const auto textVm = findTextVmaddr(segments);
	if (!textVm) {
		return false;
	}
	textVmaddr = *textVm;
	if (info.export_off + info.export_size > buffer.size()) {
		return false;
	}
	const uint8_t *trie = buffer.data() + info.export_off;
	uint64_t flags = 0;
	return trieFindSymbol(trie, info.export_size, 0, symbol.c_str(), address, flags);
}

static bool findSharedCachePath(std::string &path) {
	if (const char *env = getenv("ASTROWINE_SHARED_CACHE_PATH")) {
		if (access(env, R_OK) == 0) {
			path = env;
			return true;
		}
	}
	const char *candidates[] = {
		"/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
		"/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64",
		"/System/Library/dyld/dyld_shared_cache_arm64e",
		"/System/Library/dyld/dyld_shared_cache_arm64"
	};
	for (const auto &candidate : candidates) {
		if (access(candidate, R_OK) == 0) {
			path = candidate;
			return true;
		}
	}
	return false;
}

static bool loadSharedCacheMappings(const char *cachePath,
                                    std::vector<SharedCacheMapping> &mappings,
                                    std::vector<SharedCacheImage> &images) {
	uint8_t header[32] = {};
	if (!readFileAt(cachePath, 0, header, sizeof(header))) {
		return false;
	}
	if (memcmp(header, "dyld_v1", 7) != 0) {
		return false;
	}
	const uint32_t mappingOffset = *reinterpret_cast<uint32_t *>(header + 16);
	const uint32_t mappingCount = *reinterpret_cast<uint32_t *>(header + 20);
	const uint32_t imagesOffset = *reinterpret_cast<uint32_t *>(header + 24);
	const uint32_t imagesCount = *reinterpret_cast<uint32_t *>(header + 28);
	if (mappingCount == 0 || imagesCount == 0) {
		return false;
	}
	mappings.resize(mappingCount);
	images.resize(imagesCount);
	if (!readFileAt(cachePath, mappingOffset, mappings.data(), mappings.size() * sizeof(SharedCacheMapping))) {
		return false;
	}
	if (!readFileAt(cachePath, imagesOffset, images.data(), images.size() * sizeof(SharedCacheImage))) {
		return false;
	}
	return true;
}

static bool sharedCacheBaseAddress(const char *cachePath, uint64_t &baseAddr) {
	std::vector<SharedCacheMapping> mappings;
	std::vector<SharedCacheImage> images;
	if (!loadSharedCacheMappings(cachePath, mappings, images)) {
		return false;
	}
	uint64_t minAddr = UINT64_MAX;
	for (const auto &mapping : mappings) {
		minAddr = std::min(minAddr, mapping.address);
	}
	if (minAddr == UINT64_MAX) {
		return false;
	}
	baseAddr = minAddr;
	return true;
}

static bool resolveSharedCacheSymbol(const char *cachePath,
                                     const std::string &imageSuffix,
                                     const std::string &symbol,
                                     uint64_t slide,
                                     uint64_t &addr) {
	std::vector<SharedCacheMapping> mappings;
	std::vector<SharedCacheImage> images;
	if (!loadSharedCacheMappings(cachePath, mappings, images)) {
		return false;
	}

	uint64_t imageAddress = 0;
	uint64_t imageFileOffset = 0;
	bool foundImage = false;
	for (const auto &image : images) {
		char pathBuf[512] = {};
		if (!readFileAt(cachePath, image.pathFileOffset, pathBuf, sizeof(pathBuf) - 1)) {
			continue;
		}
		const std::string imagePath(pathBuf);
		if (imagePath.size() < imageSuffix.size()) {
			continue;
		}
		if (imagePath.compare(imagePath.size() - imageSuffix.size(), imageSuffix.size(), imageSuffix) != 0) {
			continue;
		}
		imageAddress = image.address;
		for (const auto &mapping : mappings) {
			if (image.address >= mapping.address && image.address < mapping.address + mapping.size) {
				imageFileOffset = mapping.fileOffset + (image.address - mapping.address);
				break;
			}
		}
		foundImage = true;
		break;
	}
	if (!foundImage) {
		return false;
	}

	mach_header_64 header{};
	if (!readFileAt(cachePath, imageFileOffset, &header, sizeof(header))) {
		return false;
	}
	if (header.magic != MH_MAGIC_64) {
		return false;
	}
	const uint64_t cmdSize = static_cast<uint64_t>(header.sizeofcmds);
	std::vector<unsigned char> buffer(sizeof(header) + cmdSize);
	memcpy(buffer.data(), &header, sizeof(header));
	if (cmdSize > 0) {
		if (!readFileAt(cachePath, imageFileOffset + sizeof(header), buffer.data() + sizeof(header), cmdSize)) {
			return false;
		}
	}

	DyldInfo info;
	if (!parseDyldInfo(buffer, info) || !info.valid || info.export_size == 0) {
		return false;
	}
	std::vector<MachSegmentInfo> segments;
	std::vector<MachSectionInfo> sections;
	if (!parseMachO(buffer, segments, sections)) {
		return false;
	}
	const auto textVm = findTextVmaddr(segments);
	if (!textVm) {
		return false;
	}
	const uint64_t exportFileOffset = imageFileOffset + info.export_off;
	std::vector<uint8_t> exportTrie(info.export_size);
	if (!readFileAt(cachePath, exportFileOffset, exportTrie.data(), exportTrie.size())) {
		return false;
	}

	uint64_t symAddr = 0;
	uint64_t flags = 0;
	if (!trieFindSymbol(exportTrie.data(), exportTrie.size(), 0, symbol.c_str(), symAddr, flags)) {
		std::string alt;
		if (!symbol.empty() && symbol[0] == '_') {
			alt = symbol.substr(1);
		} else {
			alt = "_" + symbol;
		}
		if (alt.empty() || !trieFindSymbol(exportTrie.data(), exportTrie.size(), 0, alt.c_str(), symAddr, flags)) {
			return false;
		}
	}
	addr = symAddr + slide;
	return true;
}

static bool collectRemoteImages(task_t taskPort, std::vector<RemoteImageInfo> &images) {
	kern_return_t kr = KERN_SUCCESS;
	auto processInfo = _dyld_process_info_create(taskPort, 0, &kr);
	if (kr != KERN_SUCCESS || !processInfo) {
		return false;
	}
	_dyld_process_info_for_each_image(processInfo, ^(uint64_t address, const uuid_t, const char *path) {
		if (!path) {
			return;
		}
		RemoteImageInfo info;
		info.base = address;
		info.path = path;
		images.push_back(std::move(info));
	});
	_dyld_process_info_release(processInfo);
	return !images.empty();
}

static bool loadImageFileCache(const std::string &path, ImageFileCache &cache) {
	if (cache.parsed) {
		return true;
	}
	if (!loadFileBuffer(path.c_str(), cache.buffer)) {
		return false;
	}
	std::vector<MachSectionInfo> dummySections;
	if (!parseMachO(cache.buffer, cache.segments, dummySections)) {
		return false;
	}
	if (!parseDyldInfo(cache.buffer, cache.dyldInfo)) {
		cache.dyldInfo.valid = false;
	}
	const auto textVm = findTextVmaddr(cache.segments);
	if (!textVm) {
		return false;
	}
	cache.textVmaddr = *textVm;
	cache.parsed = true;
	return true;
}

static bool resolveSymbolInImage(MuhDebugger &dbg,
                                 const RemoteImageInfo &image,
                                 const std::string &symbol,
                                 std::unordered_map<uint64_t, RemoteImageCache> &remoteCache,
                                 std::unordered_map<std::string, ImageFileCache> &fileCache,
                                 uint64_t &addr);

static bool resolveSymbolGlobal(MuhDebugger &dbg,
                                const std::string &symbol,
                                const std::vector<RemoteImageInfo> &images,
                                std::unordered_map<uint64_t, RemoteImageCache> &remoteCache,
                                std::unordered_map<std::string, ImageFileCache> &fileCache,
                                std::unordered_map<std::string, uint64_t> &symbolCache,
                                uint64_t &addr);

static bool applySegmentProtections(MuhDebugger &dbg, const LoadedImage &image);
static bool mapMachOIntoTarget(MuhDebugger &dbg,
                               const std::vector<unsigned char> &buffer,
                               LoadedImage &image);
static bool applyRebase(MuhDebugger &dbg,
                        const LoadedImage &image,
                        const std::vector<unsigned char> &buffer);
static bool applyBindOpcodes(MuhDebugger &dbg,
                             const LoadedImage &image,
                             const std::vector<unsigned char> &buffer,
                             uint32_t bindOff,
                             uint32_t bindSize,
                             const std::vector<RemoteImageInfo> &images,
                             std::unordered_map<std::string, ImageFileCache> &imageCache,
                             std::unordered_map<std::string, uint64_t> &symbolCache);
static bool applyBinds(MuhDebugger &dbg,
                       const LoadedImage &image,
                       const std::vector<unsigned char> &buffer,
                       const std::vector<RemoteImageInfo> &images,
                       std::unordered_map<std::string, ImageFileCache> &imageCache,
                       std::unordered_map<std::string, uint64_t> &symbolCache);
static bool runModInitFunctions(MuhDebugger &dbg, const LoadedImage &image);
static bool injectHelperMachO(MuhDebugger &dbg,
                              const char *machoPath,
                              const char *symbolName,
                              uint64_t &hookAddr,
                              uint64_t &counterAddr);

static std::optional<uint32_t> encodeBranch(uint64_t from, uint64_t to) {
	const int64_t diff = static_cast<int64_t>(to) - static_cast<int64_t>(from);
	if (diff % 4 != 0) {
		return std::nullopt;
	}
	const int64_t imm = diff >> 2;
	if (imm < -(1LL << 25) || imm >= (1LL << 25)) {
		return std::nullopt;
	}
	const uint32_t encoded = 0x14000000u | (static_cast<uint32_t>(imm) & 0x03ffffffu);
	return encoded;
}

static std::optional<uint32_t> encodeCbzImm(uint8_t reg, int64_t diff, bool nonzero) {
	if (diff % 4 != 0) {
		return std::nullopt;
	}
	const int64_t imm = diff >> 2;
	if (imm < -(1LL << 18) || imm >= (1LL << 18)) {
		return std::nullopt;
	}
	const uint32_t op = nonzero ? 0x35000000u : 0x34000000u;
	return op | ((static_cast<uint32_t>(imm) & 0x7ffffu) << 5) | (reg & 0x1fu);
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

static uint32_t encodeSvc(uint16_t imm16) {
	return 0xD4000001u | (static_cast<uint32_t>(imm16) << 5);
}

static uint32_t encodeBlr(uint8_t reg) {
	return 0xD63F0000u | (static_cast<uint32_t>(reg & 0x1fu) << 5);
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

constexpr size_t kHelperInlineDefaultStubSize = 0x78;
constexpr size_t kHelperInlineStdioStubSize = 0x180;
constexpr size_t kHelperInlineOrigOffset = 0x4c;
constexpr size_t kHelperInlineOrig2Offset = 0x50;
constexpr size_t kHelperInlineOrig3Offset = 0x54;
constexpr size_t kHelperInlineOrig4Offset = 0x58;
constexpr size_t kHelperInlineOrig5Offset = 0x5c;
constexpr size_t kHelperInlineBranchOffset = 0x60;
constexpr size_t kHelperInlineLiteralOffset = 0x70;
constexpr size_t kHelperInlineDirectOrigOffset = 0x48;
constexpr size_t kHelperInlineStdioOrigOffset = 0xC8;
constexpr size_t kHelperInlineDirectFormatFrameSize = 0x160;
constexpr size_t kHelperInlineDirectFormatBufferOffset = 0x60;
constexpr size_t kHelperInlineDirectFormatBufferSize = 0x100;
constexpr size_t kHelperInlineDirectFormatOrigOffset = 0x6C;
constexpr size_t kHelperInlineDirectFormatBodySize = kHelperInlineDirectFormatOrigOffset + 40;
constexpr size_t kHelperInlineEntrySize = 0x80;
constexpr size_t kHelperInlineBufferSize = 0x2000;
constexpr size_t kHelperInlineBufferMask = kHelperInlineBufferSize - 1;
constexpr size_t kHelperInlineHeaderSize = 0x10;

struct HelperInlineEntry {
	uint64_t regs[16];
};

static_assert(sizeof(HelperInlineEntry) == kHelperInlineEntrySize, "Helper inline entry size mismatch");

static void fillNops(std::vector<uint8_t> &buffer) {
	static const uint8_t nop[4] = {0x1F, 0x20, 0x03, 0xD5};
	for (size_t i = 0; i + 3 < buffer.size(); i += 4) {
		memcpy(buffer.data() + i, nop, sizeof(nop));
	}
}

static bool buildHelperInlineStub(uint32_t originalInstr0,
                                  uint32_t originalInstr1,
                                  uint32_t originalInstr2,
                                  uint32_t originalInstr3,
                                  uint32_t originalInstr4,
                                  uint64_t stubAddr,
                                  uint64_t returnAddr,
                                  uint64_t literalValue,
                                  bool enableLogging,
                                  std::vector<uint8_t> &outStub) {
	const uint8_t templateBytes[kHelperInlineDefaultStubSize] = {
		0xFF, 0x83, 0x00, 0xD1, 0xEF, 0x43, 0x00, 0xA9,
		0xF1, 0x0B, 0x00, 0xF9, 0x30, 0x03, 0x00, 0x58,
		0x11, 0x02, 0x40, 0xF9, 0x0F, 0x42, 0x00, 0x91,
		0xEF, 0x01, 0x11, 0x8B, 0xE0, 0x05, 0x00, 0xA9,
		0xE2, 0x0D, 0x01, 0xA9, 0xE4, 0x15, 0x02, 0xA9,
		0xE6, 0x1D, 0x03, 0xA9, 0xE8, 0x21, 0x00, 0xF9,
		0xBF, 0x3A, 0x03, 0xD5, 0x31, 0x02, 0x02, 0x91,
		0x31, 0x32, 0x40, 0x92, 0x11, 0x02, 0x00, 0xF9,
		0xEF, 0x43, 0x40, 0xA9, 0xF1, 0x0B, 0x40, 0xF9,
		0xFF, 0x83, 0x00, 0x91, 0xAA, 0xAA, 0xAA, 0xAA,
		0xBB, 0xBB, 0xBB, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC,
		0xDD, 0xDD, 0xDD, 0xDD, 0xEE, 0xEE, 0xEE, 0xEE,
		0x00, 0x00, 0x00, 0x14, 0x1F, 0x20, 0x03, 0xD5,
		0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};
	if (enableLogging) {
		outStub.assign(templateBytes, templateBytes + kHelperInlineDefaultStubSize);
	} else {
		outStub.assign(kHelperInlineDefaultStubSize, 0);
		fillNops(outStub);
	}

	memcpy(outStub.data() + kHelperInlineOrigOffset, &originalInstr0, sizeof(originalInstr0));
	memcpy(outStub.data() + kHelperInlineOrig2Offset, &originalInstr1, sizeof(originalInstr1));
	memcpy(outStub.data() + kHelperInlineOrig3Offset, &originalInstr2, sizeof(originalInstr2));
	memcpy(outStub.data() + kHelperInlineOrig4Offset, &originalInstr3, sizeof(originalInstr3));
	memcpy(outStub.data() + kHelperInlineOrig5Offset, &originalInstr4, sizeof(originalInstr4));
	auto branch = encodeBranch(stubAddr + kHelperInlineBranchOffset, returnAddr);
	if (!branch) {
		return false;
	}
	memcpy(outStub.data() + kHelperInlineBranchOffset, &(*branch), sizeof(*branch));
	memcpy(outStub.data() + kHelperInlineLiteralOffset, &literalValue, sizeof(literalValue));
	return true;
}

static bool buildHelperInlineMinimalStub(uint32_t originalInstr0,
                                         uint32_t originalInstr1,
                                         uint32_t originalInstr2,
                                         uint32_t originalInstr3,
                                         uint32_t originalInstr4,
                                         uint64_t returnAddr,
                                         std::vector<uint8_t> &outStub) {
	outStub.assign(kHelperInlineDefaultStubSize, 0);
	fillNops(outStub);
	memcpy(outStub.data(), &originalInstr0, sizeof(originalInstr0));
	memcpy(outStub.data() + 4, &originalInstr1, sizeof(originalInstr1));
	memcpy(outStub.data() + 8, &originalInstr2, sizeof(originalInstr2));
	memcpy(outStub.data() + 12, &originalInstr3, sizeof(originalInstr3));
	memcpy(outStub.data() + 16, &originalInstr4, sizeof(originalInstr4));
	uint32_t branchInstrs[5] = {};
	encodeAbsoluteBranch(returnAddr, 17, branchInstrs);
	memcpy(outStub.data() + 20, branchInstrs, sizeof(branchInstrs));
	return true;
}

static bool buildHelperInlineDirectWriteStub(uint32_t originalInstr0,
                                             uint32_t originalInstr1,
                                             uint32_t originalInstr2,
                                             uint32_t originalInstr3,
                                             uint32_t originalInstr4,
                                             uint64_t returnAddr,
                                             std::vector<uint8_t> &outStub) {
	std::vector<uint32_t> instrs;
	instrs.reserve(32);

	// Stack frame 0x50 bytes, save x0-x2, x16-x17, write x0-x3 to stderr.
	instrs.push_back(encodeSubImm(31, 31, 0x50));        // sub sp, sp, #0x50
	instrs.push_back(encodeStpImm(0, 1, 31, 0x00));       // stp x0, x1, [sp,#0]
	instrs.push_back(encodeStrImm(2, 31, 0x10));          // str x2, [sp,#0x10]
	instrs.push_back(encodeStpImm(16, 17, 31, 0x18));     // stp x16, x17, [sp,#0x18]

	instrs.push_back(encodeStrImm(0, 31, 0x28));          // str x0, [sp,#0x28]
	instrs.push_back(encodeStrImm(1, 31, 0x30));          // str x1, [sp,#0x30]
	instrs.push_back(encodeStrImm(2, 31, 0x38));          // str x2, [sp,#0x38]
	instrs.push_back(encodeStrImm(3, 31, 0x40));          // str x3, [sp,#0x40]

	instrs.push_back(encodeMovz(0, 2, 0));                // mov x0, #2 (stderr)
	instrs.push_back(encodeAddImm(1, 31, 0x28));          // add x1, sp, #0x28
	instrs.push_back(encodeMovz(2, 0x20, 0));             // mov x2, #0x20 (32 bytes)

	const uint64_t sysWrite = 0x4ull;
	instrs.push_back(encodeMovz(16, static_cast<uint16_t>(sysWrite & 0xffffu), 0));
	const uint16_t sysWriteHi = static_cast<uint16_t>((sysWrite >> 16) & 0xffffu);
	instrs.push_back(encodeMovk(16, sysWriteHi, 16));
	instrs.push_back(encodeSvc(0x80));                   // svc #0x80

	instrs.push_back(encodeLdpImm(16, 17, 31, 0x18));     // ldp x16, x17, [sp,#0x18]
	instrs.push_back(encodeLdpImm(0, 1, 31, 0x00));       // ldp x0, x1, [sp,#0]
	instrs.push_back(encodeLdrImm(2, 31, 0x10));          // ldr x2, [sp,#0x10]
	instrs.push_back(encodeAddImm(31, 31, 0x50));         // add sp, sp, #0x50

	const size_t prologueBytes = instrs.size() * sizeof(uint32_t);
	if (prologueBytes != kHelperInlineDirectOrigOffset) {
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

	outStub.assign(kHelperInlineDefaultStubSize, 0);
	fillNops(outStub);
	const size_t byteCount = instrs.size() * sizeof(uint32_t);
	if (byteCount > kHelperInlineDefaultStubSize) {
		return false;
	}
	memcpy(outStub.data(), instrs.data(), byteCount);
	return true;
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
	instrs.push_back(encodeLdrImm(1, 31, 0x48));                                   // x1 = saved x16 (svc)
	instrs.push_back(encodeLdrImm(2, 31, 0x00));                                   // x2 = saved x0
	instrs.push_back(encodeLdrImm(3, 31, 0x08));                                   // x3 = saved x1
	instrs.push_back(encodeLdrImm(4, 31, 0x10));                                   // x4 = saved x2
	instrs.push_back(encodeLdrImm(5, 31, 0x18));                                   // x5 = saved x3

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

static bool buildHelperInlineCallStub(uint32_t originalInstr0,
                                      uint32_t originalInstr1,
                                      uint32_t originalInstr2,
                                      uint32_t originalInstr3,
                                      uint32_t originalInstr4,
                                      uint64_t hookAddr,
                                      uint64_t returnAddr,
                                      std::vector<uint8_t> &outStub) {
	std::vector<uint32_t> instrs;
	instrs.reserve(40);

	// Stack frame 0x60 bytes, save x0-x8, x16-x17, call hook, restore, then run original prologue.
	instrs.push_back(encodeSubImm(31, 31, 0x60));         // sub sp, sp, #0x60
	instrs.push_back(encodeStpImm(0, 1, 31, 0x00));        // stp x0, x1, [sp,#0]
	instrs.push_back(encodeStpImm(2, 3, 31, 0x10));        // stp x2, x3, [sp,#0x10]
	instrs.push_back(encodeStpImm(4, 5, 31, 0x20));        // stp x4, x5, [sp,#0x20]
	instrs.push_back(encodeStpImm(6, 7, 31, 0x30));        // stp x6, x7, [sp,#0x30]
	instrs.push_back(encodeStpImm(16, 17, 31, 0x40));      // stp x16, x17, [sp,#0x40]
	instrs.push_back(encodeStrImm(8, 31, 0x50));           // str x8, [sp,#0x50]

	instrs.push_back(encodeMovz(16, static_cast<uint16_t>(hookAddr & 0xffffu), 0));
	instrs.push_back(encodeMovk(16, static_cast<uint16_t>((hookAddr >> 16) & 0xffffu), 16));
	instrs.push_back(encodeMovk(16, static_cast<uint16_t>((hookAddr >> 32) & 0xffffu), 32));
	instrs.push_back(encodeMovk(16, static_cast<uint16_t>((hookAddr >> 48) & 0xffffu), 48));
	instrs.push_back(encodeBlr(16));                       // blr x16

	instrs.push_back(encodeLdrImm(8, 31, 0x50));           // ldr x8, [sp,#0x50]
	instrs.push_back(encodeLdpImm(16, 17, 31, 0x40));      // ldp x16, x17, [sp,#0x40]
	instrs.push_back(encodeLdpImm(6, 7, 31, 0x30));        // ldp x6, x7, [sp,#0x30]
	instrs.push_back(encodeLdpImm(4, 5, 31, 0x20));        // ldp x4, x5, [sp,#0x20]
	instrs.push_back(encodeLdpImm(2, 3, 31, 0x10));        // ldp x2, x3, [sp,#0x10]
	instrs.push_back(encodeLdpImm(0, 1, 31, 0x00));        // ldp x0, x1, [sp,#0]
	instrs.push_back(encodeAddImm(31, 31, 0x60));          // add sp, sp, #0x60

	const size_t prologueBytes = instrs.size() * sizeof(uint32_t);
	if (prologueBytes != kHelperInlineOrigOffset) {
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

	outStub.assign(kHelperInlineDefaultStubSize, 0);
	fillNops(outStub);
	const size_t byteCount = instrs.size() * sizeof(uint32_t);
	if (byteCount > kHelperInlineDefaultStubSize) {
		return false;
	}
	memcpy(outStub.data(), instrs.data(), byteCount);
	return true;
}

static bool buildHelperInlineStdioStub(uint32_t originalInstr0,
                                       uint32_t originalInstr1,
                                       uint32_t originalInstr2,
                                       uint32_t originalInstr3,
                                       uint32_t originalInstr4,
                                       uint64_t stubAddr,
                                       uint64_t returnAddr,
                                       uint64_t dprintfAddr,
                                       uint64_t guardAddr,
                                       std::vector<uint8_t> &outStub) {
	const std::string fmt = "[helper_syscall] svc=0x%08x rcx=0x%llx rdx=0x%llx rbx=0x%llx rsp=0x%llx rbp=0x%llx\\n";
	const size_t fmtLen = fmt.size() + 1;
	if (fmtLen >= kHelperInlineStdioStubSize) {
		return false;
	}
	size_t fmtOffset = (kHelperInlineStdioStubSize - fmtLen) & ~static_cast<size_t>(0x7);
	if (fmtOffset < 0x80) {
		return false;
	}
	const uint64_t fmtAddr = stubAddr + fmtOffset;

	std::vector<uint32_t> instrs;
	instrs.reserve(96);

	// Stack frame 0xA0 bytes, save x0-x18 (including x9-x15/x18), call dprintf, restore.
	instrs.push_back(encodeSubImm(31, 31, 0xA0));         // sub sp, sp, #0xA0
	instrs.push_back(encodeStpImm(0, 1, 31, 0x00));        // stp x0, x1, [sp,#0]
	instrs.push_back(encodeStpImm(2, 3, 31, 0x10));        // stp x2, x3, [sp,#0x10]
	instrs.push_back(encodeStpImm(4, 5, 31, 0x20));        // stp x4, x5, [sp,#0x20]
	instrs.push_back(encodeStpImm(6, 7, 31, 0x30));        // stp x6, x7, [sp,#0x30]
	instrs.push_back(encodeStrImm(8, 31, 0x40));           // str x8, [sp,#0x40]
	instrs.push_back(encodeStpImm(9, 10, 31, 0x48));       // stp x9, x10, [sp,#0x48]
	instrs.push_back(encodeStpImm(11, 12, 31, 0x58));      // stp x11, x12, [sp,#0x58]
	instrs.push_back(encodeStpImm(13, 14, 31, 0x68));      // stp x13, x14, [sp,#0x68]
	instrs.push_back(encodeStrImm(15, 31, 0x78));          // str x15, [sp,#0x78]
	instrs.push_back(encodeStpImm(16, 17, 31, 0x80));      // stp x16, x17, [sp,#0x80]
	instrs.push_back(encodeStrImm(18, 31, 0x90));          // str x18, [sp,#0x90]

	// Guard check.
	instrs.push_back(encodeMovz(9, static_cast<uint16_t>(guardAddr & 0xffffu), 0));
	instrs.push_back(encodeMovk(9, static_cast<uint16_t>((guardAddr >> 16) & 0xffffu), 16));
	instrs.push_back(encodeMovk(9, static_cast<uint16_t>((guardAddr >> 32) & 0xffffu), 32));
	instrs.push_back(encodeMovk(9, static_cast<uint16_t>((guardAddr >> 48) & 0xffffu), 48));
	instrs.push_back(encodeLdrImm(10, 9, 0x00));           // ldr x10, [x9]
	const size_t guardBranchIndex = instrs.size();
	instrs.push_back(0);                                   // cbnz x10, skip
	instrs.push_back(encodeMovz(10, 1, 0));                // mov x10, #1
	instrs.push_back(encodeStrImm(10, 9, 0x00));           // str x10, [x9]

	// Prepare dprintf arguments.
	instrs.push_back(encodeMovz(0, 2, 0));                 // mov x0, #2 (stderr)
	instrs.push_back(encodeMovz(1, static_cast<uint16_t>(fmtAddr & 0xffffu), 0));
	instrs.push_back(encodeMovk(1, static_cast<uint16_t>((fmtAddr >> 16) & 0xffffu), 16));
	instrs.push_back(encodeMovk(1, static_cast<uint16_t>((fmtAddr >> 32) & 0xffffu), 32));
	instrs.push_back(encodeMovk(1, static_cast<uint16_t>((fmtAddr >> 48) & 0xffffu), 48));
	instrs.push_back(encodeLdrImm(2, 31, 0x00));           // x2 = saved x0
	instrs.push_back(encodeLdrImm(3, 31, 0x08));           // x3 = saved x1
	instrs.push_back(encodeLdrImm(4, 31, 0x10));           // x4 = saved x2
	instrs.push_back(encodeLdrImm(5, 31, 0x18));           // x5 = saved x3
	instrs.push_back(encodeLdrImm(6, 31, 0x20));           // x6 = saved x4
	instrs.push_back(encodeLdrImm(7, 31, 0x28));           // x7 = saved x5

	instrs.push_back(encodeMovz(16, static_cast<uint16_t>(dprintfAddr & 0xffffu), 0));
	instrs.push_back(encodeMovk(16, static_cast<uint16_t>((dprintfAddr >> 16) & 0xffffu), 16));
	instrs.push_back(encodeMovk(16, static_cast<uint16_t>((dprintfAddr >> 32) & 0xffffu), 32));
	instrs.push_back(encodeMovk(16, static_cast<uint16_t>((dprintfAddr >> 48) & 0xffffu), 48));
	instrs.push_back(encodeBlr(16));                       // blr x16

	instrs.push_back(encodeMovz(10, 0, 0));                // mov x10, #0
	instrs.push_back(encodeStrImm(10, 9, 0x00));           // str x10, [x9]
	const size_t skipIndex = instrs.size();

	// Restore regs.
	instrs.push_back(encodeLdrImm(18, 31, 0x90));          // ldr x18, [sp,#0x90]
	instrs.push_back(encodeLdpImm(16, 17, 31, 0x80));      // ldp x16, x17, [sp,#0x80]
	instrs.push_back(encodeLdrImm(15, 31, 0x78));          // ldr x15, [sp,#0x78]
	instrs.push_back(encodeLdpImm(13, 14, 31, 0x68));      // ldp x13, x14, [sp,#0x68]
	instrs.push_back(encodeLdpImm(11, 12, 31, 0x58));      // ldp x11, x12, [sp,#0x58]
	instrs.push_back(encodeLdpImm(9, 10, 31, 0x48));       // ldp x9, x10, [sp,#0x48]
	instrs.push_back(encodeLdrImm(8, 31, 0x40));           // ldr x8, [sp,#0x40]
	instrs.push_back(encodeLdpImm(6, 7, 31, 0x30));        // ldp x6, x7, [sp,#0x30]
	instrs.push_back(encodeLdpImm(4, 5, 31, 0x20));        // ldp x4, x5, [sp,#0x20]
	instrs.push_back(encodeLdpImm(2, 3, 31, 0x10));        // ldp x2, x3, [sp,#0x10]
	instrs.push_back(encodeLdpImm(0, 1, 31, 0x00));        // ldp x0, x1, [sp,#0]
	instrs.push_back(encodeAddImm(31, 31, 0xA0));          // add sp, sp, #0xA0

	const uint64_t cbAddr = stubAddr + guardBranchIndex * 4;
	const uint64_t skipAddr = stubAddr + skipIndex * 4;
	const auto cbnz = encodeCbzImm(10, static_cast<int64_t>(skipAddr) - static_cast<int64_t>(cbAddr), true);
	if (!cbnz) {
		return false;
	}
	instrs[guardBranchIndex] = *cbnz;

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

	outStub.assign(kHelperInlineStdioStubSize, 0);
	fillNops(outStub);
	const size_t byteCount = instrs.size() * sizeof(uint32_t);
	if (byteCount > fmtOffset) {
		return false;
	}
	memcpy(outStub.data(), instrs.data(), byteCount);
	memcpy(outStub.data() + fmtOffset, fmt.c_str(), fmtLen);
	return true;
}

#define LOG(fmt, ...)                   \
    do {                                \
        if (logsEnabled) {              \
            printf(fmt, ##__VA_ARGS__); \
        }                               \
    } while (0)

class MuhDebugger {
public:
	enum class WaitOutcome {
		Stopped,
		Exited,
		Signaled,
		Error
	};

private:
	static const uint32_t AARCH64_BREAKPOINT; // just declare here

	pid_t childPid_ = -1;
	task_t taskPort_ = MACH_PORT_NULL;
	std::map<uint64_t, uint32_t> breakpoints_; // addr -> original instruction
private:
	std::map<uint64_t, uint32_t> tempBreakpoints_; // addr -> original instruction
	std::map<uint64_t, uint64_t> tempOrigins_; // temp addr -> breakpoint addr
	WaitOutcome lastWaitOutcome_ = WaitOutcome::Error;
	int lastWaitStatus_ = 0;
	int lastStopSignal_ = 0;

	bool waitForStopped() {
		int status;
		if (waitpid(childPid_, &status, 0) == -1) {
			perror("waitpid");
			lastWaitOutcome_ = WaitOutcome::Error;
			return false;
		}
		lastWaitStatus_ = status;
		if (WIFSTOPPED(status)) {
			int signal = WSTOPSIG(status);
			LOG("Process stopped signal=%d\n", signal);
			lastWaitOutcome_ = WaitOutcome::Stopped;
			lastStopSignal_ = signal;
			return true;
		}
		if (WIFEXITED(status)) {
			lastWaitOutcome_ = WaitOutcome::Exited;
			return false;
		}
		if (WIFSIGNALED(status)) {
			lastWaitOutcome_ = WaitOutcome::Signaled;
			return false;
		}
		lastWaitOutcome_ = WaitOutcome::Error;
		lastStopSignal_ = 0;
		return false;
	}

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

	bool continueExecution(int signal = 0) {
		if (ptrace(PT_CONTINUE, childPid_, (caddr_t)1, signal) < 0) {
			perror("ptrace(PT_CONTINUE)");
			return false;
		}

		LOG("continueExecution...\n");

		return waitForStopped();
	}

	bool singleStep() {
		if (ptrace(PT_STEP, childPid_, (caddr_t)1, 0) < 0) {
			perror("ptrace(PT_STEP)");
			return false;
		}

		LOG("singleStep...\n");

		return waitForStopped();
	}

	bool detach() {
		if (ptrace(PT_DETACH, childPid_, (caddr_t)1, 0) < 0) {
			perror("ptrace(PT_DETACH)");
			return false;
		}
		LOG("Debugger detached.\n");
		return true;
	}

	WaitOutcome lastWaitOutcome() const {
		return lastWaitOutcome_;
	}

	int lastWaitStatus() const {
		return lastWaitStatus_;
	}

	int lastStopSignal() const {
		return lastStopSignal_;
	}

	task_t taskPort() const {
		return taskPort_;
	}

	bool setBreakpoint(uint64_t address) {
		// Verify address is in valid range
		if (address >= MACH_VM_MAX_ADDRESS) {
			fprintf(stderr, "Invalid address 0x%llx\n", address);
			return false;
		}

		// Read the original instruction
		uint32_t original;
		if (!readMemory(address, &original, sizeof(uint32_t))) {
			fprintf(stderr, "Failed to read memory at 0x%llx\n", address);
			return false;
		}

		// First, try to adjust memory protection
		if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, sizeof(uint32_t))) {
			return false;
		}

		// Write breakpoint instruction
		if (!writeMemory(address, &AARCH64_BREAKPOINT, sizeof(uint32_t))) {
			fprintf(stderr, "Failed to write breakpoint at 0x%llx\n", address);
			return false;
		}

		if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(uint32_t))) {
			return false;
		}

		breakpoints_[address] = original;
		LOG("Breakpoint set at address 0x%llx\n", address);
		return true;
	}

	bool setTempBreakpoint(uint64_t address, uint64_t originAddress) {
		if (tempBreakpoints_.find(address) != tempBreakpoints_.end()) {
			return true;
		}

		uint32_t original;
		if (!readMemory(address, &original, sizeof(uint32_t))) {
			fprintf(stderr, "Failed to read memory at 0x%llx\n", address);
			return false;
		}

		if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, sizeof(uint32_t))) {
			return false;
		}

		if (!writeMemory(address, &AARCH64_BREAKPOINT, sizeof(uint32_t))) {
			fprintf(stderr, "Failed to write temp breakpoint at 0x%llx\n", address);
			return false;
		}

		if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(uint32_t))) {
			return false;
		}

		tempBreakpoints_[address] = original;
		tempOrigins_[address] = originAddress;
		LOG("Temp breakpoint set at address 0x%llx (origin 0x%llx)\n", address, originAddress);
		return true;
	}

	bool removeBreakpoint(uint64_t address) {
		auto it = breakpoints_.find(address);
		if (it == breakpoints_.end()) {
			fprintf(stderr, "No breakpoint found at address 0x%llx\n", address);
			return false;
		}

		// First, try to adjust memory protection
		if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_WRITE, sizeof(uint32_t))) {
			return false;
		}

		// Restore original instruction
		if (!writeMemory(address, &it->second, sizeof(uint32_t))) {
			fprintf(stderr, "Failed to restore original instruction at 0x%llx\n", address);
			return false;
		}

		if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(uint32_t))) {
			return false;
		}
		breakpoints_.erase(it);
		LOG("Breakpoint removed from address 0x%llx\n", address);
		return true;
	}

	bool removeTempBreakpoint(uint64_t address) {
		auto it = tempBreakpoints_.find(address);
		if (it == tempBreakpoints_.end()) {
			fprintf(stderr, "No temp breakpoint found at address 0x%llx\n", address);
			return false;
		}

		if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_WRITE, sizeof(uint32_t))) {
			return false;
		}

		if (!writeMemory(address, &it->second, sizeof(uint32_t))) {
			fprintf(stderr, "Failed to restore temp original instruction at 0x%llx\n", address);
			return false;
		}

		if (!adjustMemoryProtection(address, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(uint32_t))) {
			return false;
		}

		tempBreakpoints_.erase(it);
		tempOrigins_.erase(address);
		LOG("Temp breakpoint removed from address 0x%llx\n", address);
		return true;
	}

	bool isTempBreakpoint(uint64_t address) const {
		return tempBreakpoints_.find(address) != tempBreakpoints_.end();
	}

	uint64_t tempOrigin(uint64_t address) const {
		auto it = tempOrigins_.find(address);
		if (it == tempOrigins_.end()) {
			return 0;
		}
		return it->second;
	}

	bool hasBreakpoint(uint64_t address) const {
		return breakpoints_.find(address) != breakpoints_.end() || tempBreakpoints_.find(address) != tempBreakpoints_.end();
	}

	enum Register {
		X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15,
		X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28,
		FP, LR, SP, PC, CPSR
	};

	bool getThreadState(thread_t thread, arm_thread_state64_t &state) {
		mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
		kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get thread state (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool setThreadState(thread_t thread, const arm_thread_state64_t &state) {
		kern_return_t kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to set thread state (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	uint64_t readRegister(thread_t thread, Register reg) {
		arm_thread_state64_t state;
		if (!getThreadState(thread, state)) {
			return 0;
		}

		if (reg >= X0 && reg <= X28) {
			return state.__x[reg];
		}

		switch (reg) {
		case FP:
			return state.__fp;
		case LR:
			return state.__lr;
		case SP:
			return state.__sp;
		case PC:
			return state.__pc;
		case CPSR:
			return state.__cpsr;
		default:
			fprintf(stderr, "Invalid register\n");
			return 0;
		}
	}

	bool setRegister(thread_t thread, Register reg, uint64_t value) {
		arm_thread_state64_t state;
		if (!getThreadState(thread, state)) {
			return false;
		}

		if (reg >= X0 && reg <= X28) {
			state.__x[reg] = value;
		} else {
			switch (reg) {
			case FP:
				state.__fp = value;
				break;
			case LR:
				state.__lr = value;
				break;
			case SP:
				state.__sp = value;
				break;
			case PC:
				state.__pc = value;
				break;
			case CPSR:
				state.__cpsr = value;
				break;
			default:
				fprintf(stderr, "Invalid register\n");
				return false;
			}
		}

		return setThreadState(thread, state);
	}

	bool findThreadWithPc(const std::vector<uint64_t> &addresses, thread_t &threadOut, uint64_t &matchedAddrOut) {
		thread_act_port_array_t threadList;
		mach_msg_type_number_t threadCount;

		kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get threads (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}

		for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
			arm_thread_state64_t state;
			if (!getThreadState(threadList[i], state)) {
				mach_port_deallocate(mach_task_self(), threadList[i]);
				continue;
			}
			const uint64_t pc = state.__pc;
			for (const auto addr : addresses) {
				if (pc == addr) {
					threadOut = threadList[i];
					matchedAddrOut = addr;
					for (mach_msg_type_number_t j = 0; j < threadCount; j++) {
						if (j != i) {
							mach_port_deallocate(mach_task_self(), threadList[j]);
						}
					}
					vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);
					return true;
				}
			}
			mach_port_deallocate(mach_task_self(), threadList[i]);
		}

		vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);
		return false;
	}

	bool findThreadAtAnyBreakpoint(thread_t &threadOut, uint64_t &matchedAddrOut) {
		if (breakpoints_.empty() && tempBreakpoints_.empty()) {
			return false;
		}
		std::vector<uint64_t> addresses;
		addresses.reserve(breakpoints_.size() + tempBreakpoints_.size());
		for (const auto &entry : breakpoints_) {
			addresses.push_back(entry.first);
		}
		for (const auto &entry : tempBreakpoints_) {
			addresses.push_back(entry.first);
		}
		return findThreadWithPc(addresses, threadOut, matchedAddrOut);
	}

	bool findThreadAtBrk(thread_t &threadOut, uint64_t &pcOut, uint32_t &instrOut) {
		thread_act_port_array_t threadList;
		mach_msg_type_number_t threadCount;

		kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get threads (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}

		for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
			arm_thread_state64_t state;
			if (!getThreadState(threadList[i], state)) {
				mach_port_deallocate(mach_task_self(), threadList[i]);
				continue;
			}

			const uint64_t pc = state.__pc;
			uint32_t instr = 0;
			if (readMemory(pc, &instr, sizeof(instr)) && (instr & 0xFFE0001F) == AARCH64_BREAKPOINT) {
				threadOut = threadList[i];
				pcOut = pc;
				instrOut = instr;
				for (mach_msg_type_number_t j = 0; j < threadCount; j++) {
					if (j != i) {
						mach_port_deallocate(mach_task_self(), threadList[j]);
					}
				}
				vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);
				return true;
			}

			mach_port_deallocate(mach_task_self(), threadList[i]);
		}

		vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);
		return false;
	}

	bool suspendOtherThreads(thread_t keepThread, std::vector<thread_t> &suspended) {
		thread_act_port_array_t threadList;
		mach_msg_type_number_t threadCount;

		kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get threads for suspension (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}

		for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
			if (threadList[i] == keepThread) {
				mach_port_deallocate(mach_task_self(), threadList[i]);
				continue;
			}
			kr = thread_suspend(threadList[i]);
			if (kr == KERN_SUCCESS) {
				suspended.push_back(threadList[i]);
			} else {
				mach_port_deallocate(mach_task_self(), threadList[i]);
			}
		}

		vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);
		return true;
	}

	void resumeThreads(std::vector<thread_t> &suspended) {
		for (auto thread : suspended) {
			(void)thread_resume(thread);
			mach_port_deallocate(mach_task_self(), thread);
		}
		suspended.clear();
	}

	void logStopSignal(int signal, size_t maxThreads = 6) {
		thread_act_port_array_t threadList;
		mach_msg_type_number_t threadCount;

		kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
		if (kr != KERN_SUCCESS) {
			LOG("Failed to get threads for signal logging (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return;
		}

		const size_t limit = std::min(static_cast<size_t>(threadCount), maxThreads);
		for (size_t i = 0; i < limit; i++) {
			arm_thread_state64_t state;
			if (!getThreadState(threadList[i], state)) {
				continue;
			}
			uint32_t instr = 0;
			(void)readMemory(state.__pc, &instr, sizeof(instr));
			LOG("Signal %d thread[%zu] pc=0x%llx sp=0x%llx lr=0x%llx instr=0x%08x\n",
			    signal, i,
			    static_cast<unsigned long long>(state.__pc),
			    static_cast<unsigned long long>(state.__sp),
			    static_cast<unsigned long long>(state.__lr),
			    instr);
			mach_vm_address_t region = state.__pc;
			mach_vm_size_t regionSize = 0;
			vm_region_basic_info_data_64_t info{};
			mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
			mach_port_t objectName = MACH_PORT_NULL;
			if (mach_vm_region(taskPort_, &region, &regionSize, VM_REGION_BASIC_INFO_64,
			                   (vm_region_info_t)&info, &infoCount, &objectName) == KERN_SUCCESS) {
				LOG("  region 0x%llx-0x%llx prot=0x%x max=0x%x share=%d\n",
				    static_cast<unsigned long long>(region),
				    static_cast<unsigned long long>(region + regionSize),
				    info.protection, info.max_protection, info.shared);
				if (objectName != MACH_PORT_NULL) {
					mach_port_deallocate(mach_task_self(), objectName);
				}
			}
		}

		for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
			mach_port_deallocate(mach_task_self(), threadList[i]);
		}
		vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);
	}

	bool adjustMemoryProtection(uint64_t address, vm_prot_t protection, mach_vm_size_t size) {
		// 4KB page size in rosetta process
		vm_size_t pageSize = 0x1000;
		// align to page boundary
		mach_vm_address_t region = address & ~(pageSize - 1);
		size = ((address + size + pageSize - 1) & ~(pageSize - 1)) - region;

		LOG("Adjusting memory protection at 0x%llx - 0x%llx\n", (uint64_t)region, (uint64_t)(region + size));

		kern_return_t kr = mach_vm_protect(taskPort_, region, size, false, protection);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to adjust memory protection at 0x%llx - 0x%llx (error 0x%x: %s)\n", (uint64_t)region, (uint64_t)(region + size), kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool readMemory(uint64_t address, void *buffer, size_t size) {
		mach_vm_size_t readSize;

		kern_return_t kr = mach_vm_read_overwrite(taskPort_, address, size, (mach_vm_address_t)buffer, &readSize);

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

	bool writeMemory(uint64_t address, const void *buffer, size_t size) {
		kern_return_t kr = mach_vm_write(taskPort_, address, (vm_offset_t)buffer, size);

		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to write memory at 0x%llx (error 0x%x: %s)\n", address, kr, mach_error_string(kr));
			return false;
		}

		return true;
	}

	bool allocateMemory(uint64_t &address, size_t size, vm_prot_t protection) {
		mach_vm_address_t allocAddr = 0;
		kern_return_t kr = mach_vm_allocate(taskPort_, &allocAddr, size, VM_FLAGS_ANYWHERE);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to allocate memory in target (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}
		if (!adjustMemoryProtection(allocAddr, protection, size)) {
			return false;
		}
		address = allocAddr;
		return true;
	}

	bool copyThreadState(arm_thread_state64_t &state) {
		thread_act_port_array_t threadList;
		mach_msg_type_number_t threadCount;

		kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get threads (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}

		mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
		kr = thread_get_state(threadList[0], ARM_THREAD_STATE64, (thread_state_t)&state, &count);

		// Cleanup
		for (uint i = 0; i < threadCount; i++) {
			mach_port_deallocate(mach_task_self(), threadList[i]);
		}
		vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);

		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get thread state (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}

		return true;
	}

	bool restoreThreadState(const arm_thread_state64_t &state) {
		thread_act_port_array_t threadList;
		mach_msg_type_number_t threadCount;

		kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to get threads (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}

		kr = thread_set_state(threadList[0], ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);

		// Cleanup
		for (uint i = 0; i < threadCount; i++) {
			mach_port_deallocate(mach_task_self(), threadList[i]);
		}
		vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);

		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to set thread state (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}

		return true;
	}

	bool getFirstThread(thread_t &threadOut) {
		thread_act_port_array_t threadList;
		mach_msg_type_number_t threadCount;
		kern_return_t kr = task_threads(taskPort_, &threadList, &threadCount);
		if (kr != KERN_SUCCESS || threadCount == 0) {
			fprintf(stderr, "Failed to get threads (error 0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}
		threadOut = threadList[0];
		for (mach_msg_type_number_t i = 1; i < threadCount; i++) {
			mach_port_deallocate(mach_task_self(), threadList[i]);
		}
		vm_deallocate(mach_task_self(), (vm_address_t)threadList, sizeof(thread_t) * threadCount);
		return true;
	}

	bool callFunction(thread_t thread,
	                  uint64_t funcAddr,
	                  const uint64_t *args,
	                  size_t argCount,
	                  uint64_t &result,
	                  bool suspendOthers) {
		if (argCount > 8) {
			return false;
		}
		arm_thread_state64_t saved{};
		if (!getThreadState(thread, saved)) {
			return false;
		}
		std::vector<thread_t> suspended;
		if (suspendOthers) {
			(void)suspendOtherThreads(thread, suspended);
		}

		const uint64_t returnAddr = saved.__pc;
		if (!setTempBreakpoint(returnAddr, 0)) {
			if (suspendOthers) {
				resumeThreads(suspended);
			}
			return false;
		}

		arm_thread_state64_t state = saved;
		for (size_t i = 0; i < argCount; i++) {
			state.__x[i] = args ? args[i] : 0;
		}
		state.__pc = funcAddr;
		state.__lr = returnAddr;
		if (!setThreadState(thread, state)) {
			removeTempBreakpoint(returnAddr);
			if (suspendOthers) {
				resumeThreads(suspended);
			}
			return false;
		}

		int pendingSignal = 0;
		bool hitReturn = false;
		for (int attempts = 0; attempts < 128; ++attempts) {
			if (!continueExecution(pendingSignal)) {
				break;
			}
			pendingSignal = 0;
			if (lastStopSignal() != SIGTRAP) {
				pendingSignal = lastStopSignal();
				continue;
			}
			thread_t hitThread = MACH_PORT_NULL;
			uint64_t hitAddr = 0;
			if (!findThreadAtAnyBreakpoint(hitThread, hitAddr)) {
				pendingSignal = SIGTRAP;
				continue;
			}
			if (hitAddr == returnAddr && isTempBreakpoint(hitAddr)) {
				if (hitThread != MACH_PORT_NULL) {
					mach_port_deallocate(mach_task_self(), hitThread);
				}
				hitReturn = true;
				break;
			}
			if (hitThread != MACH_PORT_NULL) {
				mach_port_deallocate(mach_task_self(), hitThread);
			}
		}

		if (hitReturn) {
			result = readRegister(thread, Register::X0);
		}
		removeTempBreakpoint(returnAddr);
		(void)setThreadState(thread, saved);
		if (suspendOthers) {
			resumeThreads(suspended);
		}
		return hitReturn;
	}

	auto findRuntime() -> uintptr_t {
		// Prefer the actual runtime image if dyld reports it.
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
		_dyld_process_info_for_each_image(processInfo, ^(uint64_t address, const uuid_t uuid, const char *path) { moduleList.push_back(address); });
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

};

// Define the static constant outside the class
const unsigned int MuhDebugger::AARCH64_BREAKPOINT = 0xD4200000;

static std::string pathBasename(const std::string &path) {
	const size_t pos = path.find_last_of('/');
	if (pos == std::string::npos) {
		return path;
	}
	return path.substr(pos + 1);
}

static std::optional<uint64_t> findRemoteImageBase(task_t taskPort, const std::string &path) {
	if (path.empty()) {
		return std::nullopt;
	}
	const std::string base = pathBasename(path);
	kern_return_t kr = KERN_SUCCESS;
	auto processInfo = _dyld_process_info_create(taskPort, 0, &kr);
	if (kr != KERN_SUCCESS || !processInfo) {
		return std::nullopt;
	}
	__block std::optional<uint64_t> found;
	_dyld_process_info_for_each_image(processInfo, ^(uint64_t address, const uuid_t, const char *imgPath) {
		if (found || !imgPath) {
			return;
		}
		if (path == imgPath) {
			found = address;
			return;
		}
		if (!base.empty()) {
			const std::string imgBase = pathBasename(imgPath);
			if (imgBase == base) {
				found = address;
			}
		}
	});
	_dyld_process_info_release(processInfo);
	return found;
}

static bool resolveRemoteSymbol(task_t taskPort, void *localFunc, uint64_t &remoteAddr) {
	if (!localFunc) {
		return false;
	}
	Dl_info info{};
	if (dladdr(localFunc, &info) == 0 || !info.dli_fbase || !info.dli_fname) {
		return false;
	}
	const std::string imagePath = info.dli_fname;
	const auto remoteBase = findRemoteImageBase(taskPort, imagePath);
	if (!remoteBase) {
		return false;
	}
	const uint64_t localAddr = reinterpret_cast<uint64_t>(localFunc);
	const uint64_t localBase = reinterpret_cast<uint64_t>(info.dli_fbase);
	remoteAddr = *remoteBase + (localAddr - localBase);
	return true;
}

static bool writeRemoteString(MuhDebugger &dbg, const std::string &value, uint64_t &remoteAddr) {
	const size_t size = value.size() + 1;
	if (!dbg.allocateMemory(remoteAddr, size, VM_PROT_READ | VM_PROT_WRITE)) {
		return false;
	}
	return dbg.writeMemory(remoteAddr, value.c_str(), size);
}

static bool injectHelperDylib(MuhDebugger &dbg,
                              const char *dylibPath,
                              const char *symbolName,
                              uint64_t &hookAddr) {
	if (!dylibPath || !*dylibPath) {
		return false;
	}
	const char *symbol = (symbolName && *symbolName) ? symbolName : "rosetta_helper_syscall_hook";
	uint64_t remoteDlopen = 0;
	uint64_t remoteDlsym = 0;
	if (!resolveRemoteSymbol(dbg.taskPort(), reinterpret_cast<void *>(&dlopen), remoteDlopen) ||
	    !resolveRemoteSymbol(dbg.taskPort(), reinterpret_cast<void *>(&dlsym), remoteDlsym)) {
		fprintf(stderr, "Failed to resolve remote dlopen/dlsym.\n");
		return false;
	}

	uint64_t remotePath = 0;
	uint64_t remoteSymbol = 0;
	if (!writeRemoteString(dbg, dylibPath, remotePath) ||
	    !writeRemoteString(dbg, symbol, remoteSymbol)) {
		fprintf(stderr, "Failed to allocate remote strings for dylib injection.\n");
		return false;
	}

	thread_t thread = MACH_PORT_NULL;
	if (!dbg.getFirstThread(thread)) {
		fprintf(stderr, "Failed to acquire target thread for dylib injection.\n");
		return false;
	}

	uint64_t handle = 0;
	const uint64_t dlopenArgs[2] = {remotePath, static_cast<uint64_t>(RTLD_NOW | RTLD_GLOBAL)};
	if (!dbg.callFunction(thread, remoteDlopen, dlopenArgs, 2, handle, false) || handle == 0) {
		fprintf(stderr, "Remote dlopen failed.\n");
		mach_port_deallocate(mach_task_self(), thread);
		return false;
	}

	uint64_t funcAddr = 0;
	const uint64_t dlsymArgs[2] = {handle, remoteSymbol};
	if (!dbg.callFunction(thread, remoteDlsym, dlsymArgs, 2, funcAddr, false) || funcAddr == 0) {
		fprintf(stderr, "Remote dlsym failed.\n");
		mach_port_deallocate(mach_task_self(), thread);
		return false;
	}

	mach_port_deallocate(mach_task_self(), thread);
	hookAddr = funcAddr;
	return true;
}

static bool loadRemoteImageCache(MuhDebugger &dbg, const RemoteImageInfo &image, RemoteImageCache &cache) {
	if (cache.valid) {
		return true;
	}
	mach_header_64 header{};
	if (!dbg.readMemory(image.base, &header, sizeof(header))) {
		return false;
	}
	if (header.magic != MH_MAGIC_64) {
		return false;
	}
	const uint64_t cmdSize = static_cast<uint64_t>(header.sizeofcmds);
	std::vector<unsigned char> buffer(sizeof(header) + cmdSize);
	memcpy(buffer.data(), &header, sizeof(header));
	if (cmdSize > 0) {
		if (!dbg.readMemory(image.base + sizeof(header), buffer.data() + sizeof(header), cmdSize)) {
			return false;
		}
	}
	std::vector<MachSectionInfo> dummySections;
	if (!parseMachO(buffer, cache.segments, dummySections)) {
		return false;
	}
	if (!parseDyldInfo(buffer, cache.dyldInfo)) {
		cache.dyldInfo.valid = false;
	}
	const auto textVm = findTextVmaddr(cache.segments);
	if (!textVm) {
		return false;
	}
	cache.textVmaddr = *textVm;

	if (cache.dyldInfo.valid && cache.dyldInfo.export_size != 0) {
		std::optional<uint64_t> exportVm = fileOffsetToVmAddr(cache.segments, cache.dyldInfo.export_off);
		if (!exportVm) {
			for (const auto &seg : cache.segments) {
				if (seg.name == "__LINKEDIT" && cache.dyldInfo.export_off >= seg.fileoff) {
					const uint64_t delta = cache.dyldInfo.export_off - seg.fileoff;
					if (delta < seg.vmsize) {
						exportVm = seg.vmaddr + delta;
						break;
					}
				}
			}
		}
		if (!exportVm) {
			return false;
		}
		const uint64_t exportAddr = image.base + (*exportVm - cache.textVmaddr);
		cache.exportTrie.resize(cache.dyldInfo.export_size);
		if (!dbg.readMemory(exportAddr, cache.exportTrie.data(), cache.exportTrie.size())) {
			return false;
		}
	}

	cache.valid = true;
	return true;
}

static bool resolveSymbolInImage(MuhDebugger &dbg,
                                 const RemoteImageInfo &image,
                                 const std::string &symbol,
                                 std::unordered_map<uint64_t, RemoteImageCache> &remoteCache,
                                 std::unordered_map<std::string, ImageFileCache> &fileCache,
                                 uint64_t &addr) {
	auto &remote = remoteCache[image.base];
	if (loadRemoteImageCache(dbg, image, remote) && !remote.exportTrie.empty()) {
		uint64_t symAddr = 0;
		uint64_t flags = 0;
		if (trieFindSymbol(remote.exportTrie.data(), remote.exportTrie.size(), 0, symbol.c_str(), symAddr, flags)) {
			addr = image.base + (symAddr - remote.textVmaddr);
			return true;
		}
	}
	if (!image.path.empty()) {
		auto &file = fileCache[image.path];
		if (loadImageFileCache(image.path, file)) {
			uint64_t symAddr = 0;
			uint64_t textVm = 0;
			if (findExportedSymbolInBuffer(file.buffer, symbol, symAddr, textVm)) {
				addr = image.base + (symAddr - textVm);
				return true;
			}
		}
	}
	return false;
}

static bool resolveSymbolGlobal(MuhDebugger &dbg,
                                const std::string &symbol,
                                const std::vector<RemoteImageInfo> &images,
                                std::unordered_map<uint64_t, RemoteImageCache> &remoteCache,
                                std::unordered_map<std::string, ImageFileCache> &fileCache,
                                std::unordered_map<std::string, uint64_t> &symbolCache,
                                uint64_t &addr) {
	auto it = symbolCache.find(symbol);
	if (it != symbolCache.end()) {
		addr = it->second;
		return addr != 0;
	}
	for (const auto &image : images) {
		uint64_t resolved = 0;
		if (resolveSymbolInImage(dbg, image, symbol, remoteCache, fileCache, resolved)) {
			symbolCache[symbol] = resolved;
			addr = resolved;
			return true;
		}
	}
	if (logsEnabled && symbol == "___stderrp") {
		static bool dumped = false;
		if (!dumped) {
			dumped = true;
			LOG("[macho] Failed to resolve %s; images=%zu\n", symbol.c_str(), images.size());
			size_t count = 0;
			for (const auto &image : images) {
				auto &remote = remoteCache[image.base];
				const bool remoteOk = loadRemoteImageCache(dbg, image, remote);
				LOG("[macho] img=0x%llx path=%s export=%u remote=%d\n",
				    static_cast<unsigned long long>(image.base),
				    image.path.c_str(),
				    remote.dyldInfo.export_size,
				    remoteOk ? 1 : 0);
				if (++count >= 32) {
					break;
				}
			}
		}
	}
	symbolCache[symbol] = 0;
	return false;
}

static bool getSharedCacheRange(MuhDebugger &dbg, uint64_t &start, uint64_t &size) {
	start = 0;
	size = 0;
	std::vector<RemoteImageInfo> images;
	if (!collectRemoteImages(dbg.taskPort(), images)) {
		return false;
	}
	std::unordered_map<uint64_t, RemoteImageCache> remoteCache;
	std::unordered_map<std::string, ImageFileCache> fileCache;
	std::unordered_map<std::string, uint64_t> symbolCache;
	uint64_t funcAddr = 0;
	if (!resolveSymbolGlobal(dbg, "_dyld_get_shared_cache_range", images, remoteCache, fileCache, symbolCache, funcAddr)) {
		return false;
	}

	uint64_t remoteStart = 0;
	uint64_t remoteLen = 0;
	if (!dbg.allocateMemory(remoteStart, sizeof(uint64_t), VM_PROT_READ | VM_PROT_WRITE) ||
	    !dbg.allocateMemory(remoteLen, sizeof(uint64_t), VM_PROT_READ | VM_PROT_WRITE)) {
		return false;
	}
	uint64_t zero = 0;
	(void)dbg.writeMemory(remoteStart, &zero, sizeof(zero));
	(void)dbg.writeMemory(remoteLen, &zero, sizeof(zero));

	thread_t thread = MACH_PORT_NULL;
	if (!dbg.getFirstThread(thread)) {
		return false;
	}
	const uint64_t args[2] = {remoteStart, remoteLen};
	uint64_t result = 0;
	const bool ok = dbg.callFunction(thread, funcAddr, args, 2, result, true);
	mach_port_deallocate(mach_task_self(), thread);
	if (!ok) {
		return false;
	}
	if (!dbg.readMemory(remoteStart, &start, sizeof(start)) ||
	    !dbg.readMemory(remoteLen, &size, sizeof(size))) {
		return false;
	}
	return start != 0 && size != 0;
}

static bool applySegmentProtections(MuhDebugger &dbg, const LoadedImage &image) {
	for (const auto &seg : image.segments) {
		if (seg.vmsize == 0) {
			continue;
		}
		const uint64_t addr = image.slide + seg.vmaddr;
		if (!dbg.adjustMemoryProtection(addr, seg.initprot, seg.vmsize)) {
			return false;
		}
	}
	return true;
}

static bool mapMachOIntoTarget(MuhDebugger &dbg,
                               const std::vector<unsigned char> &buffer,
                               LoadedImage &image) {
	if (!parseMachO(buffer, image.segments, image.sections)) {
		return false;
	}
	uint64_t minVm = UINT64_MAX;
	uint64_t maxVm = 0;
	for (const auto &seg : image.segments) {
		if (seg.vmsize == 0) {
			continue;
		}
		minVm = std::min(minVm, seg.vmaddr);
		maxVm = std::max(maxVm, seg.vmaddr + seg.vmsize);
	}
	if (minVm == UINT64_MAX || maxVm <= minVm) {
		return false;
	}
	image.minVmaddr = minVm;
	image.maxVmaddr = maxVm;
	const uint64_t size = alignUp(maxVm - minVm, 0x1000);
	uint64_t remoteBase = 0;
	if (!dbg.allocateMemory(remoteBase, size, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) {
		return false;
	}
	image.remoteBase = remoteBase;
	image.slide = remoteBase - minVm;
	const auto textVm = findTextVmaddr(image.segments);
	image.textVmaddr = textVm.value_or(minVm);

	for (const auto &seg : image.segments) {
		if (seg.vmsize == 0) {
			continue;
		}
		const uint64_t dest = remoteBase + (seg.vmaddr - minVm);
		if (seg.filesize > 0) {
			if (seg.fileoff + seg.filesize > buffer.size()) {
				return false;
			}
			if (!dbg.writeMemory(dest, buffer.data() + seg.fileoff, static_cast<size_t>(seg.filesize))) {
				return false;
			}
		}
		if (seg.vmsize > seg.filesize) {
			const uint64_t zeroStart = dest + seg.filesize;
			const uint64_t zeroSize = seg.vmsize - seg.filesize;
			std::vector<uint8_t> zeros(0x400, 0);
			uint64_t remaining = zeroSize;
			uint64_t cursor = zeroStart;
			while (remaining > 0) {
				const size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, zeros.size()));
				if (!dbg.writeMemory(cursor, zeros.data(), chunk)) {
					return false;
				}
				cursor += chunk;
				remaining -= chunk;
			}
		}
		if (seg.initprot & VM_PROT_EXECUTE) {
			(void)dbg.flushInstructionCache(dest, static_cast<size_t>(seg.vmsize));
		}
	}

	parseDyldInfo(buffer, image.dyldInfo);
	return true;
}

static bool applyRebase(MuhDebugger &dbg,
                        const LoadedImage &image,
                        const std::vector<unsigned char> &buffer) {
	if (!image.dyldInfo.valid || image.dyldInfo.rebase_size == 0) {
		return true;
	}
	const uint64_t rebaseOff = image.dyldInfo.rebase_off;
	const uint64_t rebaseEnd = rebaseOff + image.dyldInfo.rebase_size;
	if (rebaseEnd > buffer.size()) {
		return false;
	}
	const uint8_t *p = buffer.data() + rebaseOff;
	const uint8_t *end = buffer.data() + rebaseEnd;
	uint8_t type = REBASE_TYPE_POINTER;
	uint8_t segIndex = 0;
	uint64_t segOffset = 0;
	const uint64_t pointerSize = 8;
	auto doRebase = [&](uint8_t currentSeg, uint64_t currentOffset) -> bool {
		if (currentSeg >= image.segments.size()) {
			return false;
		}
		if (type != REBASE_TYPE_POINTER) {
			return false;
		}
		const uint64_t addr = image.slide + image.segments[currentSeg].vmaddr + currentOffset;
		uint64_t value = 0;
		if (!dbg.readMemory(addr, &value, sizeof(value))) {
			return false;
		}
		value += image.slide;
		return dbg.writeMemory(addr, &value, sizeof(value));
	};
	while (p < end) {
		const uint8_t opcode = *p & REBASE_OPCODE_MASK;
		const uint8_t imm = *p & REBASE_IMMEDIATE_MASK;
		p++;
		switch (opcode) {
		case REBASE_OPCODE_DONE:
			return true;
		case REBASE_OPCODE_SET_TYPE_IMM:
			type = imm;
			break;
		case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
			segIndex = imm;
			uint64_t offset = 0;
			size_t used = 0;
			if (!readUleb128(p, end, offset, used)) {
				return false;
			}
			p += used;
			segOffset = offset;
			break;
		}
		case REBASE_OPCODE_ADD_ADDR_ULEB: {
			uint64_t add = 0;
			size_t used = 0;
			if (!readUleb128(p, end, add, used)) {
				return false;
			}
			p += used;
			segOffset += add;
			break;
		}
		case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
			segOffset += static_cast<uint64_t>(imm) * pointerSize;
			break;
		case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
			for (uint8_t i = 0; i < imm; ++i) {
				if (!doRebase(segIndex, segOffset)) {
					return false;
				}
				segOffset += pointerSize;
			}
			break;
		case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
			uint64_t count = 0;
			size_t used = 0;
			if (!readUleb128(p, end, count, used)) {
				return false;
			}
			p += used;
			for (uint64_t i = 0; i < count; ++i) {
				if (!doRebase(segIndex, segOffset)) {
					return false;
				}
				segOffset += pointerSize;
			}
			break;
		}
		case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
			if (!doRebase(segIndex, segOffset)) {
				return false;
			}
			uint64_t add = 0;
			size_t used = 0;
			if (!readUleb128(p, end, add, used)) {
				return false;
			}
			p += used;
			segOffset += add + pointerSize;
			break;
		}
		case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
			uint64_t count = 0;
			size_t used = 0;
			if (!readUleb128(p, end, count, used)) {
				return false;
			}
			p += used;
			uint64_t skip = 0;
			if (!readUleb128(p, end, skip, used)) {
				return false;
			}
			p += used;
			for (uint64_t i = 0; i < count; ++i) {
				if (!doRebase(segIndex, segOffset)) {
					return false;
				}
				segOffset += skip + pointerSize;
			}
			break;
		}
		default:
			return false;
		}
	}
	return true;
}

static bool applyBindOpcodes(MuhDebugger &dbg,
                             const LoadedImage &image,
                             const std::vector<unsigned char> &buffer,
                             uint32_t bindOff,
                             uint32_t bindSize,
                             const std::vector<RemoteImageInfo> &images,
                             std::unordered_map<uint64_t, RemoteImageCache> &remoteCache,
                             std::unordered_map<std::string, ImageFileCache> &fileCache,
                             std::unordered_map<std::string, uint64_t> &symbolCache) {
	if (bindSize == 0) {
		return true;
	}
	const uint64_t bindEnd = static_cast<uint64_t>(bindOff) + bindSize;
	if (bindEnd > buffer.size()) {
		return false;
	}
	const uint8_t *p = buffer.data() + bindOff;
	const uint8_t *end = buffer.data() + bindEnd;
	uint8_t type = BIND_TYPE_POINTER;
	uint8_t segIndex = 0;
	uint64_t segOffset = 0;
	int64_t addend = 0;
	std::string symbol;
	uint8_t symbolFlags = 0;
	const uint64_t pointerSize = 8;
	auto doBind = [&](uint8_t currentSeg, uint64_t currentOffset) -> bool {
		if (currentSeg >= image.segments.size()) {
			return false;
		}
		if (type != BIND_TYPE_POINTER) {
			return false;
		}
		const uint64_t addr = image.slide + image.segments[currentSeg].vmaddr + currentOffset;
		uint64_t resolved = 0;
		if (!resolveSymbolGlobal(dbg, symbol, images, remoteCache, fileCache, symbolCache, resolved)) {
			if (symbolFlags & BIND_SYMBOL_FLAGS_WEAK_IMPORT) {
				resolved = 0;
			} else {
				fprintf(stderr, "Failed to resolve bind symbol %s\n", symbol.c_str());
				return false;
			}
		}
		const uint64_t value = resolved + static_cast<uint64_t>(addend);
		return dbg.writeMemory(addr, &value, sizeof(value));
	};
	while (p < end) {
		const uint8_t opcode = *p & BIND_OPCODE_MASK;
		const uint8_t imm = *p & BIND_IMMEDIATE_MASK;
		p++;
		switch (opcode) {
		case BIND_OPCODE_DONE:
			return true;
		case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
			break;
		case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
			uint64_t skip = 0;
			size_t used = 0;
			if (!readUleb128(p, end, skip, used)) {
				return false;
			}
			p += used;
			break;
		}
		case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
			break;
		case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
			symbolFlags = imm;
			const char *name = reinterpret_cast<const char *>(p);
			const size_t maxLen = static_cast<size_t>(end - p);
			const size_t len = strnlen(name, maxLen);
			if (p + len >= end) {
				return false;
			}
			symbol.assign(name, len);
			p += len + 1;
			break;
		}
		case BIND_OPCODE_SET_TYPE_IMM:
			type = imm;
			break;
		case BIND_OPCODE_SET_ADDEND_SLEB: {
			int64_t value = 0;
			size_t used = 0;
			if (!readSleb128(p, end, value, used)) {
				return false;
			}
			p += used;
			addend = value;
			break;
		}
		case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
			segIndex = imm;
			uint64_t offset = 0;
			size_t used = 0;
			if (!readUleb128(p, end, offset, used)) {
				return false;
			}
			p += used;
			segOffset = offset;
			break;
		}
		case BIND_OPCODE_ADD_ADDR_ULEB: {
			uint64_t add = 0;
			size_t used = 0;
			if (!readUleb128(p, end, add, used)) {
				return false;
			}
			p += used;
			segOffset += add;
			break;
		}
		case BIND_OPCODE_DO_BIND:
			if (!doBind(segIndex, segOffset)) {
				return false;
			}
			segOffset += pointerSize;
			break;
		case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
			if (!doBind(segIndex, segOffset)) {
				return false;
			}
			uint64_t add = 0;
			size_t used = 0;
			if (!readUleb128(p, end, add, used)) {
				return false;
			}
			p += used;
			segOffset += add + pointerSize;
			break;
		}
		case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
			if (!doBind(segIndex, segOffset)) {
				return false;
			}
			segOffset += static_cast<uint64_t>(imm) * pointerSize + pointerSize;
			break;
		case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
			uint64_t count = 0;
			size_t used = 0;
			if (!readUleb128(p, end, count, used)) {
				return false;
			}
			p += used;
			uint64_t skip = 0;
			if (!readUleb128(p, end, skip, used)) {
				return false;
			}
			p += used;
			for (uint64_t i = 0; i < count; ++i) {
				if (!doBind(segIndex, segOffset)) {
					return false;
				}
				segOffset += skip + pointerSize;
			}
			break;
		}
		default:
			return false;
		}
	}
	return true;
}

static bool applyBinds(MuhDebugger &dbg,
                       const LoadedImage &image,
                       const std::vector<unsigned char> &buffer,
                       const std::vector<RemoteImageInfo> &images,
                       std::unordered_map<uint64_t, RemoteImageCache> &remoteCache,
                       std::unordered_map<std::string, ImageFileCache> &fileCache,
                       std::unordered_map<std::string, uint64_t> &symbolCache) {
	if (!applyBindOpcodes(dbg, image, buffer, image.dyldInfo.bind_off, image.dyldInfo.bind_size,
	                      images, remoteCache, fileCache, symbolCache)) {
		return false;
	}
	if (!applyBindOpcodes(dbg, image, buffer, image.dyldInfo.lazy_bind_off, image.dyldInfo.lazy_bind_size,
	                      images, remoteCache, fileCache, symbolCache)) {
		return false;
	}
	if (!applyBindOpcodes(dbg, image, buffer, image.dyldInfo.weak_bind_off, image.dyldInfo.weak_bind_size,
	                      images, remoteCache, fileCache, symbolCache)) {
		return false;
	}
	return true;
}

static bool runModInitFunctions(MuhDebugger &dbg, const LoadedImage &image) {
	for (const auto &sec : image.sections) {
		if (sec.sectname != "__mod_init_func") {
			continue;
		}
		if (sec.size == 0) {
			continue;
		}
		const uint64_t addr = image.slide + sec.addr;
		const size_t count = static_cast<size_t>(sec.size / sizeof(uint64_t));
		if (count == 0) {
			return true;
		}
		std::vector<uint64_t> initPtrs(count, 0);
		if (!dbg.readMemory(addr, initPtrs.data(), count * sizeof(uint64_t))) {
			return false;
		}
		thread_t thread = MACH_PORT_NULL;
		if (!dbg.getFirstThread(thread)) {
			return false;
		}
		for (size_t i = 0; i < count; ++i) {
			if (initPtrs[i] == 0) {
				continue;
			}
			uint64_t result = 0;
			if (!dbg.callFunction(thread, initPtrs[i], nullptr, 0, result, true)) {
				mach_port_deallocate(mach_task_self(), thread);
				return false;
			}
		}
		mach_port_deallocate(mach_task_self(), thread);
		return true;
	}
	return true;
}

static bool injectHelperMachO(MuhDebugger &dbg,
                              const char *machoPath,
                              const char *symbolName,
                              uint64_t &hookAddr,
                              uint64_t &counterAddr) {
	if (!machoPath || !*machoPath) {
		return false;
	}
	std::vector<unsigned char> buffer;
	if (!loadFileBuffer(machoPath, buffer)) {
		fprintf(stderr, "Failed to read payload Mach-O: %s\n", machoPath);
		return false;
	}

	LoadedImage image;
	if (!mapMachOIntoTarget(dbg, buffer, image)) {
		fprintf(stderr, "Failed to map payload Mach-O.\n");
		return false;
	}

	std::vector<RemoteImageInfo> images;
	if (!collectRemoteImages(dbg.taskPort(), images)) {
		fprintf(stderr, "Failed to collect remote images.\n");
		return false;
	}
	std::unordered_map<uint64_t, RemoteImageCache> remoteCache;
	std::unordered_map<std::string, ImageFileCache> fileCache;
	std::unordered_map<std::string, uint64_t> symbolCache;
	if (!applyRebase(dbg, image, buffer)) {
		fprintf(stderr, "Failed to apply payload rebases.\n");
		return false;
	}
	if (!applyBinds(dbg, image, buffer, images, remoteCache, fileCache, symbolCache)) {
		fprintf(stderr, "Failed to apply payload binds.\n");
		return false;
	}

	if (!runModInitFunctions(dbg, image)) {
		fprintf(stderr, "Failed to run payload initializers.\n");
		return false;
	}
	if (!applySegmentProtections(dbg, image)) {
		fprintf(stderr, "Failed to restore payload protections.\n");
		return false;
	}

	auto resolveExportSymbol = [&](const char *name, uint64_t &symAddrOut, uint64_t &textVmOut) -> bool {
		if (!name || !*name) {
			return false;
		}
		if (findExportedSymbolInBuffer(buffer, name, symAddrOut, textVmOut)) {
			return true;
		}
		if (name[0] == '_') {
			return false;
		}
		std::string underscored;
		underscored.reserve(strlen(name) + 1);
		underscored.push_back('_');
		underscored.append(name);
		return findExportedSymbolInBuffer(buffer, underscored, symAddrOut, textVmOut);
	};

	const char *symbol = (symbolName && *symbolName) ? symbolName : "rosetta_helper_syscall_hook";
	uint64_t symAddr = 0;
	uint64_t textVm = 0;
	if (!resolveExportSymbol(symbol, symAddr, textVm)) {
		fprintf(stderr, "Failed to locate payload symbol %s.\n", symbol);
		return false;
	}
	hookAddr = image.remoteBase + (symAddr - textVm);

	counterAddr = 0;
	uint64_t counterSym = 0;
	uint64_t counterTextVm = 0;
	if (resolveExportSymbol("rosetta_helper_syscall_counter", counterSym, counterTextVm)) {
		counterAddr = image.remoteBase + (counterSym - counterTextVm);
	}
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
	uint64_t bufferAddr = 0;
	uint64_t bufferBase = 0;
};

static bool setupHelperInlineHook(MuhDebugger &dbg,
                                  uint64_t helperSyscallAddr,
                                  uint64_t runtimeBase,
                                  bool enableLogging,
                                  bool directLogging,
                                  bool minimalStub,
                                  uint64_t externalHookAddr,
                                  bool formatStub,
                                  const std::vector<uint8_t> &formatBlob,
                                  uint64_t formatEntryOffset,
                                  bool stdioStub,
                                  uint64_t stdioFuncAddr,
                                  uint64_t stdioGuardAddr,
                                  HelperInlineState &state) {
	mach_vm_address_t regionStart = 0;
	mach_vm_size_t regionSize = 0;
	vm_prot_t regionProt = 0;
	if (!findExecRegionForAddress(dbg, helperSyscallAddr, regionStart, regionSize, regionProt)) {
		fprintf(stderr, "Failed to locate executable region for helper_syscall.\n");
		return false;
	}
	const char *runtimePath = "/usr/libexec/rosetta/runtime";
	const size_t stubSize = formatStub
	    ? (alignUp(kHelperInlineDirectFormatBodySize, 4) + formatBlob.size())
	    : (stdioStub ? kHelperInlineStdioStubSize : kHelperInlineDefaultStubSize);
	if (formatStub && formatBlob.empty()) {
		fprintf(stderr, "Inline formatter blob is empty.\n");
		return false;
	}
	if (formatStub && formatEntryOffset >= formatBlob.size()) {
		fprintf(stderr, "Inline formatter entry offset is out of range.\n");
		return false;
	}
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

	const bool useLogging = enableLogging && !minimalStub && !directLogging && externalHookAddr == 0 && !stdioStub && !formatStub;
	uint64_t bufferAddr = 0;
	if (useLogging) {
		const size_t bufferSize = kHelperInlineHeaderSize + kHelperInlineBufferSize;
		if (!dbg.allocateMemory(bufferAddr, bufferSize, VM_PROT_READ | VM_PROT_WRITE)) {
			fprintf(stderr, "Failed to allocate helper inline log buffer.\n");
			return false;
		}
		std::vector<uint8_t> zeros(bufferSize, 0);
		if (!dbg.writeMemory(bufferAddr, zeros.data(), zeros.size())) {
			fprintf(stderr, "Failed to initialize helper inline log buffer.\n");
			return false;
		}
	}

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
	uint64_t relocateBase = stubAddr + kHelperInlineOrigOffset;
	if (directLogging) {
		relocateBase = stubAddr + kHelperInlineDirectOrigOffset;
	} else if (formatStub) {
		relocateBase = stubAddr + kHelperInlineDirectFormatOrigOffset;
	} else if (stdioStub) {
		relocateBase = stubAddr + kHelperInlineStdioOrigOffset;
	} else if (minimalStub) {
		relocateBase = stubAddr;
	}
	if (!relocateInstruction(originalInstr0, helperSyscallAddr, relocateBase, relocated0) ||
	    !relocateInstruction(originalInstr1, helperSyscallAddr + 4, relocateBase + 4, relocated1) ||
	    !relocateInstruction(originalInstr2, helperSyscallAddr + 8, relocateBase + 8, relocated2) ||
	    !relocateInstruction(originalInstr3, helperSyscallAddr + 12, relocateBase + 12, relocated3) ||
	    !relocateInstruction(originalInstr4, helperSyscallAddr + 16, relocateBase + 16, relocated4)) {
		fprintf(stderr, "Failed to relocate helper_syscall prologue for inline hook.\n");
		return false;
	}

	std::vector<uint8_t> stub;
	if (formatStub) {
		if (!buildHelperInlineDirectFormatStub(relocated0, relocated1, relocated2, relocated3, relocated4,
		                                       stubAddr, helperSyscallAddr + 20, formatBlob, formatEntryOffset, stub)) {
			fprintf(stderr, "Failed to build helper inline formatted stub.\n");
			return false;
		}
	} else if (stdioStub) {
		if (!buildHelperInlineStdioStub(relocated0, relocated1, relocated2, relocated3, relocated4,
		                               stubAddr, helperSyscallAddr + 20, stdioFuncAddr, stdioGuardAddr, stub)) {
			fprintf(stderr, "Failed to build helper inline stdio stub.\n");
			return false;
		}
	} else if (externalHookAddr != 0) {
		if (!buildHelperInlineCallStub(relocated0, relocated1, relocated2, relocated3, relocated4,
		                               externalHookAddr, helperSyscallAddr + 20, stub)) {
			fprintf(stderr, "Failed to build helper inline call stub.\n");
			return false;
		}
	} else if (directLogging) {
		if (!buildHelperInlineDirectWriteStub(relocated0, relocated1, relocated2, relocated3, relocated4,
		                                      helperSyscallAddr + 20, stub)) {
			fprintf(stderr, "Failed to build helper inline direct stub.\n");
			return false;
		}
	} else if (minimalStub) {
		if (!buildHelperInlineMinimalStub(relocated0, relocated1, relocated2, relocated3, relocated4,
		                                  helperSyscallAddr + 20, stub)) {
			fprintf(stderr, "Failed to build helper inline minimal stub.\n");
			return false;
		}
	} else {
		const uint64_t literalValue = useLogging ? bufferAddr : stubAddr;
		if (!buildHelperInlineStub(relocated0, relocated1, relocated2, relocated3, relocated4,
		                           stubAddr, helperSyscallAddr + 20, literalValue, useLogging, stub)) {
			fprintf(stderr, "Failed to build helper inline stub.\n");
			return false;
		}
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
	state.bufferAddr = bufferAddr;
	state.bufferBase = bufferAddr ? (bufferAddr + kHelperInlineHeaderSize) : 0;

	uint32_t patchedInstrs[5] = {};
	if (dbg.readMemory(helperSyscallAddr, patchedInstrs, sizeof(patchedInstrs))) {
		LOG("helper_inline patched instrs=0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
		    patchedInstrs[0], patchedInstrs[1], patchedInstrs[2], patchedInstrs[3], patchedInstrs[4]);
	}
	if (externalHookAddr == 0 && !directLogging && !minimalStub && !formatStub && !stdioStub) {
		uint64_t stubLiteral = 0;
		if (dbg.readMemory(stubAddr + kHelperInlineLiteralOffset, &stubLiteral, sizeof(stubLiteral))) {
			LOG("helper_inline stub literal=0x%llx\n", static_cast<unsigned long long>(stubLiteral));
		}
	}
	return true;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "%s <path to program>\n", argv[0]);
		return 1;
	}

	logsEnabled = getenv("ASTROWINE_LOGS");
	const std::string targetPath = argc > 1 ? argv[1] : "";
	const bool passSigtrapBrk = getenvPrefer("ASTROWINE_PASS_SIGTRAP", "ROSETTA_PASS_SIGTRAP") != nullptr;
	bool redirectSigsysBrk = getenvPrefer("ASTROWINE_SKIP_SIGSYS_REDIRECT", "ROSETTA_SKIP_SIGSYS_REDIRECT") == nullptr;
	const bool skipWinebootHook = getenvPrefer("ASTROWINE_SKIP_WINEBOOT", "ROSETTA_SKIP_WINEBOOT") != nullptr;
	const bool inlineHelperHook = getenv("ASTROWINE_HELPER_INLINE") != nullptr;
	const bool inlineMinimalStub = getenv("ASTROWINE_HELPER_INLINE_MINIMAL") != nullptr;
	const bool inlineDirectLogging = getenv("ASTROWINE_HELPER_INLINE_DIRECT") != nullptr;
	const bool inlineStdioStub = getenv("ASTROWINE_HELPER_INLINE_STDIO") != nullptr;
	const bool inlineFormatStubRequested = getenv("ASTROWINE_HELPER_INLINE_FORMAT") != nullptr;
	const bool inlineCStubRequested = getenv("ASTROWINE_HELPER_INLINE_C") != nullptr;
	const char *inlineFormatPathEnv = getenv("ASTROWINE_HELPER_INLINE_FORMAT_PATH");
	const char *inlineCPathEnv = getenv("ASTROWINE_HELPER_INLINE_C_PATH");
	const char *helperDylibPath = getenv("ASTROWINE_HELPER_DYLIB_PATH");
	const char *helperDylibSymbol = getenv("ASTROWINE_HELPER_DYLIB_SYMBOL");
	const char *helperMachOPath = getenv("ASTROWINE_HELPER_MACHO_PATH");
	const char *helperMachOSymbol = getenv("ASTROWINE_HELPER_MACHO_SYMBOL");
	const bool probeHelperMachO = getenv("ASTROWINE_HELPER_MACHO_PROBE") != nullptr;
	const bool detachAfterHook = getenv("ASTROWINE_DETACH") != nullptr;
	const bool helperHooksEnabled = []() {
		const char *env = getenv("ASTROWINE_HELPER_HOOKS");
		return !(env && strcmp(env, "0") == 0);
	}();
	int inlinePollMs = 50;
	if (const char *pollEnv = getenv("ASTROWINE_HELPER_INLINE_POLL_MS")) {
		char *end = nullptr;
		const long parsed = strtol(pollEnv, &end, 10);
		if (end != pollEnv && parsed > 0 && parsed < 10000) {
			inlinePollMs = static_cast<int>(parsed);
		}
	}
	const char *svcEnv = getenvPrefer("ASTROWINE_SVC_HOOKS", "ROSETTA_SVC_HOOKS");
	const bool svcHooksEnabled = svcEnv ? (strcmp(svcEnv, "0") != 0) : (!inlineHelperHook && helperHooksEnabled);
	const bool svcScanAllExec = getenvPrefer("ASTROWINE_SVC_SCAN_ALL_EXEC", "ROSETTA_SVC_SCAN_ALL_EXEC") != nullptr;
	uint64_t svcFilterValue = 0;
	bool svcFilterEnabled = false;
	if (const char *filterEnv = getenvPrefer("ASTROWINE_SVC_FILTER_VALUE", "ROSETTA_SVC_FILTER_VALUE")) {
		errno = 0;
		char *end = nullptr;
		const unsigned long long value = strtoull(filterEnv, &end, 0);
		if (errno == 0 && end != filterEnv) {
			svcFilterEnabled = true;
			svcFilterValue = static_cast<uint64_t>(value);
		}
	}
	size_t svcScanInterval = 50;
	if (const char *scanEnv = getenvPrefer("ASTROWINE_SVC_SCAN_INTERVAL", "ROSETTA_SVC_SCAN_INTERVAL")) {
		svcScanInterval = strtoull(scanEnv, nullptr, 10);
	}
	if (svcScanInterval == 0) {
		svcScanInterval = 1;
	}
	std::unordered_set<uint64_t> svcBreakpointAddrs;
	std::unordered_map<uint64_t, uint32_t> svcOriginalInstr;
	std::unordered_map<uint64_t, mach_vm_size_t> svcScannedRegions;
	size_t svcScanTick = 0;
	bool isWineboot = false;
	for (int i = 1; i < argc; i++) {
		if (strstr(argv[i], "wineboot.exe") != nullptr) {
			isWineboot = true;
			break;
		}
	}
	if (isWineboot && skipWinebootHook) {
		execv(argv[1], &argv[1]);
		perror("execv");
		return 1;
	}

	LOG("Launching debugger.\n");

	// Fork and execute new instance
	pid_t child = fork();

	// the debugger will be this process debugging its child
	if (child == 0) {
		// the fresh child waiting to be debugged
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

	// Set up offsets dynamically
	OffsetFinder offsetFinder;
	offsetFinder.setDefaultOffsets();
	if (!offsetFinder.determineOffsets()) {
		fprintf(stderr, "Failed to locate helper patterns in Rosetta runtime.\n");
		dbg.detach();
		return 0;
	}
	LOG("Found rosetta runtime helper offsets successfully!\n");
	LOG("offset_helper_syscall=%llx\n", offsetFinder.offsetHelperSyscall_);

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

	uint64_t helperExternalHookAddr = 0;
	uint64_t helperExternalCounterAddr = 0;
	uint64_t stdioFuncAddr = 0;
	uint64_t stdioGuardAddr = 0;
	std::vector<uint8_t> inlineFormatBlob;
	uint64_t inlineFormatEntryOffset = 0;
	bool useFormatStub = false;
	if (inlineHelperHook && (inlineCStubRequested || inlineFormatStubRequested)) {
		std::string blobPath;
		const char *pathEnv = inlineCPathEnv && *inlineCPathEnv ? inlineCPathEnv : inlineFormatPathEnv;
		if (pathEnv && *pathEnv) {
			blobPath = pathEnv;
		} else {
			blobPath = dirName(argv[0]);
			blobPath += "/helper_syscall_inline_c.o";
		}
		if (!readMachOTextSectionWithSymbol(blobPath.c_str(), "_rosetta_helper_syscall_inline",
		                                    inlineFormatBlob, inlineFormatEntryOffset)) {
			fprintf(stderr, "Failed to load inline helper C text from %s\n", blobPath.c_str());
		} else {
			useFormatStub = true;
			LOG("inline_c blob loaded from %s (%zu bytes, entry 0x%llx)\n",
			    blobPath.c_str(), inlineFormatBlob.size(),
			    static_cast<unsigned long long>(inlineFormatEntryOffset));
		}
	}

	bool useStdioStub = inlineHelperHook && inlineStdioStub && !useFormatStub;
	if (useStdioStub) {
		void *localDprintf = dlsym(RTLD_DEFAULT, "dprintf");
		if (localDprintf) {
			stdioFuncAddr = reinterpret_cast<uint64_t>(localDprintf);
			LOG("helper_stdio using local dprintf addr: 0x%llx\n",
			    static_cast<unsigned long long>(stdioFuncAddr));
		} else {
			std::string cachePath;
			if (!findSharedCachePath(cachePath)) {
				fprintf(stderr, "Failed to locate dyld shared cache.\n");
				useStdioStub = false;
			} else {
				uint64_t cacheBase = 0;
				if (!sharedCacheBaseAddress(cachePath.c_str(), cacheBase)) {
					fprintf(stderr, "Failed to parse dyld shared cache base.\n");
					useStdioStub = false;
				} else {
					uint64_t cacheStart = 0;
					uint64_t cacheSize = 0;
					if (!getSharedCacheRange(dbg, cacheStart, cacheSize)) {
						fprintf(stderr, "Failed to query shared cache range.\n");
						useStdioStub = false;
					} else {
						const uint64_t slide = cacheStart - cacheBase;
						if (!resolveSharedCacheSymbol(cachePath.c_str(), "libSystem.B.dylib", "_dprintf", slide, stdioFuncAddr)) {
							fprintf(stderr, "Failed to resolve _dprintf from shared cache.\n");
							useStdioStub = false;
						}
					}
				}
			}
		}
		if (useStdioStub) {
			if (!dbg.allocateMemory(stdioGuardAddr, sizeof(uint64_t), VM_PROT_READ | VM_PROT_WRITE)) {
				fprintf(stderr, "Failed to allocate stdio guard memory.\n");
				useStdioStub = false;
			} else {
				uint64_t zero = 0;
				(void)dbg.writeMemory(stdioGuardAddr, &zero, sizeof(zero));
				LOG("helper_stdio dprintf addr: 0x%llx guard: 0x%llx\n",
				    static_cast<unsigned long long>(stdioFuncAddr),
				    static_cast<unsigned long long>(stdioGuardAddr));
			}
		}
	}

	if (inlineHelperHook && helperMachOPath && !useStdioStub && !useFormatStub) {
		if (!injectHelperMachO(dbg, helperMachOPath, helperMachOSymbol, helperExternalHookAddr, helperExternalCounterAddr)) {
			fprintf(stderr, "Failed to inject helper Mach-O; falling back to inline stub.\n");
		} else {
			LOG("helper_macho hook addr: 0x%llx\n", helperExternalHookAddr);
			if (helperExternalCounterAddr != 0) {
				LOG("helper_macho counter addr: 0x%llx\n", helperExternalCounterAddr);
			}
		}
	} else if (inlineHelperHook && helperDylibPath && !useStdioStub && !useFormatStub) {
		if (!injectHelperDylib(dbg, helperDylibPath, helperDylibSymbol, helperExternalHookAddr)) {
			fprintf(stderr, "Failed to inject helper dylib; falling back to inline stub.\n");
		} else {
			LOG("helper_dylib hook addr: 0x%llx\n", helperExternalHookAddr);
		}
	}

	bool helperInlineActive = false;
	HelperInlineState helperInlineState;
	if (helperExternalHookAddr != 0 && probeHelperMachO) {
		thread_t thread = MACH_PORT_NULL;
		if (dbg.getFirstThread(thread)) {
			const uint64_t args[8] = {0, 0, 0, 0, 0, 0, 0, 0};
			uint64_t result = 0;
			(void)dbg.callFunction(thread, helperExternalHookAddr, args, 8, result, true);
			mach_port_deallocate(mach_task_self(), thread);
		}
		if (helperExternalCounterAddr != 0) {
			uint64_t counterValue = 0;
			if (dbg.readMemory(helperExternalCounterAddr, &counterValue, sizeof(counterValue))) {
				LOG("helper_macho counter probe: %llu\n", static_cast<unsigned long long>(counterValue));
			} else {
				LOG("helper_macho counter probe failed at 0x%llx\n",
				    static_cast<unsigned long long>(helperExternalCounterAddr));
			}
		}
	}
	if (helperHooksEnabled) {
		if (inlineHelperHook) {
			initHookLog();
			const bool useFormatLogging = useFormatStub && helperExternalHookAddr == 0;
			const bool useMinimalStub = inlineMinimalStub && helperExternalHookAddr == 0 && !useStdioStub && !useFormatLogging;
			const bool useDirectLogging = inlineDirectLogging && hookLogsEnabled && helperExternalHookAddr == 0 && !useStdioStub && !useFormatLogging;
			if (!setupHelperInlineHook(dbg, helperSyscallAddr, runtimeBase, hookLogsEnabled, useDirectLogging,
			                           useMinimalStub, helperExternalHookAddr, useFormatLogging, inlineFormatBlob,
			                           inlineFormatEntryOffset,
			                           useStdioStub, stdioFuncAddr, stdioGuardAddr, helperInlineState)) {
				fprintf(stderr, "Inline helper hook failed; falling back to breakpoint hook.\n");
			} else {
				helperInlineActive = true;
			LOG("helper_inline stub at 0x%llx buffer 0x%llx\n",
			    static_cast<unsigned long long>(helperInlineState.stubAddr),
			    static_cast<unsigned long long>(helperInlineState.bufferAddr));
		}
	}

	if (!helperInlineActive) {
		if (!dbg.setBreakpoint(helperSyscallAddr)) {
			fprintf(stderr, "Failed to set helper_syscall breakpoint\n");
			dbg.detach();
			return 1;
		}
	}
}

	if (detachAfterHook) {
		redirectSigsysBrk = false;
	}

	{
		const char *allowEnv = getenv("ASTROWINE_ALLOW_APPLE_INTERNAL");
		const bool allowAppleInternal = !(allowEnv && strcmp(allowEnv, "0") == 0);
		if (allowAppleInternal) {
		const std::vector<uint8_t> allowPattern = {
			0x70, 0x3C, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4, 0x01, 0x00,
			0x80, 0x92, 0x20, 0x20, 0x80, 0x9A, 0xC0, 0x03, 0x5F, 0xD6
		};
		const auto allowOffset = findPatternInFile("/usr/libexec/rosetta/runtime", allowPattern);
		if (allowOffset) {
			const uint64_t allowAddr = runtimeBase + *allowOffset;
			const uint32_t patch[2] = {0x52800000u, 0xD65F03C0u}; // mov w0,#0; ret
			if (!dbg.adjustMemoryProtection(allowAddr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, sizeof(patch))) {
				hookLog("[allow_apple_internal] failed to change protection at 0x%llx\n", allowAddr);
			} else if (!dbg.writeMemory(allowAddr, patch, sizeof(patch))) {
				hookLog("[allow_apple_internal] failed to patch at 0x%llx\n", allowAddr);
			} else if (!dbg.adjustMemoryProtection(allowAddr, VM_PROT_READ | VM_PROT_EXECUTE, sizeof(patch))) {
				hookLog("[allow_apple_internal] failed to restore protection at 0x%llx\n", allowAddr);
			} else {
				hookLog("[allow_apple_internal] patched at 0x%llx\n", allowAddr);
			}
		} else {
			hookLog("[allow_apple_internal] pattern not found in /usr/libexec/rosetta/runtime\n");
		}
		}
	}

	const bool inlineRingLogging = helperInlineActive && helperInlineState.bufferAddr != 0 && hookLogsEnabled && !inlineDirectLogging;
	bool shouldDetach = detachAfterHook;
	if (!shouldDetach) {
		if (helperInlineActive && !svcHooksEnabled && !inlineRingLogging) {
			shouldDetach = true;
		} else if (!helperHooksEnabled && !svcHooksEnabled && !hookLogsEnabled) {
			shouldDetach = true;
		}
	}
	std::atomic<bool> inlineLogRunning{false};
	std::thread inlineLogThread;
	if (inlineRingLogging && helperInlineState.bufferAddr != 0) {
		inlineLogRunning.store(true);
		inlineLogThread = std::thread([&]() {
			uint64_t readIndex = 0;
			while (inlineLogRunning.load()) {
				uint64_t writeIndex = 0;
				if (!dbg.readMemory(helperInlineState.bufferAddr, &writeIndex, sizeof(writeIndex))) {
					std::this_thread::sleep_for(std::chrono::milliseconds(inlinePollMs));
					continue;
				}
				while (readIndex != writeIndex && inlineLogRunning.load()) {
					HelperInlineEntry entry{};
					const uint64_t entryAddr = helperInlineState.bufferBase + readIndex;
					if (!dbg.readMemory(entryAddr, &entry, sizeof(entry))) {
						break;
					}
					hookLog("[helper_syscall_inline] svc=0x%08x rcx=0x%llx rdx=0x%llx rbx=0x%llx rsp=0x%llx rbp=0x%llx rsi=0x%llx rdi=0x%llx r8=0x%llx\n",
					        static_cast<uint32_t>(entry.regs[0] & 0xffffffffu), entry.regs[1], entry.regs[2], entry.regs[3],
					        entry.regs[4], entry.regs[5], entry.regs[6], entry.regs[7], entry.regs[8]);
					readIndex = (readIndex + kHelperInlineEntrySize) & kHelperInlineBufferMask;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(inlinePollMs));
			}
		});
	}

	if (shouldDetach && !svcHooksEnabled && (helperInlineActive || !helperHooksEnabled)) {
		if (!dbg.detach()) {
			fprintf(stderr, "Failed to detach debugger\n");
			return 1;
		}
		if (inlineLogRunning.load()) {
			int status = 0;
			pid_t waited = 0;
			do {
				waited = waitpid(child, &status, 0);
			} while (waited == -1 && errno == EINTR);
			inlineLogRunning.store(false);
			if (inlineLogThread.joinable()) {
				inlineLogThread.join();
			}
			return 0;
		}
		return 0;
	}

	int pendingSignal = 0;
	size_t signalLogCount = 0;
	size_t trapLogCount = 0;
	struct SegmentRange {
		uint64_t start;
		uint64_t end;
	};
	auto collectImageSegments = [&]() -> std::vector<SegmentRange> {
		std::vector<SegmentRange> segments;
		kern_return_t kr = KERN_SUCCESS;
		auto processInfo = _dyld_process_info_create(dbg.taskPort(), 0, &kr);
		if (kr != KERN_SUCCESS) {
			return segments;
		}
		__block std::vector<uint64_t> imageBases;
		_dyld_process_info_for_each_image(processInfo, ^(uint64_t address, const uuid_t, const char *) {
			imageBases.push_back(address);
		});
		_dyld_process_info_release(processInfo);

		for (const auto base : imageBases) {
			mach_header_64 header{};
			if (!dbg.readMemory(base, &header, sizeof(header))) {
				continue;
			}
			if (header.magic != MH_MAGIC_64) {
				continue;
			}
			uint64_t cmdAddr = base + sizeof(header);
			for (uint32_t i = 0; i < header.ncmds; i++) {
				load_command cmd{};
				if (!dbg.readMemory(cmdAddr, &cmd, sizeof(cmd))) {
					break;
				}
				if (cmd.cmd == LC_SEGMENT_64) {
					segment_command_64 seg{};
					if (!dbg.readMemory(cmdAddr, &seg, sizeof(seg))) {
						break;
					}
					const uint64_t segStart = base + seg.vmaddr;
					const uint64_t segEnd = segStart + seg.vmsize;
					if (seg.vmsize != 0) {
						segments.push_back({segStart, segEnd});
					}
				}
				if (cmd.cmdsize == 0) {
					break;
				}
				cmdAddr += cmd.cmdsize;
			}
		}
		std::sort(segments.begin(), segments.end(), [](const SegmentRange &a, const SegmentRange &b) {
			return a.start < b.start;
		});
		return segments;
	};
	auto regionIntersectsImage = [&](uint64_t start, uint64_t end, const std::vector<SegmentRange> &segments) -> bool {
		for (const auto &seg : segments) {
			if (end <= seg.start) {
				break;
			}
			if (start < seg.end && end > seg.start) {
				return true;
			}
		}
		return false;
	};
	auto scanSvcBreakpoints = [&]() {
		if (!svcHooksEnabled) {
			return;
		}
		task_t task = dbg.taskPort();
		if (task == MACH_PORT_NULL) {
			return;
		}
		mach_vm_address_t address = 0;
		mach_vm_size_t size = 0;
		vm_region_basic_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
		mach_port_t objectName = MACH_PORT_NULL;
		size_t added = 0;
		const size_t chunkSize = 0x4000;
		std::vector<SegmentRange> imageSegments;
		if (svcScanAllExec) {
			imageSegments = collectImageSegments();
		}
		while (true) {
			count = VM_REGION_BASIC_INFO_COUNT_64;
			if (mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO_64,
			                   (vm_region_info_t)&info, &count, &objectName) != KERN_SUCCESS) {
				break;
			}

			const bool isExecutable = (info.protection & VM_PROT_EXECUTE) != 0;
			const bool isWritable = (info.protection & VM_PROT_WRITE) != 0;
			if (!isExecutable) {
				address += size;
				continue;
			}
			if (!svcScanAllExec && !isWritable) {
				address += size;
				continue;
			}
			const uint64_t regionEnd = static_cast<uint64_t>(address + size);
			if (svcScanAllExec && regionIntersectsImage(static_cast<uint64_t>(address), regionEnd, imageSegments)) {
				address += size;
				continue;
			}
			if (!isWritable) {
				auto it = svcScannedRegions.find(address);
				if (it != svcScannedRegions.end() && it->second == size) {
					address += size;
					continue;
				}
				svcScannedRegions[address] = size;
			}

			for (mach_vm_address_t offset = 0; offset < size; offset += chunkSize) {
				const size_t readSize = static_cast<size_t>(std::min<mach_vm_size_t>(chunkSize, size - offset));
				std::vector<uint8_t> buffer(readSize);
				if (!dbg.readMemory(address + offset, buffer.data(), readSize)) {
					continue;
				}
				for (size_t i = 0; i + 4 <= readSize; i += 4) {
					const uint32_t instr = static_cast<uint32_t>(buffer[i]) |
					                       (static_cast<uint32_t>(buffer[i + 1]) << 8) |
					                       (static_cast<uint32_t>(buffer[i + 2]) << 16) |
					                       (static_cast<uint32_t>(buffer[i + 3]) << 24);
					if ((instr & 0xFFE0001F) != 0xD4000001) {
						continue;
					}
					const uint64_t instrAddr = static_cast<uint64_t>(address + offset + i);
					if (svcBreakpointAddrs.find(instrAddr) != svcBreakpointAddrs.end()) {
						continue;
					}
					if (!dbg.setBreakpoint(instrAddr)) {
						continue;
					}
					svcBreakpointAddrs.insert(instrAddr);
					svcOriginalInstr[instrAddr] = instr;
					added++;
				}
			}

			address += size;
		}
		if (added > 0) {
			hookLog("[svc_scan] added=%zu total=%zu\n", added, svcBreakpointAddrs.size());
		}
	};
	if (svcHooksEnabled) {
		scanSvcBreakpoints();
	}
	while (true) {
		if (!dbg.continueExecution(pendingSignal)) {
			auto outcome = dbg.lastWaitOutcome();
			if (outcome == MuhDebugger::WaitOutcome::Exited || outcome == MuhDebugger::WaitOutcome::Signaled) {
				break;
			}
			fprintf(stderr, "Failed to continue execution\n");
			break;
		}
		pendingSignal = 0;
		if (svcHooksEnabled) {
			svcScanTick++;
			if (svcScanTick % svcScanInterval == 0) {
				scanSvcBreakpoints();
			}
		}

		const int stopSignal = dbg.lastStopSignal();
		if (stopSignal != SIGTRAP) {
			if (logsEnabled && signalLogCount < 5) {
				dbg.logStopSignal(stopSignal);
				signalLogCount++;
			}
			if (stopSignal == SIGSYS) {
				if (!redirectSigsysBrk) {
					pendingSignal = stopSignal;
					continue;
				}
				thread_t brkThread = MACH_PORT_NULL;
				uint64_t brkPc = 0;
				uint32_t brkInstr = 0;
				if (dbg.findThreadAtBrk(brkThread, brkPc, brkInstr)) {
					const uint32_t brkImm = (brkInstr >> 5) & 0xFFFF;
					if (brkImm == 0x5) {
						LOG("Redirecting SIGSYS BRK at 0x%llx to helper_syscall\n", brkPc);
						dbg.setRegister(brkThread, MuhDebugger::Register::LR, brkPc + 4);
						dbg.setRegister(brkThread, MuhDebugger::Register::PC, helperSyscallAddr);
						mach_port_deallocate(mach_task_self(), brkThread);
						continue;
					}
				}
			}
			pendingSignal = stopSignal;
			continue;
		}

		thread_t hitThread = MACH_PORT_NULL;
		uint64_t hitAddr = 0;
		if (!dbg.findThreadAtAnyBreakpoint(hitThread, hitAddr)) {
			if (logsEnabled && trapLogCount < 5) {
				dbg.logStopSignal(SIGTRAP);
				trapLogCount++;
			}
			thread_t brkThread = MACH_PORT_NULL;
			uint64_t brkPc = 0;
			uint32_t brkInstr = 0;
			if (dbg.findThreadAtBrk(brkThread, brkPc, brkInstr)) {
				const uint32_t brkImm = (brkInstr >> 5) & 0xFFFF;
				if (passSigtrapBrk) {
					LOG("Passing SIGTRAP BRK #%u at 0x%llx\n", brkImm, brkPc);
					mach_port_deallocate(mach_task_self(), brkThread);
					pendingSignal = SIGTRAP;
					continue;
				}
				LOG("Skipping SIGTRAP BRK #%u at 0x%llx\n", brkImm, brkPc);
				dbg.setRegister(brkThread, MuhDebugger::Register::PC, brkPc + 4);
				mach_port_deallocate(mach_task_self(), brkThread);
				continue;
			}
			LOG("Ignoring SIGTRAP at non-BRK instruction\n");
			continue;
		}

		if (dbg.isTempBreakpoint(hitAddr)) {
			const uint64_t originAddr = dbg.tempOrigin(hitAddr);
			if (!dbg.removeTempBreakpoint(hitAddr)) {
				fprintf(stderr, "Failed to remove temp breakpoint at 0x%llx\n", hitAddr);
				if (hitThread != MACH_PORT_NULL) {
					mach_port_deallocate(mach_task_self(), hitThread);
				}
				return 1;
			}
			if (originAddr != 0 && !dbg.setBreakpoint(originAddr)) {
				fprintf(stderr, "Failed to restore breakpoint at 0x%llx\n", originAddr);
				mach_port_deallocate(mach_task_self(), hitThread);
				return 1;
			}
			mach_port_deallocate(mach_task_self(), hitThread);
			continue;
		}

		const bool isSyscall = (hitAddr == helperSyscallAddr);
		const bool isSvcTrap = svcBreakpointAddrs.find(hitAddr) != svcBreakpointAddrs.end();

		if (isSyscall) {
			const uint64_t x0 = dbg.readRegister(hitThread, MuhDebugger::Register::X0);
			const uint64_t x1 = dbg.readRegister(hitThread, MuhDebugger::Register::X1);
			const uint64_t x2 = dbg.readRegister(hitThread, MuhDebugger::Register::X2);
			const uint64_t x3 = dbg.readRegister(hitThread, MuhDebugger::Register::X3);
			const uint64_t x4 = dbg.readRegister(hitThread, MuhDebugger::Register::X4);
			const uint64_t x5 = dbg.readRegister(hitThread, MuhDebugger::Register::X5);
			const uint64_t x6 = dbg.readRegister(hitThread, MuhDebugger::Register::X6);
			const uint64_t x7 = dbg.readRegister(hitThread, MuhDebugger::Register::X7);
			const uint64_t x8 = dbg.readRegister(hitThread, MuhDebugger::Register::X8);
			hookLog("[helper_syscall] svc=0x%08x rcx=0x%llx rdx=0x%llx rbx=0x%llx rsp=0x%llx rbp=0x%llx rsi=0x%llx rdi=0x%llx r8=0x%llx\n",
			        static_cast<uint32_t>(x0 & 0xffffffffu), x1, x2, x3, x4, x5, x6, x7, x8);
		} else if (isSvcTrap) {
			const auto svcIt = svcOriginalInstr.find(hitAddr);
			const uint32_t svcInstr = (svcIt != svcOriginalInstr.end()) ? svcIt->second : 0;
			const uint32_t svcImm = (svcInstr >> 5) & 0xFFFF;
			const uint64_t x0 = dbg.readRegister(hitThread, MuhDebugger::Register::X0);
			const uint64_t x1 = dbg.readRegister(hitThread, MuhDebugger::Register::X1);
			const uint64_t x2 = dbg.readRegister(hitThread, MuhDebugger::Register::X2);
			const uint64_t x3 = dbg.readRegister(hitThread, MuhDebugger::Register::X3);
			const uint64_t x4 = dbg.readRegister(hitThread, MuhDebugger::Register::X4);
			const uint64_t x5 = dbg.readRegister(hitThread, MuhDebugger::Register::X5);
			const uint64_t x6 = dbg.readRegister(hitThread, MuhDebugger::Register::X6);
			const uint64_t x7 = dbg.readRegister(hitThread, MuhDebugger::Register::X7);
			const uint64_t x8 = dbg.readRegister(hitThread, MuhDebugger::Register::X8);
			const uint64_t x16 = dbg.readRegister(hitThread, MuhDebugger::Register::X16);
			bool filterMatch = true;
			if (svcFilterEnabled) {
				filterMatch = false;
				const uint64_t regs[] = {x0, x1, x2, x3, x4, x5, x6, x7, x8, x16};
				for (const auto reg : regs) {
					if (reg == svcFilterValue) {
						filterMatch = true;
						break;
					}
					if (svcFilterValue <= 0xffffffffu && (reg & 0xffffffffu) == svcFilterValue) {
						filterMatch = true;
						break;
					}
				}
			}
			if (filterMatch) {
				hookLog("[svc_trap] pc=0x%llx svc_imm=0x%04x x16=0x%llx x8=0x%llx x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx x4=0x%llx x5=0x%llx x6=0x%llx x7=0x%llx\n",
				        hitAddr, svcImm, x16, x8, x0, x1, x2, x3, x4, x5, x6, x7);
			}
		}

		if (!dbg.removeBreakpoint(hitAddr)) {
			fprintf(stderr, "Failed to remove breakpoint at 0x%llx\n", hitAddr);
			if (hitThread != MACH_PORT_NULL) {
				mach_port_deallocate(mach_task_self(), hitThread);
			}
			return 1;
		}

		const uint64_t tempAddr = hitAddr + 4;
		if (!dbg.setTempBreakpoint(tempAddr, hitAddr)) {
			fprintf(stderr, "Failed to set temp breakpoint at 0x%llx\n", tempAddr);
			mach_port_deallocate(mach_task_self(), hitThread);
			return 1;
		}

		mach_port_deallocate(mach_task_self(), hitThread);
	}

	if (inlineLogRunning.load()) {
		inlineLogRunning.store(false);
	}
	if (inlineLogThread.joinable()) {
		inlineLogThread.join();
	}

	if (dbg.lastWaitOutcome() == MuhDebugger::WaitOutcome::Stopped) {
		dbg.detach();
	}

	return 0;
}
