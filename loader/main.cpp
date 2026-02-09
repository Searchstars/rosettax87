#include "offset_finder.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <libproc.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr uint32_t kAarch64Brk = 0xD4200000u;
constexpr uint64_t kTargetPageSize = 0x1000;
constexpr int kMaxStopsToHitBp = 256;

constexpr std::string_view kNeedle = "VirtualApple";
constexpr std::string_view kReplacement = "Apple M4    ";
static_assert(kNeedle.size() == kReplacement.size(), "replacement must be same length as needle");

bool gLogsEnabled = false;

#define LOG(fmt, ...)                                 \
	do {                                              \
		if (gLogsEnabled) {                          \
			std::fprintf(stderr, fmt, ##__VA_ARGS__); \
		}                                             \
	} while (0)

enum class WaitResult {
	Stopped,
	Exited,
	Error,
};

struct ExportEntry {
	uint64_t address;
	uint64_t name; // const char*
};

struct Exports {
	uint64_t version;
	uint64_t x87Exports;
	uint64_t x87ExportCount;
	uint64_t runtimeExports;
	uint64_t runtimeExportCount;
};

static_assert(sizeof(Exports) == 0x28, "Unexpected Exports layout");

uint32_t encodeMovz(uint8_t reg, uint16_t imm16, uint8_t shift) {
	const uint32_t hw = static_cast<uint32_t>((shift / 16) & 0x3u);
	return 0xD2800000u | (static_cast<uint32_t>(imm16) << 5) | (hw << 21) | (reg & 0x1fu);
}

uint32_t encodeMovk(uint8_t reg, uint16_t imm16, uint8_t shift) {
	const uint32_t hw = static_cast<uint32_t>((shift / 16) & 0x3u);
	return 0xF2800000u | (static_cast<uint32_t>(imm16) << 5) | (hw << 21) | (reg & 0x1fu);
}

uint32_t encodeB(int64_t immBytes) {
	const int64_t imm26 = immBytes >> 2;
	return 0x14000000u | (static_cast<uint32_t>(imm26) & 0x03ffffffu);
}

uint32_t encodeBCond(uint8_t cond, int64_t immBytes) {
	const int64_t imm19 = immBytes >> 2;
	return 0x54000000u | ((static_cast<uint32_t>(imm19) & 0x7ffffu) << 5) | (cond & 0x0fu);
}

uint32_t encodeSubsImm(uint8_t reg, uint16_t imm12) {
	return 0xF1000000u | ((static_cast<uint32_t>(imm12 & 0x0fffu)) << 10) |
	       ((static_cast<uint32_t>(reg & 0x1fu)) << 5) | (reg & 0x1fu);
}

void emitMovAbs64(std::vector<uint32_t> &out, uint8_t reg, uint64_t value) {
	out.push_back(encodeMovz(reg, static_cast<uint16_t>(value & 0xffffu), 0));
	out.push_back(encodeMovk(reg, static_cast<uint16_t>((value >> 16) & 0xffffu), 16));
	out.push_back(encodeMovk(reg, static_cast<uint16_t>((value >> 32) & 0xffffu), 32));
	out.push_back(encodeMovk(reg, static_cast<uint16_t>((value >> 48) & 0xffffu), 48));
}

class Debugger {
public:
	~Debugger() {
		if (threadPort_ != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), threadPort_);
		if (taskPort_ != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), taskPort_);
	}

	bool attachTracedChild(pid_t pid) {
		pid_ = pid;
		const WaitResult wr = waitForStop();
		if (wr != WaitResult::Stopped) return false;

		kern_return_t kr = task_for_pid(mach_task_self(), pid_, &taskPort_);
		if (kr != KERN_SUCCESS) {
			std::fprintf(stderr, "task_for_pid(%d) failed (0x%x: %s)\n", pid_, kr, mach_error_string(kr));
			return false;
		}

		// Choose an initial thread; we'll re-select the stopped thread after breakpoints.
		thread_act_port_array_t threads = nullptr;
		mach_msg_type_number_t threadCount = 0;
		kr = task_threads(taskPort_, &threads, &threadCount);
		if (kr != KERN_SUCCESS || !threads || threadCount == 0) {
			std::fprintf(stderr, "task_threads failed (0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}
		if (threadPort_ != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), threadPort_);
		threadPort_ = threads[0];
		for (mach_msg_type_number_t i = 1; i < threadCount; ++i) mach_port_deallocate(mach_task_self(), threads[i]);
		vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(threads), sizeof(thread_t) * threadCount);
		return true;
	}

	bool cont(int signalValue = 0) const {
		if (ptrace(PT_CONTINUE, pid_, reinterpret_cast<caddr_t>(1), signalValue) < 0) {
			std::perror("ptrace(PT_CONTINUE)");
			return false;
		}
		return true;
	}

	bool stopAndWait() const {
		if (kill(pid_, SIGSTOP) < 0) {
			std::perror("kill(SIGSTOP)");
			return false;
		}
		return waitForStop() == WaitResult::Stopped;
	}

	bool detach() const {
		if (ptrace(PT_DETACH, pid_, reinterpret_cast<caddr_t>(1), 0) < 0) {
			if (errno == ESRCH) return true;
			std::perror("ptrace(PT_DETACH)");
			return false;
		}
		return true;
	}

	WaitResult waitForStop() const {
		int status = 0;
		const pid_t waited = waitpid(pid_, &status, 0);
		if (waited < 0) {
			std::perror("waitpid");
			return WaitResult::Error;
		}
		if (WIFSTOPPED(status)) return WaitResult::Stopped;
		if (WIFEXITED(status) || WIFSIGNALED(status)) return WaitResult::Exited;
		return WaitResult::Error;
	}

	bool readMemory(uint64_t address, void *buffer, size_t size) const {
		mach_vm_size_t readSize = 0;
		const kern_return_t kr = mach_vm_read_overwrite(taskPort_, address, size,
		                                                reinterpret_cast<mach_vm_address_t>(buffer), &readSize);
		return kr == KERN_SUCCESS && readSize == size;
	}

	bool writeMemory(uint64_t address, const void *buffer, size_t size) const {
		// mach_vm_write takes a vm_offset_t payload pointer; allocate staging in our address space.
		mach_vm_address_t staging = 0;
		const kern_return_t allocKr = mach_vm_allocate(mach_task_self(), &staging, size, VM_FLAGS_ANYWHERE);
		if (allocKr != KERN_SUCCESS) {
			LOG("mach_vm_allocate(staging) failed (0x%x: %s)\n", allocKr, mach_error_string(allocKr));
			return false;
		}
		std::memcpy(reinterpret_cast<void *>(static_cast<uintptr_t>(staging)), buffer, size);

		const kern_return_t kr = mach_vm_write(taskPort_, address,
		                                       static_cast<vm_offset_t>(staging),
		                                       static_cast<mach_msg_type_number_t>(size));
		(void)mach_vm_deallocate(mach_task_self(), staging, size);
		if (kr != KERN_SUCCESS) {
			LOG("mach_vm_write failed at 0x%llx (0x%x: %s)\n",
			    static_cast<unsigned long long>(address), kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool protect(uint64_t address, size_t size, vm_prot_t prot) const {
		const uint64_t pageStart = address & ~(kTargetPageSize - 1);
		const uint64_t pageEnd = (address + size + kTargetPageSize - 1) & ~(kTargetPageSize - 1);
		const mach_vm_size_t span = static_cast<mach_vm_size_t>(pageEnd - pageStart);
		const kern_return_t kr = mach_vm_protect(taskPort_, pageStart, span, false, prot);
		if (kr != KERN_SUCCESS) {
			LOG("mach_vm_protect(0x%llx, 0x%llx, 0x%x) failed (0x%x: %s)\n",
			    static_cast<unsigned long long>(pageStart),
			    static_cast<unsigned long long>(span),
			    prot, kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool getThreadState(arm_thread_state64_t &state) const {
		if (threadPort_ == MACH_PORT_NULL) return false;
		mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
		const kern_return_t kr =
		    thread_get_state(threadPort_, ARM_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count);
		if (kr != KERN_SUCCESS) {
			std::fprintf(stderr, "thread_get_state failed (0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool setThreadState(const arm_thread_state64_t &state) const {
		if (threadPort_ == MACH_PORT_NULL) return false;
		const kern_return_t kr =
		    thread_set_state(threadPort_, ARM_THREAD_STATE64,
		                     reinterpret_cast<thread_state_t>(const_cast<arm_thread_state64_t *>(&state)),
		                     ARM_THREAD_STATE64_COUNT);
		if (kr != KERN_SUCCESS) {
			std::fprintf(stderr, "thread_set_state failed (0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}
		return true;
	}

	bool selectThreadByPC(uint64_t pcA, uint64_t pcB, arm_thread_state64_t &stateOut) {
		thread_act_port_array_t threads = nullptr;
		mach_msg_type_number_t threadCount = 0;
		kern_return_t kr = task_threads(taskPort_, &threads, &threadCount);
		if (kr != KERN_SUCCESS || !threads || threadCount == 0) {
			std::fprintf(stderr, "task_threads failed (0x%x: %s)\n", kr, mach_error_string(kr));
			return false;
		}

		thread_t found = MACH_PORT_NULL;
		arm_thread_state64_t foundState {};
		for (mach_msg_type_number_t i = 0; i < threadCount; ++i) {
			arm_thread_state64_t st {};
			mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
			kr = thread_get_state(threads[i], ARM_THREAD_STATE64, reinterpret_cast<thread_state_t>(&st), &count);
			if (kr == KERN_SUCCESS && (st.__pc == pcA || st.__pc == pcB)) {
				found = threads[i];
				foundState = st;
				threads[i] = MACH_PORT_NULL; // keep this port
				break;
			}
		}

		for (mach_msg_type_number_t i = 0; i < threadCount; ++i) {
			if (threads[i] != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), threads[i]);
		}
		vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(threads), sizeof(thread_t) * threadCount);

		if (found == MACH_PORT_NULL) return false;

		if (threadPort_ != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), threadPort_);
		threadPort_ = found;
		stateOut = foundState;
		return true;
	}

	bool setBreakpoint(uint64_t address) {
		uint32_t original = 0;
		if (!readMemory(address, &original, sizeof(original))) {
			std::fprintf(stderr, "failed to read breakpoint target at 0x%llx\n",
			             static_cast<unsigned long long>(address));
			return false;
		}
		if (!protect(address, sizeof(original), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) return false;
		if (!writeMemory(address, &kAarch64Brk, sizeof(kAarch64Brk))) return false;
		if (!protect(address, sizeof(original), VM_PROT_READ | VM_PROT_EXECUTE)) return false;
		breakpoints_[address] = original;
		return true;
	}

	bool removeBreakpoint(uint64_t address) {
		const auto it = breakpoints_.find(address);
		if (it == breakpoints_.end()) return false;
		const uint32_t original = it->second;
		if (!protect(address, sizeof(original), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) return false;
		if (!writeMemory(address, &original, sizeof(original))) return false;
		if (!protect(address, sizeof(original), VM_PROT_READ | VM_PROT_EXECUTE)) return false;
		breakpoints_.erase(it);
		return true;
	}

	uint64_t findRosettaRuntimeBase() const {
		mach_vm_address_t address = 0;
		mach_vm_size_t size = 0;
		vm_region_basic_info_data_64_t info {};
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
		mach_port_t objectName = MACH_PORT_NULL;

		while (true) {
			count = VM_REGION_BASIC_INFO_COUNT_64;
			const kern_return_t kr = mach_vm_region(taskPort_, &address, &size, VM_REGION_BASIC_INFO_64,
			                                        reinterpret_cast<vm_region_info_t>(&info), &count, &objectName);
			if (objectName != MACH_PORT_NULL) {
				mach_port_deallocate(mach_task_self(), objectName);
				objectName = MACH_PORT_NULL;
			}
			if (kr != KERN_SUCCESS) break;

			const bool rx = (info.protection & (VM_PROT_READ | VM_PROT_EXECUTE)) == (VM_PROT_READ | VM_PROT_EXECUTE);
			if (rx) {
				char path[PROC_PIDPATHINFO_MAXSIZE] {};
				const int len = proc_regionfilename(pid_, static_cast<uint64_t>(address), path, sizeof(path));
				if (len > 0 && std::strstr(path, "/usr/libexec/rosetta/runtime")) {
					uint32_t magic = 0;
					if (readMemory(static_cast<uint64_t>(address), &magic, sizeof(magic)) && magic == MH_MAGIC_64) {
						return static_cast<uint64_t>(address);
					}
				}
			}

			if (address + size <= address) break;
			address += size;
		}
		return 0;
	}

	uint64_t allocateTranslatedMemory(uint64_t runtimeBase, const OffsetFinder &offsets, uint64_t size) {
		arm_thread_state64_t backup {};
		if (!getThreadState(backup)) return 0;

		arm_thread_state64_t state = backup;
		constexpr uint64_t kMapPrivate = 0x2;
		constexpr uint64_t kMapAnon = 0x1000;
		constexpr uint64_t kMapTranslatedAllowExecute = 0x20000;

		// mmap(addr=0,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON|MAP_TRANSLATED_ALLOW_EXECUTE,-1,0)
		state.__x[0] = 0;
		state.__x[1] = size;
		state.__x[2] = VM_PROT_READ | VM_PROT_WRITE;
		state.__x[3] = kMapPrivate | kMapAnon | kMapTranslatedAllowExecute;
		state.__x[4] = static_cast<uint64_t>(-1);
		state.__x[5] = 0;
		state.__pc = runtimeBase + offsets.offsetSvcCallEntry_;
		if (!setThreadState(state)) return 0;

		const uint64_t retBp = runtimeBase + offsets.offsetSvcCallRet_;
		if (!setBreakpoint(retBp)) {
			(void)setThreadState(backup);
			return 0;
		}
		if (!cont()) {
			(void)removeBreakpoint(retBp);
			(void)setThreadState(backup);
			return 0;
		}
		if (waitForStop() != WaitResult::Stopped) {
			(void)removeBreakpoint(retBp);
			(void)setThreadState(backup);
			return 0;
		}
		(void)removeBreakpoint(retBp);

		arm_thread_state64_t after {};
		if (!getThreadState(after)) {
			(void)setThreadState(backup);
			return 0;
		}

		const uint64_t mapped = after.__x[0];
		(void)setThreadState(backup);
		return mapped;
	}

	task_t taskPort() const { return taskPort_; }
	pid_t pid() const { return pid_; }

private:
	pid_t pid_ = -1;
	task_t taskPort_ = MACH_PORT_NULL;
	thread_t threadPort_ = MACH_PORT_NULL;
	std::map<uint64_t, uint32_t> breakpoints_;
};

struct MappedRegion {
	uint64_t start;
	uint64_t size;
	vm_prot_t prot;
};

std::vector<MappedRegion> findMappedRegionsByPathSubstring(const Debugger &dbg, const char *substr) {
	std::vector<MappedRegion> out;
	mach_vm_address_t address = 0;
	mach_vm_size_t size = 0;
	vm_region_basic_info_data_64_t info {};
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t objectName = MACH_PORT_NULL;

	while (true) {
		count = VM_REGION_BASIC_INFO_COUNT_64;
		const kern_return_t kr = mach_vm_region(dbg.taskPort(), &address, &size, VM_REGION_BASIC_INFO_64,
		                                        reinterpret_cast<vm_region_info_t>(&info), &count, &objectName);
		if (objectName != MACH_PORT_NULL) {
			mach_port_deallocate(mach_task_self(), objectName);
			objectName = MACH_PORT_NULL;
		}
		if (kr != KERN_SUCCESS) break;

		char path[PROC_PIDPATHINFO_MAXSIZE] {};
		const int len = proc_regionfilename(dbg.pid(), static_cast<uint64_t>(address), path, sizeof(path));
		if (len > 0 && std::strstr(path, substr)) {
			out.push_back(MappedRegion{static_cast<uint64_t>(address), static_cast<uint64_t>(size), info.protection});
		}

		if (address + size <= address) break;
		address += size;
	}

	return out;
}

size_t patchStringInRegions(const Debugger &dbg,
                            const std::vector<MappedRegion> &regions,
                            std::string_view needle,
                            std::string_view replacementSameLen) {
	if (needle.empty() || needle.size() != replacementSameLen.size()) return 0;

	const size_t needleLen = needle.size();
	const size_t blockSize = 64 * 1024;
	std::vector<uint8_t> prevTail;
	prevTail.resize(needleLen > 1 ? needleLen - 1 : 0);

	size_t patched = 0;

	for (const auto &r : regions) {
		if (!(r.prot & VM_PROT_READ) || r.size == 0) continue;

		std::fill(prevTail.begin(), prevTail.end(), 0);
		bool haveTail = false;

		for (uint64_t off = 0; off < r.size; off += blockSize) {
			const size_t toRead = static_cast<size_t>(std::min<uint64_t>(blockSize, r.size - off));
			std::vector<uint8_t> chunk;
			chunk.resize((haveTail ? prevTail.size() : 0) + toRead);

			size_t prefix = 0;
			if (haveTail && !prevTail.empty()) {
				std::memcpy(chunk.data(), prevTail.data(), prevTail.size());
				prefix = prevTail.size();
			}

			if (!dbg.readMemory(r.start + off, chunk.data() + prefix, toRead)) continue;

			// Search and patch within this window.
			for (size_t i = 0; i + needleLen <= chunk.size(); ++i) {
				if (std::memcmp(chunk.data() + i, needle.data(), needleLen) != 0) continue;

				const uint64_t abs = r.start + off - static_cast<uint64_t>(prefix) + static_cast<uint64_t>(i);

				// Make the containing page writable via COW, patch, then restore original protection.
				if (!dbg.protect(abs, needleLen, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) continue;
				if (dbg.writeMemory(abs, replacementSameLen.data(), needleLen)) patched++;
				(void)dbg.protect(abs, needleLen, r.prot);

				// Skip past this occurrence.
				i += needleLen - 1;
			}

			// Keep tail for boundary-crossing matches.
			if (!prevTail.empty()) {
				const size_t tailCopy = std::min(prevTail.size(), chunk.size());
				std::memcpy(prevTail.data(), chunk.data() + (chunk.size() - tailCopy), tailCopy);
				haveTail = true;
			}
		}
	}

	return patched;
}

bool readCString(const Debugger &dbg, uint64_t address, std::string &out, size_t maxLen) {
	out.clear();
	if (address == 0 || maxLen == 0) return false;
	std::vector<char> buf(maxLen);
	if (!dbg.readMemory(address, buf.data(), buf.size())) return false;
	const auto it = std::find(buf.begin(), buf.end(), '\0');
	out.assign(buf.begin(), it);
	return true;
}

bool findRuntimeCpuidAddress(const Debugger &dbg, const Exports &exports, uint64_t &runtimeCpuidOut) {
	runtimeCpuidOut = 0;
	if (exports.runtimeExports == 0 || exports.runtimeExportCount == 0 || exports.runtimeExportCount > 4096) return false;

	std::vector<ExportEntry> runtimeExports(static_cast<size_t>(exports.runtimeExportCount));
	if (!dbg.readMemory(exports.runtimeExports, runtimeExports.data(), runtimeExports.size() * sizeof(ExportEntry))) {
		return false;
	}

	for (const auto &entry : runtimeExports) {
		std::string name;
		if (!readCString(dbg, entry.name, name, 128)) continue;
		if (name == "runtime_cpuid") {
			runtimeCpuidOut = entry.address;
			return runtimeCpuidOut != 0;
		}
	}
	return false;
}

bool canEncodeB(uint64_t from, uint64_t to) {
	const int64_t diff = static_cast<int64_t>(to) - static_cast<int64_t>(from);
	if ((diff & 0x3) != 0) return false;
	return diff >= -(1ll << 27) && diff <= ((1ll << 27) - 4);
}

uint32_t getCpuidDelayIters() {
	const char *env = std::getenv("ASTROWINE_CPUID_DELAY_ITERS");
	if (!env || !*env) return 5000;

	char *end = nullptr;
	const unsigned long long parsed = std::strtoull(env, &end, 10);
	if (end == env || *end != '\0') return 5000;
	if (parsed > 500000000ull) return 500000000u;
	return static_cast<uint32_t>(parsed);
}

bool installCpuidDelayHook(Debugger &dbg,
                           uint64_t runtimeBase,
                           const OffsetFinder &offsets,
                           const arm_thread_state64_t &stateAtBreak,
                           uint32_t delayIters) {
	if (delayIters == 0) return true;

	const uint64_t exportsAddr = stateAtBreak.__x[19];
	if (exportsAddr == 0) {
		std::fprintf(stderr, "cpuid-delay: X19 exports pointer is null.\n");
		return false;
	}

	Exports exports {};
	if (!dbg.readMemory(exportsAddr, &exports, sizeof(exports))) {
		std::fprintf(stderr, "cpuid-delay: failed to read exports struct.\n");
		return false;
	}

	uint64_t runtimeCpuid = 0;
	if (!findRuntimeCpuidAddress(dbg, exports, runtimeCpuid)) {
		std::fprintf(stderr, "cpuid-delay: failed to locate runtime_cpuid.\n");
		return false;
	}

	uint32_t origFirstInsn = 0;
	if (!dbg.readMemory(runtimeCpuid, &origFirstInsn, sizeof(origFirstInsn))) {
		std::fprintf(stderr, "cpuid-delay: failed to read runtime_cpuid first instruction.\n");
		return false;
	}

	const uint64_t stubPage = dbg.allocateTranslatedMemory(runtimeBase, offsets, kTargetPageSize);
	if (!stubPage || stubPage == static_cast<uint64_t>(-1)) {
		std::fprintf(stderr, "cpuid-delay: failed to allocate translated memory.\n");
		return false;
	}

	std::vector<uint32_t> stub;
	stub.reserve(16);

	emitMovAbs64(stub, 16, delayIters);
	const size_t loopIdx = stub.size();
	stub.push_back(encodeSubsImm(16, 1)); // subs x16, x16, #1
	const size_t bneIdx = stub.size();
	stub.push_back(0); // b.ne loop (patched below)
	stub.push_back(origFirstInsn);
	const size_t backBranchIdx = stub.size();
	stub.push_back(0); // b runtime_cpuid+4 (patched below)

	const uint64_t stubAddr = stubPage;
	const uint64_t bneFrom = stubAddr + static_cast<uint64_t>(bneIdx * sizeof(uint32_t));
	const uint64_t loopTo = stubAddr + static_cast<uint64_t>(loopIdx * sizeof(uint32_t));
	stub[bneIdx] = encodeBCond(0x1, static_cast<int64_t>(loopTo) - static_cast<int64_t>(bneFrom)); // NE

	const uint64_t backFrom = stubAddr + static_cast<uint64_t>(backBranchIdx * sizeof(uint32_t));
	const uint64_t backTo = runtimeCpuid + sizeof(uint32_t);
	if (!canEncodeB(backFrom, backTo)) {
		std::fprintf(stderr, "cpuid-delay: stub back-branch out of range.\n");
		return false;
	}
	stub[backBranchIdx] = encodeB(static_cast<int64_t>(backTo) - static_cast<int64_t>(backFrom));

	const uint64_t patchFrom = runtimeCpuid;
	const uint64_t patchTo = stubAddr;
	if (!canEncodeB(patchFrom, patchTo)) {
		std::fprintf(stderr, "cpuid-delay: entry branch out of range.\n");
		return false;
	}
	const uint32_t branchToStub = encodeB(static_cast<int64_t>(patchTo) - static_cast<int64_t>(patchFrom));

	if (!dbg.writeMemory(stubAddr, stub.data(), stub.size() * sizeof(uint32_t))) {
		std::fprintf(stderr, "cpuid-delay: failed to write stub.\n");
		return false;
	}
	if (!dbg.protect(stubAddr, kTargetPageSize, VM_PROT_READ | VM_PROT_EXECUTE)) {
		std::fprintf(stderr, "cpuid-delay: failed to set stub page RX.\n");
		return false;
	}

	if (!dbg.protect(runtimeCpuid, sizeof(uint32_t), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) {
		std::fprintf(stderr, "cpuid-delay: failed to set runtime_cpuid writable.\n");
		return false;
	}
	if (!dbg.writeMemory(runtimeCpuid, &branchToStub, sizeof(branchToStub))) {
		std::fprintf(stderr, "cpuid-delay: failed to patch runtime_cpuid.\n");
		return false;
	}
	if (!dbg.protect(runtimeCpuid, sizeof(uint32_t), VM_PROT_READ | VM_PROT_EXECUTE)) {
		std::fprintf(stderr, "cpuid-delay: failed to restore runtime_cpuid RX.\n");
		return false;
	}

	LOG("cpuid-delay: patched runtime_cpuid=0x%llx -> stub=0x%llx (iters=%u)\n",
	    static_cast<unsigned long long>(runtimeCpuid),
	    static_cast<unsigned long long>(stubAddr),
	    delayIters);
	return true;
}

} // namespace

int main(int argc, char **argv) {
	if (argc < 2) {
		std::fprintf(stderr, "%s <program> [args...]\n", argv[0]);
		return 1;
	}

	gLogsEnabled = std::getenv("ASTROWINE_LOGS") != nullptr;

	const pid_t child = fork();
	if (child < 0) {
		std::perror("fork");
		return 1;
	}

	if (child == 0) {
		if (ptrace(PT_TRACE_ME, 0, nullptr, 0) < 0) {
			std::perror("child: ptrace(PT_TRACE_ME)");
			_exit(1);
		}
		execv(argv[1], &argv[1]);
		std::perror("child: execv");
		_exit(1);
	}

	Debugger dbg;
	if (!dbg.attachTracedChild(child)) return 1;

	// Locate Rosetta runtime mapping.
	uint64_t runtimeBase = dbg.findRosettaRuntimeBase();
	if (!runtimeBase) {
		// Give dyld a moment.
		(void)dbg.cont();
		usleep(2000);
		if (!dbg.stopAndWait()) return 1;
		runtimeBase = dbg.findRosettaRuntimeBase();
	}
	if (!runtimeBase) {
		std::fprintf(stderr, "failed to locate /usr/libexec/rosetta/runtime mapping in target.\n");
		(void)dbg.detach();
		return 1;
	}
	LOG("rosetta runtime base: 0x%llx\n", static_cast<unsigned long long>(runtimeBase));

	OffsetFinder offsets;
	offsets.setDefaultOffsets();
	if (!offsets.determineOffsets()) {
		std::fprintf(stderr, "failed to determine rosetta runtime offsets; refusing to continue.\n");
		(void)dbg.detach();
		return 1;
	}
	LOG("offsets: exports_fetch=0x%llx svc_entry=0x%llx svc_ret=0x%llx\n",
	    static_cast<unsigned long long>(offsets.offsetExportsFetch_),
	    static_cast<unsigned long long>(offsets.offsetSvcCallEntry_),
	    static_cast<unsigned long long>(offsets.offsetSvcCallRet_));

	const uint64_t exportsFetchBp = runtimeBase + offsets.offsetExportsFetch_;
	if (gLogsEnabled) {
		std::array<uint32_t, 12> expPreview {};
		if (dbg.readMemory(exportsFetchBp, expPreview.data(), expPreview.size() * sizeof(uint32_t))) {
			LOG("exports_fetch preview:");
			for (size_t i = 0; i < expPreview.size(); ++i) LOG(" %08x", expPreview[i]);
			LOG("\n");
		}
	}
	if (!dbg.setBreakpoint(exportsFetchBp)) {
		std::fprintf(stderr, "failed to set exports_fetch breakpoint.\n");
		(void)dbg.detach();
		return 1;
	}

	// Run until breakpoint triggers.
	bool hit = false;
	arm_thread_state64_t stateAtBreak {};
	for (int i = 0; i < kMaxStopsToHitBp; ++i) {
		if (!dbg.cont()) break;
		if (dbg.waitForStop() != WaitResult::Stopped) break;
		if (dbg.selectThreadByPC(exportsFetchBp, exportsFetchBp + 4, stateAtBreak)) {
			hit = true;
			break;
		}
	}
	(void)dbg.removeBreakpoint(exportsFetchBp);

	if (!hit) {
		std::fprintf(stderr, "did not hit exports_fetch breakpoint.\n");
		(void)dbg.detach();
		return 1;
	}

	// Ensure we re-execute the original instruction we temporarily replaced with BRK.
	if (stateAtBreak.__pc == exportsFetchBp + 4) stateAtBreak.__pc = exportsFetchBp;

	// Patch the "VirtualApple" string in libRosettaRuntime's mappings using debugger-legal COW writes.
	std::vector<MappedRegion> regions = findMappedRegionsByPathSubstring(dbg, "libRosettaRuntime");
	if (regions.empty()) regions = findMappedRegionsByPathSubstring(dbg, "oah/libRosettaRuntime");
	if (regions.empty()) regions = findMappedRegionsByPathSubstring(dbg, "/Library/Apple/usr/libexec/oah/libRosettaRuntime");

	if (gLogsEnabled) {
		LOG("libRosettaRuntime mapped regions: %zu\n", regions.size());
		for (const auto &r : regions) {
			LOG("  region: [0x%llx, 0x%llx) prot=0x%x\n",
			    static_cast<unsigned long long>(r.start),
			    static_cast<unsigned long long>(r.start + r.size),
			    r.prot);
		}
	}

	size_t patched = 0;
	if (!regions.empty()) {
		std::vector<MappedRegion> execRegions;
		execRegions.reserve(regions.size());
		for (const auto &r : regions) {
			// Prefer scanning the non-writable text mapping (typically prot=R|X). This avoids
			// spending time in large RWX/bss reservations that may share the same backing path.
			const bool rx = (r.prot & (VM_PROT_READ | VM_PROT_EXECUTE)) == (VM_PROT_READ | VM_PROT_EXECUTE);
			const bool writable = (r.prot & VM_PROT_WRITE) != 0;
			if (rx && !writable) execRegions.push_back(r);
		}
		patched = patchStringInRegions(dbg, execRegions.empty() ? regions : execRegions, kNeedle, kReplacement);
		if (patched == 0 && !execRegions.empty()) {
			// Fallback: also scan non-exec mappings of the same image (rodata can be r--).
			patched = patchStringInRegions(dbg, regions, kNeedle, kReplacement);
		}
	}

	std::fprintf(stderr, "patched occurrences: %zu\n", patched);

	const uint32_t delayIters = getCpuidDelayIters();
	if (delayIters > 0) {
		if (!installCpuidDelayHook(dbg, runtimeBase, offsets, stateAtBreak, delayIters)) {
			(void)dbg.detach();
			return 1;
		}
		if (gLogsEnabled) std::fprintf(stderr, "cpuid-delay iterations: %u\n", delayIters);
	}

	// Resume original execution at exports_fetch and detach immediately.
	if (!dbg.setThreadState(stateAtBreak)) {
		std::fprintf(stderr, "failed to restore thread state at breakpoint.\n");
		(void)dbg.detach();
		return 1;
	}

	if (!dbg.detach()) return 1;

	// Default behavior: exit immediately after detach (anti-debug sensitive titles may check
	// for an attached tracer early). For local testing, you can opt into waiting to capture
	// the child's stdout/stderr deterministically.
	if (std::getenv("ASTROWINE_WAIT_CHILD") == nullptr) return 0;

	int status = 0;
	if (waitpid(child, &status, 0) < 0) {
		std::perror("waitpid(child)");
		return 1;
	}
	if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
	if (WIFEXITED(status)) return WEXITSTATUS(status);
	return 0;
}
