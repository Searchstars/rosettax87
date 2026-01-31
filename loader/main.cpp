#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <thread>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/mach_vm.h>

#include <algorithm>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

#include "offset_finder.hpp"

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

	const char *env = getenv("ROSETTA_HOOK_LOGS");
	if (env && strcmp(env, "0") == 0) {
		hookLogsEnabled = false;
		return;
	}

	const char *logPath = getenv("ROSETTA_HOOK_LOG_PATH");
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

typedef const struct dyld_process_info_base *DyldProcessInfo;

extern "C" DyldProcessInfo _dyld_process_info_create(task_t task, uint64_t timestamp, kern_return_t *kernelError);
extern "C" void _dyld_process_info_for_each_image(DyldProcessInfo info, void (^callback)(uint64_t machHeaderAddress, const uuid_t uuid, const char *path));
extern "C" void _dyld_process_info_release(DyldProcessInfo info);

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
			LOG("Signal %d thread[%zu] pc=0x%llx instr=0x%08x\n", signal, i, state.__pc, instr);
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

	bool writeMemory(uint64_t address, const void *buffer, size_t size) {
		kern_return_t kr = mach_vm_write(taskPort_, address, (vm_offset_t)buffer, size);

		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "Failed to write memory at 0x%llx (error 0x%x: %s)\n", address, kr, mach_error_string(kr));
			return false;
		}

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

	auto findRuntime() -> uintptr_t {
		mach_vm_address_t address = 0;
		mach_vm_size_t size;
		vm_region_basic_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
		mach_port_t objectName;
		kern_return_t kr;
		__block std::vector<uintptr_t> moduleList;

		auto processInfo = _dyld_process_info_create(taskPort_, 0, &kr);
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

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "%s <path to program>\n", argv[0]);
		return 1;
	}

	logsEnabled = getenv("ROSETTA_X87_LOGS");
	const bool resolveLogAll = getenv("ROSETTA_RESOLVE_LOG_ALL") != nullptr;
	std::unordered_set<uint64_t> resolveSeen;
	const std::string targetPath = argc > 1 ? argv[1] : "";
	const bool passSigtrapBrk = getenv("ROSETTA_PASS_SIGTRAP") != nullptr;
	const bool redirectSigsysBrk = getenv("ROSETTA_SKIP_SIGSYS_REDIRECT") == nullptr;
	const bool skipWinebootHook = getenv("ROSETTA_SKIP_WINEBOOT") != nullptr;
	size_t resolveHookLimit = 100;
	if (const char *limitEnv = getenv("ROSETTA_RESOLVE_HOOK_LIMIT")) {
		resolveHookLimit = strtoull(limitEnv, nullptr, 10);
	}
	bool resolveHookEnabled = resolveHookLimit != 0;
	size_t resolveHookCount = 0;
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
	LOG("offset_helper_syscall=%llx offset_helper_resolve_addr=%llx\n",
	    offsetFinder.offsetHelperSyscall_, offsetFinder.offsetHelperResolveAddr_);

	const auto runtimeBase = dbg.findRuntime();

	LOG("Rosetta runtime base: 0x%lx\n", runtimeBase);

	if (runtimeBase == 0) {
		fprintf(stderr, "Rosetta runtime not found; running without hooks.\n");
		dbg.detach();
		return 0;
	}

	const auto helperSyscallAddr = runtimeBase + offsetFinder.offsetHelperSyscall_;
	const auto helperResolveAddr = runtimeBase + offsetFinder.offsetHelperResolveAddr_;

	LOG("helper_syscall address: 0x%llx\n", helperSyscallAddr);
	LOG("helper_resolve_addr address: 0x%llx\n", helperResolveAddr);

	if (!dbg.setBreakpoint(helperSyscallAddr) ||
	    (resolveHookEnabled && !dbg.setBreakpoint(helperResolveAddr))) {
		fprintf(stderr, "Failed to set helper breakpoints\n");
		dbg.detach();
		return 1;
	}

	int pendingSignal = 0;
	size_t signalLogCount = 0;
	size_t trapLogCount = 0;
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
			const bool restoreOrigin = !(originAddr == helperResolveAddr && !resolveHookEnabled);
			if (!dbg.removeTempBreakpoint(hitAddr)) {
				fprintf(stderr, "Failed to remove temp breakpoint at 0x%llx\n", hitAddr);
				if (hitThread != MACH_PORT_NULL) {
					mach_port_deallocate(mach_task_self(), hitThread);
				}
				return 1;
			}
			if (restoreOrigin && originAddr != 0 && !dbg.setBreakpoint(originAddr)) {
				fprintf(stderr, "Failed to restore breakpoint at 0x%llx\n", originAddr);
				mach_port_deallocate(mach_task_self(), hitThread);
				return 1;
			}
			mach_port_deallocate(mach_task_self(), hitThread);
			continue;
		}

		const bool isSyscall = (hitAddr == helperSyscallAddr);
		const bool isResolve = (hitAddr == helperResolveAddr);
		if (isResolve && resolveHookEnabled && resolveHookLimit > 0) {
			resolveHookCount++;
			if (resolveHookCount > resolveHookLimit) {
				resolveHookEnabled = false;
				LOG("Disabling helper_resolve_addr hook after %zu hits\n", resolveHookCount);
			}
		}

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
		} else {
			const uint64_t x0 = dbg.readRegister(hitThread, MuhDebugger::Register::X0);
			const uint64_t x1 = dbg.readRegister(hitThread, MuhDebugger::Register::X1);
			const uint64_t x2 = dbg.readRegister(hitThread, MuhDebugger::Register::X2);
			bool shouldLog = resolveLogAll;
			if (!shouldLog) {
				auto inserted = resolveSeen.insert(x1).second;
				shouldLog = inserted;
				if (resolveSeen.size() > 100000) {
					resolveSeen.clear();
				}
			}
			if (shouldLog) {
				hookLog("[helper_resolve_addr] context=0x%llx x86_address=0x%llx stubs_sh=0x%llx\n", x0, x1, x2);
			}
		}

		if (!dbg.removeBreakpoint(hitAddr)) {
			fprintf(stderr, "Failed to remove breakpoint at 0x%llx\n", hitAddr);
			if (hitThread != MACH_PORT_NULL) {
				mach_port_deallocate(mach_task_self(), hitThread);
			}
			return 1;
		}

		if (!(isResolve && !resolveHookEnabled)) {
			const uint64_t tempAddr = hitAddr + 4;
			if (!dbg.setTempBreakpoint(tempAddr, hitAddr)) {
				fprintf(stderr, "Failed to set temp breakpoint at 0x%llx\n", tempAddr);
				mach_port_deallocate(mach_task_self(), hitThread);
				return 1;
			}
		}

		mach_port_deallocate(mach_task_self(), hitThread);
	}

	if (dbg.lastWaitOutcome() == MuhDebugger::WaitOutcome::Stopped) {
		dbg.detach();
	}

	return 0;
}
