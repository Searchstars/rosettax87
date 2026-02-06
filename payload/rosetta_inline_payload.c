#include <stdint.h>
#include <stddef.h>

// NOTE: This code is copied into a Rosetta runtime code-cave as a raw __text blob.
// It must be freestanding and must not rely on external symbols or data sections.

static inline __attribute__((always_inline)) char hex_digit(uint8_t value) {
	return (value < 10) ? (char)('0' + value) : (char)('a' + (value - 10));
}

static inline __attribute__((always_inline)) void write_hex16(char **cursor, uint64_t value) {
	for (int shift = 60; shift >= 0; shift -= 4) {
		const uint8_t nibble = (uint8_t)((value >> shift) & 0x0fu);
		*(*cursor)++ = hex_digit(nibble);
	}
}

static inline __attribute__((always_inline)) void write_str(char **cursor, const char *text) {
	while (*text) {
		*(*cursor)++ = *text++;
	}
}

static inline __attribute__((always_inline)) uint64_t flush_line(char *out, char *cursor) {
	*cursor++ = '\n';
	const uint64_t len = (uint64_t)(cursor - out);
	register uint64_t r0 asm("x0") = 2;
	register uint64_t r1 asm("x1") = (uint64_t)out;
	register uint64_t r2 asm("x2") = len;
	register uint64_t r16 asm("x16") = 4;
	__asm__ volatile("svc #0x80"
	                 : "+r"(r0)
	                 : "r"(r1), "r"(r2), "r"(r16)
	                 : "memory");
	return len;
}

static inline __attribute__((always_inline)) uint64_t sys_getpid(void) {
	register uint64_t r0 asm("x0") = 0;
	register uint64_t r16 asm("x16") = 20; // SYS_getpid
	__asm__ volatile("svc #0x80"
	                 : "+r"(r0)
	                 : "r"(r16)
	                 : "memory", "x1", "x2", "x3", "x4", "x5", "x6", "x7");
	return r0;
}

static inline __attribute__((always_inline)) uint64_t sys_kill(uint64_t pid, uint64_t sig) {
	register uint64_t r0 asm("x0") = pid;
	register uint64_t r1 asm("x1") = sig;
	register uint64_t r16 asm("x16") = 37; // SYS_kill
	__asm__ volatile("svc #0x80"
	                 : "+r"(r0)
	                 : "r"(r1), "r"(r16)
	                 : "memory", "x2", "x3", "x4", "x5", "x6", "x7");
	return r0;
}

static inline __attribute__((always_inline)) uint64_t sys_thread_selfid(void) {
	register uint64_t r0 asm("x0") = 0;
	register uint64_t r16 asm("x16") = 372; // SYS_thread_selfid
	__asm__ volatile("svc #0x80"
	                 : "+r"(r0)
	                 : "r"(r16)
	                 : "memory", "x1", "x2", "x3", "x4", "x5", "x6", "x7");
	return r0;
}

static inline __attribute__((always_inline)) uint64_t sys_pthread_kill(uint64_t tid, uint64_t sig) {
	register uint64_t r0 asm("x0") = tid;
	register uint64_t r1 asm("x1") = sig;
	register uint64_t r16 asm("x16") = 328; // SYS___pthread_kill
	__asm__ volatile("svc #0x80"
	                 : "+r"(r0)
	                 : "r"(r1), "r"(r16)
	                 : "memory", "x2", "x3", "x4", "x5", "x6", "x7");
	return r0;
}

static inline __attribute__((always_inline)) uint64_t current_pthread_kill_id(void) {
	/* libpthread stores the kernel thread id used by __pthread_kill at
	 * (pthread_self + 0xf8). On arm64 macOS, pthread_self is TPIDRRO_EL0 - 0xe0,
	 * so the id sits at TPIDRRO_EL0 + 0x18. */
	uint64_t tpidrro = 0;
	__asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tpidrro));
	return *(volatile uint32_t *)(uintptr_t)(tpidrro + 0x18u);
}

static inline __attribute__((always_inline)) void dmb_ish(void) {
	__asm__ volatile("dmb ish" ::: "memory");
}

enum {
	ASTROWINE_STATE_FLAG_LOG_SYSCALL = 1u << 0,
	ASTROWINE_STATE_FLAG_LOG_RESOLVE = 1u << 1,
	ASTROWINE_STATE_FLAG_INTERCEPT = 1u << 2,
};

// "ASTRWST1\0" little endian (unique enough for debugging).
static const uint64_t kAstroWineStateMagic = 0x0031545357525453ull;
static const uint32_t kAstroWineStateVersion = 1u;

struct AstroWineState {
	uint64_t magic;
	uint32_t version;
	volatile uint32_t lock;
	volatile uint32_t count;
	uint32_t capacity;
	/* Optional override: when non-zero, intercept only x86 addresses below threshold.
	 * When zero, use seccomp-like address filtering (preferred default). */
	uint64_t native_threshold_x86;
	uint64_t wine_shm_ptr;         // Optional: pointer to a Wine-shared struct (see Wine patch). 0 disables it.
	uint32_t flags;
	uint32_t _pad;
	// Tables follow in memory:
	// uint64_t arm_addrs[capacity];  (sorted)
	// uint64_t x86_addrs[capacity];
	// uint8_t  func_flags[capacity]; (1 = interceptable)
};

struct AstroWineWineShm {
	uint64_t magic;
	uint32_t version;
	/* pending states:
	 * 0 = idle, 1 = ready for Wine handler, 2 = write-locked by payload */
	volatile uint32_t pending;
	uint64_t syscall_nr;
	uint64_t syscall_rip;
	/* Register snapshot for Wine's SIGSYS handler override. */
	uint64_t rbx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t rsp;
	uint64_t rbp;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
};

static inline __attribute__((always_inline)) int claim_wine_shm_slot(volatile uint32_t *pending) {
	for (uint32_t i = 0; i < 1000000u; ++i) {
		uint32_t expected = 0;
		if (__atomic_compare_exchange_n((uint32_t *)pending, &expected, 2u, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
			return 1;
		}
	}
	return 0;
}

static inline __attribute__((always_inline)) void spin_lock(volatile uint32_t *lock) {
	uint32_t value;
	uint32_t status;
	for (;;) {
		__asm__ volatile(
			"1:\n"
			"ldaxr %w0, [%2]\n"
			"cbnz  %w0, 1b\n"
			"mov   %w0, #1\n"
			"stlxr %w1, %w0, [%2]\n"
			"cbnz  %w1, 1b\n"
			: "=&r"(value), "=&r"(status)
			: "r"(lock)
			: "memory");
		return;
	}
}

static inline __attribute__((always_inline)) void spin_unlock(volatile uint32_t *lock) {
	__asm__ volatile("stlr wzr, [%0]" : : "r"(lock) : "memory");
}

static inline __attribute__((always_inline)) uint64_t *state_arm_table(struct AstroWineState *st) {
	return (uint64_t *)((char *)st + sizeof(*st));
}

static inline __attribute__((always_inline)) uint64_t *state_x86_table(struct AstroWineState *st) {
	uint64_t *arm = state_arm_table(st);
	return arm + st->capacity;
}

static inline __attribute__((always_inline)) uint8_t *state_func_flags(struct AstroWineState *st) {
	uint64_t *x86 = state_x86_table(st);
	return (uint8_t *)(x86 + st->capacity);
}

static inline __attribute__((always_inline)) uint32_t lower_bound_u64(const uint64_t *arr, uint32_t count, uint64_t value) {
	uint32_t lo = 0;
	uint32_t hi = count;
	while (lo < hi) {
		const uint32_t mid = lo + ((hi - lo) >> 1);
		const uint64_t v = arr[mid];
		if (v < value) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	return lo;
}

static inline __attribute__((always_inline)) uint32_t find_floor_index_u64(const uint64_t *arr, uint32_t count, uint64_t value) {
	// Returns UINT32_MAX if no element <= value.
	uint32_t lo = 0;
	uint32_t hi = count;
	while (lo < hi) {
		const uint32_t mid = lo + ((hi - lo) >> 1);
		if (arr[mid] <= value) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	if (lo == 0) {
		return 0xffffffffu;
	}
	return lo - 1;
}

/* Mirror Wine's Linux seccomp address policy for trapping x86 syscalls:
 * 1) trap low addresses (< 0x700000000000), except wine64-preloader window.
 * 2) in high addresses, only trap top-down allocation window 0x7fff:fe000000..fffeffff. */
static inline __attribute__((always_inline)) int should_trap_x86_rip_like_seccomp(uint64_t rip) {
	if (!rip) {
		return 0;
	}

	const uint32_t hi = (uint32_t)(rip >> 32);
	const uint32_t lo = (uint32_t)rip;

	if (hi > 0x7000u) {
		if (hi != 0x7fffu) {
			return 0;
		}
		if (lo < 0xfe000000u) {
			return 0;
		}
		if (lo >= 0xffff0000u) {
			return 0;
		}
		return 1;
	}

	/* Allow wine64-preloader shim window. */
	if (lo >= 0x7d400000u && lo < 0x7d402000u) {
		return 0;
	}
	return 1;
}

static inline __attribute__((always_inline)) void maybe_log_syscall(char *out,
                                                                    struct AstroWineState *st,
                                                                    uint64_t sysnum,
                                                                    uint64_t lr,
                                                                    uint64_t arm_func,
                                                                    uint64_t x86_func,
                                                                    const char *tag) {
	if (!st || !(st->flags & ASTROWINE_STATE_FLAG_LOG_SYSCALL)) {
		return;
	}
	char *cursor = out;
	write_str(&cursor, tag);
	write_str(&cursor, " sys=0x");
	write_hex16(&cursor, sysnum);
	write_str(&cursor, " lr=0x");
	write_hex16(&cursor, lr);
	write_str(&cursor, " arm_func=0x");
	write_hex16(&cursor, arm_func);
	write_str(&cursor, " x86_func=0x");
	write_hex16(&cursor, x86_func);
	(void)flush_line(out, cursor);
}

static inline __attribute__((always_inline)) void maybe_log_resolve(char *out,
                                                                    struct AstroWineState *st,
                                                                    uint64_t x86_addr,
                                                                    uint64_t arm_addr,
                                                                    const char *tag) {
	if (!st || !(st->flags & ASTROWINE_STATE_FLAG_LOG_RESOLVE)) {
		return;
	}
	char *cursor = out;
	write_str(&cursor, tag);
	write_str(&cursor, " x86=0x");
	write_hex16(&cursor, x86_addr);
	write_str(&cursor, " arm=0x");
	write_hex16(&cursor, arm_addr);
	(void)flush_line(out, cursor);
}

__attribute__((used, noinline))
uint64_t rosetta_helper_syscall_inline(char *out,
                                       uint64_t state_ptr,
                                       uint64_t sysnum,
                                       uint64_t lr,
                                       uint64_t regs_ptr) {
	struct AstroWineState *st = (struct AstroWineState *)(uintptr_t)state_ptr;
	if (!st || st->magic != kAstroWineStateMagic || st->version != kAstroWineStateVersion) {
		return 0;
	}

	// Fast path: Darwin x86_64 syscalls always include a syscall class in the upper bits
	// (e.g. 0x2000000 for UNIX). Windows syscall numbers are typically small (class==0).
	const uint32_t syscall_class = (uint32_t)((sysnum & 0x07000000u) >> 24);
	if (syscall_class != 0) {
		if (st->flags & ASTROWINE_STATE_FLAG_LOG_SYSCALL) {
			maybe_log_syscall(out, st, sysnum, lr, 0, 0, "syscall(pass)");
		}
		return 0;
	}

	uint64_t arm_func = 0;
	uint64_t x86_func = 0;
	uint8_t interceptable = 0;
	const uint64_t *regs = (const uint64_t *)(uintptr_t)regs_ptr;
	const uint64_t x86_rcx_rip = regs ? regs[1] : 0;

	spin_lock(&st->lock);
	const uint32_t count = st->count;
	if (count) {
		const uint64_t *arm = state_arm_table(st);
		const uint64_t *x86 = state_x86_table(st);
		const uint8_t *flags = state_func_flags(st);
		const uint32_t idx = find_floor_index_u64(arm, count, lr);
		if (idx != 0xffffffffu) {
			arm_func = arm[idx];
			x86_func = x86[idx];
			interceptable = flags[idx];
		}
	}
	spin_unlock(&st->lock);

	/* Use the exact x86 trap site (RCX semantics of SYSCALL) whenever available.
	 * The arm->x86 function floor mapping can resolve to a wrapper thunk. */
	const uint64_t x86_site = x86_rcx_rip ? x86_rcx_rip : x86_func;
	const uint64_t threshold = st->native_threshold_x86;
	int should_intercept = 0;
	if ((st->flags & ASTROWINE_STATE_FLAG_INTERCEPT) && interceptable) {
		/* Keep threshold override for experiments; otherwise use seccomp-like trap policy. */
		should_intercept = threshold ? (x86_site != 0 && x86_site < threshold)
		                             : should_trap_x86_rip_like_seccomp(x86_site);
	}

	if (!should_intercept || st->wine_shm_ptr == 0) {
		maybe_log_syscall(out, st, sysnum, lr, arm_func, x86_site, "syscall(skip)");
		return 0;
	}

	// Communicate syscall info to Wine via a fixed shared struct, then raise SIGSYS.
	struct AstroWineWineShm *shm = (struct AstroWineWineShm *)(uintptr_t)st->wine_shm_ptr;
	if (!claim_wine_shm_slot(&shm->pending)) {
		maybe_log_syscall(out, st, sysnum, lr, arm_func, x86_site, "syscall(shm-busy)");
		return 0;
	}

	shm->syscall_nr = sysnum;
	/* Preserve a seccomp-like trap site whenever possible. */
	shm->syscall_rip = x86_site;
	/* x86_64 -> arm64 register mapping (Rosetta2):
	 * x0..x15 correspond to RAX..R15. */
	shm->rbx = regs[3];
	shm->rdx = regs[2];
	shm->rsi = regs[6];
	shm->rdi = regs[7];
	shm->rsp = regs[4];
	shm->rbp = regs[5];
	shm->r8 = regs[8];
	shm->r9 = regs[9];
	shm->r10 = regs[10];
	shm->r12 = regs[12];
	shm->r13 = regs[13];
	shm->r14 = regs[14];
	shm->r15 = regs[15];
	dmb_ish();
	__atomic_store_n((uint32_t *)&shm->pending, 1u, __ATOMIC_RELEASE);

	maybe_log_syscall(out, st, sysnum, lr, arm_func, x86_func, "syscall(TRAP)");

	const uint64_t tid = current_pthread_kill_id();
	uint64_t raise_result = (uint64_t)-1;
	if (tid != 0) {
		raise_result = sys_pthread_kill(tid, 12 /* SIGSYS */);
	}
	if (raise_result != 0) {
		const uint64_t tid_selfid = sys_thread_selfid();
		if (tid_selfid != 0 && tid_selfid != (uint64_t)-1) {
			raise_result = sys_pthread_kill(tid_selfid, 12 /* SIGSYS */);
		}
	}
	if (raise_result != 0) {
		const uint64_t pid = sys_getpid();
		raise_result = sys_kill(pid, 12 /* SIGSYS */);
	}

	/* Best effort: if signal was handled in-place, pending will be cleared by Wine handler. */
	for (uint32_t i = 0; i < 1000000u; ++i) {
		if (__atomic_load_n((uint32_t *)&shm->pending, __ATOMIC_ACQUIRE) == 0) {
			break;
		}
	}
	if (__atomic_load_n((uint32_t *)&shm->pending, __ATOMIC_ACQUIRE) != 0) {
		__atomic_store_n((uint32_t *)&shm->pending, 0u, __ATOMIC_RELEASE);
	}

	// If the Wine SIGSYS handler doesn't redirect for some reason, tell the stub to skip the original helper.
	return 1;
}

__attribute__((used, noinline))
uint64_t rosetta_helper_resolve_inline(char *out,
                                       uint64_t state_ptr,
                                       uint64_t x86_addr,
                                       uint64_t arm_addr) {
	struct AstroWineState *st = (struct AstroWineState *)(uintptr_t)state_ptr;
	if (!st || st->magic != kAstroWineStateMagic || st->version != kAstroWineStateVersion) {
		return 0;
	}
	if (x86_addr == 0 || arm_addr == 0) {
		return 0;
	}

	spin_lock(&st->lock);
	const uint32_t count = st->count;
	const uint32_t capacity = st->capacity;
	uint64_t *arm = state_arm_table(st);
	uint64_t *x86 = state_x86_table(st);
	uint8_t *flags = state_func_flags(st);

	const uint32_t pos = lower_bound_u64(arm, count, arm_addr);
	if (pos < count && arm[pos] == arm_addr) {
		x86[pos] = x86_addr;
		const uint64_t threshold = st->native_threshold_x86;
		flags[pos] = (!threshold || x86_addr < threshold) ? 1 : 0;
	} else if (count < capacity) {
		for (uint32_t i = count; i > pos; --i) {
			arm[i] = arm[i - 1];
			x86[i] = x86[i - 1];
			flags[i] = flags[i - 1];
		}
		arm[pos] = arm_addr;
		x86[pos] = x86_addr;
		const uint64_t threshold = st->native_threshold_x86;
		flags[pos] = (!threshold || x86_addr < threshold) ? 1 : 0;
		st->count = count + 1;
	}
	spin_unlock(&st->lock);

	maybe_log_resolve(out, st, x86_addr, arm_addr, "resolve(map)");
	return 0;
}
