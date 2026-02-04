#include <stddef.h>
#include <stdint.h>

static inline long sys_write(int fd, const void *buf, uint64_t len) {
	register uint64_t x0 asm("x0") = (uint64_t)fd;
	register uint64_t x1 asm("x1") = (uint64_t)buf;
	register uint64_t x2 asm("x2") = len;
	register uint64_t x16 asm("x16") = 0x4; // SYS_write
	asm volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
	return (long)x0;
}

__attribute__((visibility("default")))
volatile uint64_t rosetta_helper_syscall_counter = 0;

static size_t append_str(char *out, size_t pos, const char *text) {
	while (*text) {
		out[pos++] = *text++;
	}
	return pos;
}

static size_t append_hex_n(char *out, size_t pos, uint64_t value, int digits) {
	static const char kHex[] = "0123456789abcdef";
	out[pos++] = '0';
	out[pos++] = 'x';
	for (int shift = (digits - 1) * 4; shift >= 0; shift -= 4) {
		out[pos++] = kHex[(value >> shift) & 0xf];
	}
	return pos;
}

__attribute__((visibility("default"), noinline, used))
void rosetta_helper_syscall_hook(uint64_t x0,
                                 uint64_t x1,
                                 uint64_t x2,
                                 uint64_t x3,
                                 uint64_t x4,
                                 uint64_t x5,
                                 uint64_t x6,
                                 uint64_t x7) {
	static volatile int in_hook = 0;
	if (__sync_lock_test_and_set(&in_hook, 1)) {
		return;
	}

	const uint64_t counter = __atomic_fetch_add(&rosetta_helper_syscall_counter, 1, __ATOMIC_RELAXED);
	if (counter < 1024) {
		char buf[256];
		size_t pos = 0;
		pos = append_str(buf, pos, "[helper_hook] svc=");
		pos = append_hex_n(buf, pos, (uint32_t)x0, 8);
		pos = append_str(buf, pos, " rcx=");
		pos = append_hex_n(buf, pos, x1, 16);
		pos = append_str(buf, pos, " rdx=");
		pos = append_hex_n(buf, pos, x2, 16);
		pos = append_str(buf, pos, " rbx=");
		pos = append_hex_n(buf, pos, x3, 16);
		pos = append_str(buf, pos, " rsp=");
		pos = append_hex_n(buf, pos, x4, 16);
		pos = append_str(buf, pos, " rbp=");
		pos = append_hex_n(buf, pos, x5, 16);
		pos = append_str(buf, pos, " rsi=");
		pos = append_hex_n(buf, pos, x6, 16);
		pos = append_str(buf, pos, " rdi=");
		pos = append_hex_n(buf, pos, x7, 16);
		buf[pos++] = '\n';
		sys_write(2, buf, pos);
	} else if (counter == 1024) {
		static const char msg[] = "[helper_hook] output suppressed after 1024 calls\n";
		sys_write(2, msg, sizeof(msg) - 1);
	}
	__sync_lock_release(&in_hook);
}
