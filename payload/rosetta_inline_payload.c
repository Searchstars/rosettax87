#include <stdint.h>
#include <stddef.h>

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

__attribute__((used, noinline))
uint64_t rosetta_helper_syscall_inline(char *out,
                                       uint64_t svc,
                                       uint64_t x0,
                                       uint64_t x1,
                                       uint64_t x2,
                                       uint64_t x3) {
	char *cursor = out;
	write_str(&cursor, "syscall svc=0x");
	write_hex16(&cursor, svc);

	write_str(&cursor, " x0=0x");
	write_hex16(&cursor, x0);

	write_str(&cursor, " x1=0x");
	write_hex16(&cursor, x1);

	write_str(&cursor, " x2=0x");
	write_hex16(&cursor, x2);

	write_str(&cursor, " x3=0x");
	write_hex16(&cursor, x3);

	return flush_line(out, cursor);
}

__attribute__((used, noinline))
uint64_t rosetta_helper_resolve_inline(char *out,
                                       uint64_t x0,
                                       uint64_t x1,
                                       uint64_t x2,
                                       uint64_t x3,
                                       uint64_t x4) {
	char *cursor = out;
	write_str(&cursor, "resolve x0=0x");
	write_hex16(&cursor, x0);

	write_str(&cursor, " x1=0x");
	write_hex16(&cursor, x1);

	write_str(&cursor, " x2=0x");
	write_hex16(&cursor, x2);

	write_str(&cursor, " x3=0x");
	write_hex16(&cursor, x3);

	write_str(&cursor, " x4=0x");
	write_hex16(&cursor, x4);

	return flush_line(out, cursor);
}
