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

__attribute__((used, noinline))
uint64_t rosetta_helper_syscall_inline(char *out,
                                       uint64_t svc,
                                       uint64_t x0,
                                       uint64_t x1,
                                       uint64_t x2,
                                       uint64_t x3) {
	char *cursor = out;
	*cursor++ = '[';
	*cursor++ = 'h';
	*cursor++ = 'e';
	*cursor++ = 'l';
	*cursor++ = 'p';
	*cursor++ = 'e';
	*cursor++ = 'r';
	*cursor++ = '_';
	*cursor++ = 's';
	*cursor++ = 'y';
	*cursor++ = 's';
	*cursor++ = 'c';
	*cursor++ = 'a';
	*cursor++ = 'l';
	*cursor++ = 'l';
	*cursor++ = ']';
	*cursor++ = ' ';

	*cursor++ = 's';
	*cursor++ = 'v';
	*cursor++ = 'c';
	*cursor++ = '=';
	*cursor++ = '0';
	*cursor++ = 'x';
	write_hex16(&cursor, svc);

	*cursor++ = ' ';
	*cursor++ = 'x';
	*cursor++ = '0';
	*cursor++ = '=';
	*cursor++ = '0';
	*cursor++ = 'x';
	write_hex16(&cursor, x0);

	*cursor++ = ' ';
	*cursor++ = 'x';
	*cursor++ = '1';
	*cursor++ = '=';
	*cursor++ = '0';
	*cursor++ = 'x';
	write_hex16(&cursor, x1);

	*cursor++ = ' ';
	*cursor++ = 'x';
	*cursor++ = '2';
	*cursor++ = '=';
	*cursor++ = '0';
	*cursor++ = 'x';
	write_hex16(&cursor, x2);

	*cursor++ = ' ';
	*cursor++ = 'x';
	*cursor++ = '3';
	*cursor++ = '=';
	*cursor++ = '0';
	*cursor++ = 'x';
	write_hex16(&cursor, x3);

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
