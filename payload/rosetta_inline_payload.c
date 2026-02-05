#include <stdint.h>
#include <stddef.h>

#include "rosetta_inline_shared.h"

#define ROSETTA_INLINE_INVALID_ADDR UINT64_C(0xffffffffffffffff)
#define ROSETTA_INLINE_MIN_PTR      UINT64_C(0x0000000100000000)
#define ROSETTA_INLINE_MAX_PTR      UINT64_C(0x00007fffffffffff)

#define ROSETTA_ENCODE_MOVZ(reg, imm16, shift) \
	(0xD2800000u | ((uint32_t)(imm16) << 5) | \
	 (((uint32_t)(((shift) / 16u) & 0x3u)) << 21) | ((uint32_t)(reg) & 0x1fu))

#define ROSETTA_ENCODE_MOVK(reg, imm16, shift) \
	(0xF2800000u | ((uint32_t)(imm16) << 5) | \
	 (((uint32_t)(((shift) / 16u) & 0x3u)) << 21) | ((uint32_t)(reg) & 0x1fu))

static inline uint64_t rosetta_inline_state_addr_raw(void) {
#if defined(__aarch64__)
	uint64_t value = 0;
	__asm__ volatile(
		".inst %1\n"
		".inst %2\n"
		".inst %3\n"
		".inst %4\n"
		"mov %0, x15\n"
		: "=r"(value)
		: "i"(ROSETTA_ENCODE_MOVZ(15, (uint16_t)(ROSETTA_INLINE_STATE_ADDR_MARKER & 0xffffu), 0)),
		  "i"(ROSETTA_ENCODE_MOVK(15, (uint16_t)((ROSETTA_INLINE_STATE_ADDR_MARKER >> 16) & 0xffffu), 16)),
		  "i"(ROSETTA_ENCODE_MOVK(15, (uint16_t)((ROSETTA_INLINE_STATE_ADDR_MARKER >> 32) & 0xffffu), 32)),
		  "i"(ROSETTA_ENCODE_MOVK(15, (uint16_t)((ROSETTA_INLINE_STATE_ADDR_MARKER >> 48) & 0xffffu), 48)));
	return value;
#else
	return 0;
#endif
}

static inline uint64_t rosetta_inline_wine_addr_raw(void) {
#if defined(__aarch64__)
	uint64_t value = 0;
	__asm__ volatile(
		".inst %1\n"
		".inst %2\n"
		".inst %3\n"
		".inst %4\n"
		"mov %0, x15\n"
		: "=r"(value)
		: "i"(ROSETTA_ENCODE_MOVZ(15, (uint16_t)(ROSETTA_INLINE_WINE_ADDR_MARKER & 0xffffu), 0)),
		  "i"(ROSETTA_ENCODE_MOVK(15, (uint16_t)((ROSETTA_INLINE_WINE_ADDR_MARKER >> 16) & 0xffffu), 16)),
		  "i"(ROSETTA_ENCODE_MOVK(15, (uint16_t)((ROSETTA_INLINE_WINE_ADDR_MARKER >> 32) & 0xffffu), 32)),
		  "i"(ROSETTA_ENCODE_MOVK(15, (uint16_t)((ROSETTA_INLINE_WINE_ADDR_MARKER >> 48) & 0xffffu), 48)));
	return value;
#else
	return 0;
#endif
}

static inline uint64_t rosetta_inline_state_addr(void) {
	const uint64_t addr = rosetta_inline_state_addr_raw();
	if (addr < ROSETTA_INLINE_MIN_PTR || addr > ROSETTA_INLINE_MAX_PTR) {
		return 0;
	}
	return addr;
}

static inline uint64_t rosetta_inline_wine_addr(void) {
	const uint64_t addr = rosetta_inline_wine_addr_raw();
	if (addr < ROSETTA_INLINE_MIN_PTR || addr > ROSETTA_INLINE_MAX_PTR) {
		return 0;
	}
	return addr;
}

static inline rosetta_inline_state_header *rosetta_inline_state(void) {
	const uint64_t addr = rosetta_inline_state_addr();
	if (!addr) {
		return NULL;
	}
	rosetta_inline_state_header *state = (rosetta_inline_state_header *)(uintptr_t)addr;
	if (state->magic != ROSETTA_INLINE_STATE_MAGIC ||
	    state->version != ROSETTA_INLINE_STATE_VERSION ||
	    state->initialized == 0) {
		return NULL;
	}
	return state;
}

static inline rosetta_wine_control *rosetta_wine_ctrl(void) {
	const uint64_t addr = rosetta_inline_wine_addr();
	if (!addr) {
		return NULL;
	}
	rosetta_wine_control *ctrl = (rosetta_wine_control *)(uintptr_t)addr;
	if (ctrl->magic0 != ROSETTA_WINE_CONTROL_MAGIC0 ||
	    ctrl->magic1 != ROSETTA_WINE_CONTROL_MAGIC1 ||
	    ctrl->version != ROSETTA_WINE_CONTROL_VERSION) {
		return NULL;
	}
	return ctrl;
}

static inline rosetta_inline_map_entry *rosetta_inline_map(rosetta_inline_state_header *state) {
	return (rosetta_inline_map_entry *)((uint8_t *)state + sizeof(*state));
}

static inline uint64_t *rosetta_inline_list(rosetta_inline_state_header *state) {
	rosetta_inline_map_entry *map = rosetta_inline_map(state);
	return (uint64_t *)(map + state->map_capacity);
}

static inline void rosetta_inline_spin_lock(uint32_t *lock) {
	while (__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE)) {
		__asm__ volatile("yield" ::: "memory");
	}
}

static inline void rosetta_inline_spin_unlock(uint32_t *lock) {
	__atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

static inline uint64_t rosetta_inline_hash(uint64_t value) {
	value ^= value >> 33;
	value *= UINT64_C(0xff51afd7ed558ccd);
	value ^= value >> 33;
	value *= UINT64_C(0xc4ceb9fe1a85ec53);
	value ^= value >> 33;
	return value;
}

static inline uint64_t rosetta_inline_map_find(rosetta_inline_map_entry *entries,
                                               uint64_t capacity,
                                               uint64_t key) {
	if (!key || capacity == 0) {
		return ROSETTA_INLINE_INVALID_ADDR;
	}
	const uint64_t mask = capacity - 1;
	uint64_t index = rosetta_inline_hash(key) & mask;
	for (uint64_t probe = 0; probe < capacity; ++probe) {
		const uint64_t slot = entries[index].key;
		if (!slot) {
			return ROSETTA_INLINE_INVALID_ADDR;
		}
		if (slot == key) {
			return entries[index].value;
		}
		index = (index + 1) & mask;
	}
	return ROSETTA_INLINE_INVALID_ADDR;
}

static inline void rosetta_inline_map_insert(rosetta_inline_state_header *state,
                                             rosetta_inline_map_entry *entries,
                                             uint64_t key,
                                             uint64_t value) {
	if (!key || !value || state->map_capacity == 0) {
		return;
	}
	const uint64_t mask = state->map_capacity - 1;
	uint64_t index = rosetta_inline_hash(key) & mask;
	for (uint64_t probe = 0; probe < state->map_capacity; ++probe) {
		if (entries[index].key == 0) {
			entries[index].key = key;
			entries[index].value = value;
			state->map_count++;
			return;
		}
		if (entries[index].key == key) {
			entries[index].value = value;
			return;
		}
		index = (index + 1) & mask;
	}
}

static inline void rosetta_inline_memmove_u64(uint64_t *dst, const uint64_t *src, uint64_t count) {
	if (dst == src || count == 0) {
		return;
	}
	if (dst < src) {
		for (uint64_t i = 0; i < count; ++i) {
			dst[i] = src[i];
		}
		return;
	}
	for (uint64_t i = count; i > 0; --i) {
		dst[i - 1] = src[i - 1];
	}
}

static inline void rosetta_inline_list_insert(rosetta_inline_state_header *state,
                                              uint64_t *list,
                                              uint64_t value) {
	if (!value || state->list_capacity == 0 || state->list_count >= state->list_capacity) {
		return;
	}
	if (state->list_count == 0) {
		list[state->list_count++] = value;
		return;
	}
	if (value > list[state->list_count - 1]) {
		list[state->list_count++] = value;
		return;
	}
	// 非单调递增时直接忽略，避免 O(n^2) 插入开销导致卡死。
	if (value == list[state->list_count - 1]) {
		return;
	}
}

static inline uint64_t rosetta_inline_list_floor(const uint64_t *list,
                                                 uint64_t count,
                                                 uint64_t value) {
	if (!count) {
		return ROSETTA_INLINE_INVALID_ADDR;
	}
	uint64_t lo = 0;
	uint64_t hi = count;
	while (lo < hi) {
		const uint64_t mid = lo + ((hi - lo) >> 1);
		if (list[mid] <= value) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	if (!lo) {
		return ROSETTA_INLINE_INVALID_ADDR;
	}
	return list[lo - 1];
}

static inline uint64_t rosetta_inline_guess_x86(uint64_t a, uint64_t b) {
	if (a >= ROSETTA_INLINE_MIN_PTR && a <= ROSETTA_INLINE_MAX_PTR) {
		return a;
	}
	if (b >= ROSETTA_INLINE_MIN_PTR && b <= ROSETTA_INLINE_MAX_PTR) {
		return b;
	}
	return a ? a : b;
}

static inline void rosetta_inline_trigger_segv(void) {
	__asm__ volatile("" ::: "memory");
	volatile uint64_t *bad = (volatile uint64_t *)0;
	*bad = 0;
}

__attribute__((used, noinline))
uint64_t rosetta_helper_resolve_inline(char *scratch,
                                       uint64_t arg0,
                                       uint64_t arg1,
                                       uint64_t arg2,
                                       uint64_t arg3,
                                       uint64_t arg4,
                                       uint64_t arg5,
                                       uint64_t ret_addr) {
	(void)scratch;
	(void)arg0;
	(void)arg3;
	(void)arg4;
	(void)arg5;

	rosetta_inline_state_header *state = rosetta_inline_state();
	if (!state) {
		return ret_addr;
	}

	const uint64_t x86_addr = rosetta_inline_guess_x86(arg1, arg2);
	if (!x86_addr || !ret_addr) {
		return ret_addr;
	}

	rosetta_inline_spin_lock(&state->lock);
	rosetta_inline_map_entry *map = rosetta_inline_map(state);
	uint64_t *list = rosetta_inline_list(state);
	rosetta_inline_list_insert(state, list, ret_addr);
	rosetta_inline_map_insert(state, map, ret_addr, x86_addr);
	const uint64_t map_count = state->map_count;
	const uint64_t list_count = state->list_count;
	rosetta_inline_spin_unlock(&state->lock);

	rosetta_wine_control *wine = rosetta_wine_ctrl();
	if (wine) {
		__atomic_store_n(&wine->map_write_count, map_count, __ATOMIC_RELAXED);
		__atomic_store_n(&wine->list_write_count, list_count, __ATOMIC_RELAXED);
		__atomic_store_n(&wine->last_x86_addr, x86_addr, __ATOMIC_RELAXED);
		__atomic_store_n(&wine->last_arm_pc, ret_addr, __ATOMIC_RELAXED);
	}
	return ret_addr;
}

__attribute__((used, noinline))
uint64_t rosetta_helper_syscall_inline(char *scratch,
                                       uint64_t arg0,
                                       uint64_t arg1,
                                       uint64_t arg2,
                                       uint64_t arg3,
                                       uint64_t arg4,
                                       uint64_t arg5,
                                       uint64_t ret_addr) {
	(void)scratch;
	(void)arg0;
	(void)arg1;
	(void)arg2;
	(void)arg3;
	(void)arg4;
	(void)arg5;

	rosetta_inline_state_header *state = rosetta_inline_state();
	if (!state) {
		return 0;
	}

	const uint64_t pc = ret_addr;
	if (!pc) {
		return 0;
	}

	rosetta_inline_spin_lock(&state->lock);
	rosetta_inline_map_entry *map = rosetta_inline_map(state);
	uint64_t *list = rosetta_inline_list(state);
	const uint64_t base = rosetta_inline_list_floor(list, state->list_count, pc);
	const uint64_t x86_addr = (base == ROSETTA_INLINE_INVALID_ADDR)
		? ROSETTA_INLINE_INVALID_ADDR
		: rosetta_inline_map_find(map, state->map_capacity, base);
	rosetta_inline_spin_unlock(&state->lock);

	if (x86_addr == ROSETTA_INLINE_INVALID_ADDR) {
		return 0;
	}

	rosetta_wine_control *wine = rosetta_wine_ctrl();
	if (!wine) {
		return 0;
	}

	const uint64_t base_addr = wine->main_image_base;
	const uint64_t size = wine->main_image_size;
	if (!base_addr) {
		return 0;
	}
	if (x86_addr < base_addr) {
		return 0;
	}
	if (size && x86_addr >= base_addr + size) {
		return 0;
	}

	wine->exception_x86_addr = x86_addr;
	wine->exception_arm_pc = pc;
	__atomic_store_n(&wine->exception_pending, 1, __ATOMIC_RELEASE);
	rosetta_inline_trigger_segv();
	return 0;
}
