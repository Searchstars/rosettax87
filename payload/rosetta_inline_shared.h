#ifndef ROSETTA_INLINE_SHARED_H
#define ROSETTA_INLINE_SHARED_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROSETTA_INLINE_STATE_MAGIC   UINT64_C(0x524f535441544553) /* "ROSTATES" */
#define ROSETTA_INLINE_STATE_VERSION 1u

#define ROSETTA_INLINE_STATE_ADDR_MARKER UINT64_C(0x8a7b6c5d4e3f2a19)
#define ROSETTA_INLINE_WINE_ADDR_MARKER  UINT64_C(0x192a3b4c5d6e7f8a)

#define ROSETTA_WINE_CONTROL_MAGIC0  UINT64_C(0x57524f5345545441) /* "WROSETTA" */
#define ROSETTA_WINE_CONTROL_MAGIC1  UINT64_C(0x57494e45434f4e54) /* "WINECONT" */
#define ROSETTA_WINE_CONTROL_VERSION 1u

typedef struct {
	uint64_t key;
	uint64_t value;
} rosetta_inline_map_entry;

typedef struct {
	uint64_t magic;
	uint32_t version;
	uint32_t initialized;
	uint32_t lock;
	uint32_t reserved;
	uint64_t map_capacity;
	uint64_t map_count;
	uint64_t list_capacity;
	uint64_t list_count;
} rosetta_inline_state_header;

typedef struct {
	uint64_t magic0;
	uint64_t magic1;
	uint32_t version;
	uint32_t size;
	uint64_t main_image_base;
	uint64_t main_image_size;
	uint64_t exception_pending;
	uint64_t exception_x86_addr;
	uint64_t exception_arm_pc;
} rosetta_wine_control;

#ifdef __cplusplus
}
#endif

#endif
