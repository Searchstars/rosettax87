#pragma once

#include <iostream>
#include <cstdint>

struct OffsetFinder {
	auto setDefaultOffsets() -> void;
	auto determineOffsets() -> bool;

	std::uint64_t offsetHelperSyscall_;
	std::uint64_t offsetJitTranslate_;
};
