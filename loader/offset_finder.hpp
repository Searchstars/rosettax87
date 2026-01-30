#pragma once

#include <iostream>

struct OffsetFinder {
	auto setDefaultOffsets() -> void;
	auto determineOffsets() -> bool;

	std::uint64_t offsetHelperSyscall_;
	std::uint64_t offsetHelperResolveAddr_;
};
