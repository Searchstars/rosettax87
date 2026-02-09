#pragma once

#include <cstdint>

struct OffsetFinder {
	auto setDefaultOffsets() -> void;
	auto determineOffsets() -> bool;

	std::uint64_t offsetExportsFetch_ = 0;
	std::uint64_t offsetSvcCallEntry_ = 0;
	std::uint64_t offsetSvcCallRet_ = 0;
};

