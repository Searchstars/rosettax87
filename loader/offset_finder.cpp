#include "offset_finder.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <optional>
#include <vector>

namespace {

auto readFile(const char *path) -> std::optional<std::vector<unsigned char>> {
	std::ifstream file(path, std::ios::binary);
	if (!file) return std::nullopt;

	file.seekg(0, std::ios::end);
	const auto size = file.tellg();
	if (size <= 0) return std::nullopt;
	file.seekg(0, std::ios::beg);

	std::vector<unsigned char> buffer(static_cast<size_t>(size));
	if (!file.read(reinterpret_cast<char *>(buffer.data()), buffer.size())) return std::nullopt;
	return buffer;
}

auto findFirst(const std::vector<unsigned char> &buffer, const std::vector<unsigned char> &pattern) -> std::optional<std::uint64_t> {
	if (pattern.empty() || buffer.size() < pattern.size()) return std::nullopt;
	const std::boyer_moore_searcher searcher(pattern.begin(), pattern.end());
	const auto it = std::search(buffer.begin(), buffer.end(), searcher);
	if (it == buffer.end()) return std::nullopt;
	return static_cast<std::uint64_t>(std::distance(buffer.begin(), it));
}

} // namespace

auto OffsetFinder::setDefaultOffsets() -> void {
	// Known-good offsets for an older macOS 26.0 Rosetta runtime build. These are only used
	// if the on-disk pattern scan succeeds, or if the user explicitly opts into defaults.
	offsetExportsFetch_ = 0xFA8C;
	offsetSvcCallEntry_ = 0x1998;
	offsetSvcCallRet_ = offsetSvcCallEntry_ + 0xC;
}

auto OffsetFinder::determineOffsets() -> bool {
	const auto bufferOpt = readFile("/usr/libexec/rosetta/runtime");
	if (!bufferOpt) {
		std::fprintf(stderr, "offset_finder: failed to read /usr/libexec/rosetta/runtime\n");
		return false;
	}
	const auto &buffer = *bufferOpt;

	// LDR X2, [X19,#8]; LDR W3, [X19,#0x10]
	const std::vector<unsigned char> exportsFetch = {0x62, 0x06, 0x40, 0xF9, 0x63, 0x12, 0x40, 0xB9};
	// MOV X16, #197; SVC 0x80; CSET X1, CS; RET
	const std::vector<unsigned char> svcCall = {0xB0, 0x18, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4,
	                                            0xE1, 0x37, 0x9F, 0x9A, 0xC0, 0x03, 0x5F, 0xD6};

	const auto fetch = findFirst(buffer, exportsFetch);
	const auto svc = findFirst(buffer, svcCall);

	if (!fetch || !svc) {
		std::fprintf(stderr, "offset_finder: pattern not found (exports_fetch=%d svc_call=%d)\n",
		             fetch.has_value() ? 1 : 0, svc.has_value() ? 1 : 0);
		return false;
	}

	offsetExportsFetch_ = *fetch;
	offsetSvcCallEntry_ = *svc;
	offsetSvcCallRet_ = offsetSvcCallEntry_ + 0xC;
	return true;
}

