#include "offset_finder.hpp"

#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {
	auto parsePattern(const char *pattern) -> std::vector<int> {
		std::vector<int> bytes;
		std::istringstream stream(pattern);
		std::string token;
		while (stream >> token) {
			if (token.find('?') != std::string::npos) {
				bytes.push_back(-1);
				continue;
			}
			bytes.push_back(std::stoi(token, nullptr, 16));
		}
		return bytes;
	}

	auto findPattern(const std::vector<unsigned char> &buffer, const std::vector<int> &pattern) -> std::optional<std::uint64_t> {
		if (pattern.empty() || buffer.size() < pattern.size()) {
			return std::nullopt;
		}
		for (size_t i = 0; i + pattern.size() <= buffer.size(); ++i) {
			bool matched = true;
			for (size_t j = 0; j < pattern.size(); ++j) {
				const int byte = pattern[j];
				if (byte >= 0 && buffer[i + j] != static_cast<unsigned char>(byte)) {
					matched = false;
					break;
				}
			}
			if (matched) {
				return static_cast<std::uint64_t>(i);
			}
		}
		return std::nullopt;
	}
}

auto OffsetFinder::setDefaultOffsets() -> void {
	offsetHelperSyscall_ = 0;
	offsetHelperResolveAddr_ = 0;
}

auto OffsetFinder::determineOffsets() -> bool {
	const auto helperSyscallPattern = parsePattern(
		"17 08 08 12 F7 7E 18 53 FF 06 00 71 ?? ?? ?? ?? FF 0A 00 71 ?? ?? ?? ?? FF 0E 00 71");
	const auto helperResolvePattern = parsePattern(
		"FF 03 01 D1 F6 57 01 A9 F4 4F 02 A9 FD 7B 03 A9 FD C3 00 91 ?? ?? ?? ?? "
		"1F 05 00 71 ?? ?? ?? ?? F3 03 02 AA F4 03 01 AA ?? ?? ?? ?? ?? ?? ?? ?? "
		"?? ?? ?? ?? ?? ?? ?? ?? E0 03 16 AA 03 00 80 D2");

	std::ifstream file{"/usr/libexec/rosetta/runtime", std::ios::binary};
	if (!file) {
		fprintf(stderr, "Problem accessing rosetta runtime to determine helper offsets automatically.\n");
		return false;
	}

	file.seekg(0, std::ios::end);
	const std::streampos size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<unsigned char> buffer(static_cast<size_t>(size));
	if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
		fprintf(stderr, "Problem reading rosetta runtime to determine helper offsets automatically.\n");
		return false;
	}

	const auto helperSyscallOffset = findPattern(buffer, helperSyscallPattern);
	const auto helperResolveOffset = findPattern(buffer, helperResolvePattern);

	if (!helperSyscallOffset || !helperResolveOffset) {
		fprintf(stderr, "Helper patterns not found in rosetta runtime binary.\n");
		return false;
	}

	offsetHelperSyscall_ = *helperSyscallOffset;
	offsetHelperResolveAddr_ = *helperResolveOffset;
	return true;
}
