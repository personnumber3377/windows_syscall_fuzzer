#include "InputReader.h"
#include <cstring>
#include <fstream>

InputReader::InputReader(const std::uint8_t* data, std::size_t size) noexcept
    : data_(data), size_(size), position_(0) {}

bool InputReader::Empty() const noexcept { return position_ >= size_; }
std::size_t InputReader::Remaining() const noexcept { return position_ <= size_ ? size_ - position_ : 0; }

bool InputReader::ReadU8(std::uint8_t& value) noexcept {
    if (Remaining() < 1) return false;
    value = data_[position_++];
    return true;
}

bool InputReader::ReadU32(std::uint32_t& value) noexcept {
    if (Remaining() < sizeof(value)) return false;
    std::memcpy(&value, data_ + position_, sizeof(value));
    position_ += sizeof(value);
    return true;
}

bool InputReader::ReadBytes(std::size_t count, std::span<const std::uint8_t>& value) noexcept {
    if (Remaining() < count) return false;
    value = {data_ + position_, count};
    position_ += count;
    return true;
}

bool InputReader::LoadFile(const std::wstring& path, std::vector<std::uint8_t>& output) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    const auto end = file.tellg();
    if (end < 0) return false;
    output.resize(static_cast<std::size_t>(end));
    file.seekg(0);
    if (!output.empty()) file.read(reinterpret_cast<char*>(output.data()), static_cast<std::streamsize>(output.size()));
    return !!file;
}
