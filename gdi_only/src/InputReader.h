#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

class InputReader final {
public:
    InputReader(const std::uint8_t* data, std::size_t size) noexcept;
    bool Empty() const noexcept;
    std::size_t Remaining() const noexcept;
    bool ReadU8(std::uint8_t& value) noexcept;
    bool ReadU32(std::uint32_t& value) noexcept;
    bool ReadBytes(std::size_t count, std::span<const std::uint8_t>& value) noexcept;

    template<class T>
    bool ReadIndex(std::size_t count, T& result) noexcept {
        static_assert(std::is_integral_v<T>);
        std::uint32_t raw = 0;
        if (count == 0 || !ReadU32(raw)) return false;
        result = static_cast<T>(raw % count);
        return true;
    }

    static bool LoadFile(const std::wstring& path, std::vector<std::uint8_t>& output);
private:
    const std::uint8_t* data_{};
    std::size_t size_{};
    std::size_t position_{};
};
