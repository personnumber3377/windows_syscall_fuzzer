#pragma once
#include "InputReader.h"
#include "ResourceManager.h"
#include <cstddef>
#include <cstdint>

enum class Opcode : std::uint8_t {
    Stop=0x00, SelectBitmap=0x10, SelectBrush=0x11, SelectPen=0x12,
    BitBlt=0x13, FillRegion=0x14, SetBitmapBits=0x15,
    ReadFile=0x20, WriteFile=0x21, RewindFile=0x22,
    SetEvent=0x30, ResetEvent=0x31, MapView=0x40
};

class FuzzRunner final {
public:
    explicit FuzzRunner(ResourceManager& r) noexcept : resources_(r) {}
    bool Run(const std::uint8_t* data, std::size_t size);
    bool Run(InputReader& input);
private:
    bool Execute(Opcode op, InputReader& in);
    ResourceManager& resources_;
};
