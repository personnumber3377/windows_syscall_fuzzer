#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstddef>
#include <string>
#include <vector>

class ResourceManager final {
public:
    ~ResourceManager();
    bool Initialize();
    void Destroy() noexcept;

    HDC GetDC(std::size_t i) const noexcept;
    HBITMAP GetBitmap(std::size_t i) const noexcept;
    HBRUSH GetBrush(std::size_t i) const noexcept;
    HPEN GetPen(std::size_t i) const noexcept;
    HRGN GetRegion(std::size_t i) const noexcept;
    HANDLE GetFile(std::size_t i) const noexcept;
    HANDLE GetEvent(std::size_t i) const noexcept;
    HANDLE GetMapping(std::size_t i) const noexcept;

    std::size_t DCCount() const noexcept { return dcs_.size(); }
    std::size_t BitmapCount() const noexcept { return bitmaps_.size(); }
    std::size_t BrushCount() const noexcept { return brushes_.size(); }
    std::size_t PenCount() const noexcept { return pens_.size(); }
    std::size_t RegionCount() const noexcept { return regions_.size(); }
    std::size_t FileCount() const noexcept { return files_.size(); }
    std::size_t EventCount() const noexcept { return events_.size(); }
    std::size_t MappingCount() const noexcept { return mappings_.size(); }

private:
    template<class T> static T Pick(const std::vector<T>& v, std::size_t i) noexcept {
        return v.empty() ? nullptr : v[i % v.size()];
    }
    bool InitGdi();
    bool InitKernelObjects();

    std::vector<HDC> dcs_;
    std::vector<HBITMAP> bitmaps_;
    std::vector<HBRUSH> brushes_;
    std::vector<HPEN> pens_;
    std::vector<HRGN> regions_;
    std::vector<HANDLE> files_;
    std::vector<HANDLE> events_;
    std::vector<HANDLE> mappings_;
    std::wstring scratchPath_;
};
