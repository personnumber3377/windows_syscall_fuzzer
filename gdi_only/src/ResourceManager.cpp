#include "ResourceManager.h"
#include <array>

namespace {
template<class T> void DeleteGdi(std::vector<T>& v) noexcept {
    for (auto h : v) if (h) DeleteObject(h);
    v.clear();
}
void CloseAll(std::vector<HANDLE>& v) noexcept {
    for (auto h : v) if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    v.clear();
}
}

ResourceManager::~ResourceManager() { Destroy(); }

bool ResourceManager::Initialize() {
    Destroy();
    if (!InitGdi() || !InitKernelObjects()) { Destroy(); return false; }
    return true;
}

bool ResourceManager::InitGdi() {
    HDC screen = GetDC(nullptr);
    if (!screen) return false;

    for (int i=0;i<3;i++) if (HDC dc=CreateCompatibleDC(screen)) dcs_.push_back(dc);
    for (SIZE s : std::array<SIZE,5>{{{1,1},{8,8},{32,32},{64,64},{256,256}}}) {
        if (HBITMAP b=CreateCompatibleBitmap(screen,s.cx,s.cy)) bitmaps_.push_back(b);
    }
    if (HBITMAP b=CreateBitmap(64,64,1,1,nullptr)) bitmaps_.push_back(b);

    BITMAPINFO bi{};
    bi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth=64;
    bi.bmiHeader.biHeight=-64;
    bi.bmiHeader.biPlanes=1;
    bi.bmiHeader.biBitCount=32;
    bi.bmiHeader.biCompression=BI_RGB;
    void* bits=nullptr;
    if (HBITMAP b=CreateDIBSection(screen,&bi,DIB_RGB_COLORS,&bits,nullptr,0)) bitmaps_.push_back(b);

    for (COLORREF c : std::array<COLORREF,5>{RGB(0,0,0),RGB(255,255,255),RGB(255,0,0),RGB(0,255,0),RGB(0,0,255)}) {
        if (HBRUSH b=CreateSolidBrush(c)) brushes_.push_back(b);
        if (HPEN p=CreatePen(PS_SOLID,1,c)) pens_.push_back(p);
    }
    if (HRGN r=CreateRectRgn(0,0,32,32)) regions_.push_back(r);
    if (HRGN r=CreateEllipticRgn(0,0,64,64)) regions_.push_back(r);
    if (HRGN r=CreateRoundRectRgn(0,0,128,64,8,8)) regions_.push_back(r);

    if (!dcs_.empty() && !bitmaps_.empty()) SelectObject(dcs_[0],bitmaps_[0]);
    if (dcs_.size()>1 && bitmaps_.size()>1) SelectObject(dcs_[1],bitmaps_[1]);
    ReleaseDC(nullptr,screen);
    return !dcs_.empty() && !bitmaps_.empty() && !brushes_.empty() && !pens_.empty() && !regions_.empty();
}

bool ResourceManager::InitKernelObjects() {
    wchar_t dir[MAX_PATH]{}, path[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH,dir) || !GetTempFileNameW(dir,L"WTF",0,path)) return false;
    HANDLE f=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,nullptr);
    if (f==INVALID_HANDLE_VALUE) return false;
    scratchPath_=path; files_.push_back(f);

    if (HANDLE n=CreateFileW(L"NUL",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
        n!=INVALID_HANDLE_VALUE) files_.push_back(n);
    if (HANDLE e=CreateEventW(nullptr,TRUE,FALSE,nullptr)) events_.push_back(e);
    if (HANDLE e=CreateEventW(nullptr,FALSE,TRUE,nullptr)) events_.push_back(e);
    if (HANDLE m=CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,0x10000,nullptr)) mappings_.push_back(m);
    return !files_.empty() && !events_.empty() && !mappings_.empty();
}

void ResourceManager::Destroy() noexcept {
    for (auto dc:dcs_) if (dc) DeleteDC(dc);
    dcs_.clear();
    DeleteGdi(bitmaps_); DeleteGdi(brushes_); DeleteGdi(pens_); DeleteGdi(regions_);
    CloseAll(mappings_); CloseAll(events_); CloseAll(files_);
    if (!scratchPath_.empty()) { DeleteFileW(scratchPath_.c_str()); scratchPath_.clear(); }
}

HDC ResourceManager::GetDC(std::size_t i) const noexcept { return Pick(dcs_,i); }
HBITMAP ResourceManager::GetBitmap(std::size_t i) const noexcept { return Pick(bitmaps_,i); }
HBRUSH ResourceManager::GetBrush(std::size_t i) const noexcept { return Pick(brushes_,i); }
HPEN ResourceManager::GetPen(std::size_t i) const noexcept { return Pick(pens_,i); }
HRGN ResourceManager::GetRegion(std::size_t i) const noexcept { return Pick(regions_,i); }
HANDLE ResourceManager::GetFile(std::size_t i) const noexcept { return Pick(files_,i); }
HANDLE ResourceManager::GetEvent(std::size_t i) const noexcept { return Pick(events_,i); }
HANDLE ResourceManager::GetMapping(std::size_t i) const noexcept { return Pick(mappings_,i); }
