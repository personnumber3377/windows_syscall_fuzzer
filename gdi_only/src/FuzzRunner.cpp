#include "FuzzRunner.h"
#include <algorithm>
#include <array>
#include <span>
#include <vector>

bool FuzzRunner::Run(const std::uint8_t* data, std::size_t size) { InputReader in(data,size); return Run(in); }

bool FuzzRunner::Run(InputReader& in) {
    for (std::size_t n=0; n<1024 && !in.Empty(); ++n) {
        std::uint8_t raw=0; if (!in.ReadU8(raw)) return false;
        auto op=static_cast<Opcode>(raw); if (op==Opcode::Stop) return true;
        if (!Execute(op,in)) return false;
    }
    return true;
}

bool FuzzRunner::Execute(Opcode op, InputReader& in) {
    std::size_t a=0,b=0,c=0; std::uint32_t x=0,y=0,w=0,h=0,len=0,rop=0;
    switch(op) {
    case Opcode::SelectBitmap:
        if(!in.ReadIndex(resources_.DCCount(),a)||!in.ReadIndex(resources_.BitmapCount(),b)) return false;
        SelectObject(resources_.GetDC(a),resources_.GetBitmap(b)); return true;
    case Opcode::SelectBrush:
        if(!in.ReadIndex(resources_.DCCount(),a)||!in.ReadIndex(resources_.BrushCount(),b)) return false;
        SelectObject(resources_.GetDC(a),resources_.GetBrush(b)); return true;
    case Opcode::SelectPen:
        if(!in.ReadIndex(resources_.DCCount(),a)||!in.ReadIndex(resources_.PenCount(),b)) return false;
        SelectObject(resources_.GetDC(a),resources_.GetPen(b)); return true;
    case Opcode::BitBlt: {
        if(!in.ReadIndex(resources_.DCCount(),a)||!in.ReadIndex(resources_.DCCount(),b)||
           !in.ReadU32(x)||!in.ReadU32(y)||!in.ReadU32(w)||!in.ReadU32(h)||!in.ReadU32(rop)) return false;
        static constexpr std::array<DWORD,6> rops{SRCCOPY,SRCAND,SRCPAINT,SRCINVERT,BLACKNESS,WHITENESS};
        BitBlt(resources_.GetDC(a),(int)x,(int)y,(int)w,(int)h,resources_.GetDC(b),0,0,rops[rop%rops.size()]); return true; }
    case Opcode::FillRegion:
        if(!in.ReadIndex(resources_.DCCount(),a)||!in.ReadIndex(resources_.RegionCount(),b)||!in.ReadIndex(resources_.BrushCount(),c)) return false;
        FillRgn(resources_.GetDC(a),resources_.GetRegion(b),resources_.GetBrush(c)); return true;
    case Opcode::SetBitmapBits: {
        if(!in.ReadIndex(resources_.BitmapCount(),a)||!in.ReadU32(len)) return false;
        len=(std::uint32_t)std::min<std::size_t>(len,std::min<std::size_t>(in.Remaining(),65536));
        std::span<const std::uint8_t> bytes; if(!in.ReadBytes(len,bytes)) return false;
        SetBitmapBits(resources_.GetBitmap(a),(DWORD)bytes.size(),bytes.data()); return true; }
    case Opcode::ReadFile: {
        if(!in.ReadIndex(resources_.FileCount(),a)||!in.ReadU32(len)) return false;
        len%=65537; std::vector<std::uint8_t> buf(len); DWORD got=0;
        ::ReadFile(resources_.GetFile(a),buf.data(),len,&got,nullptr); return true; }
    case Opcode::WriteFile: {
        if(!in.ReadIndex(resources_.FileCount(),a)||!in.ReadU32(len)) return false;
        len=(std::uint32_t)std::min<std::size_t>(len,std::min<std::size_t>(in.Remaining(),65536));
        std::span<const std::uint8_t> bytes; if(!in.ReadBytes(len,bytes)) return false; DWORD wrote=0;
        ::WriteFile(resources_.GetFile(a),bytes.data(),len,&wrote,nullptr); return true; }
    case Opcode::RewindFile:
        if(!in.ReadIndex(resources_.FileCount(),a)) return false;
        SetFilePointer(resources_.GetFile(a),0,nullptr,FILE_BEGIN); return true;
    case Opcode::SetEvent:
        if(!in.ReadIndex(resources_.EventCount(),a)) return false; ::SetEvent(resources_.GetEvent(a)); return true;
    case Opcode::ResetEvent:
        if(!in.ReadIndex(resources_.EventCount(),a)) return false; ::ResetEvent(resources_.GetEvent(a)); return true;
    case Opcode::MapView: {
        if(!in.ReadIndex(resources_.MappingCount(),a)||!in.ReadU32(x)||!in.ReadU32(len)) return false;
        x%=0x10000; len%=0x10001-x;
        void* p=MapViewOfFile(resources_.GetMapping(a),FILE_MAP_READ|FILE_MAP_WRITE,0,x,len);
        if(p){ if(len) static_cast<volatile std::uint8_t*>(p)[0]^=(std::uint8_t)x; UnmapViewOfFile(p); } return true; }
    default: return true;
    }
}
