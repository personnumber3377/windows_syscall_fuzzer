#include "FuzzRunner.h"
#include "InputReader.h"
#include "ResourceManager.h"
#include <iostream>
#include <vector>

int wmain(int argc, wchar_t** argv) {
    if(argc!=2){ std::wcerr<<L"usage: win_resource_fuzzer.exe testcase.bin\n"; return 1; }
    std::vector<std::uint8_t> data;
    if(!InputReader::LoadFile(argv[1],data)){ std::wcerr<<L"failed to read input\n"; return 2; }
    ResourceManager resources;
    if(!resources.Initialize()){ std::cerr<<"resource initialization failed\n"; return 3; }
    std::cout<<"DCs="<<resources.DCCount()<<" bitmaps="<<resources.BitmapCount()
             <<" files="<<resources.FileCount()<<" events="<<resources.EventCount()<<"\n";
    FuzzRunner runner(resources);
    bool ok=runner.Run(data.data(),data.size());
    std::cout<<(ok?"complete":"truncated")<<"\n";
    return 0;
}
