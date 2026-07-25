#include "FuzzRunner.h"
#include "ResourceManager.h"
#include <cstddef>
#include <cstdint>

static ResourceManager g_resources;
static FuzzRunner* g_runner=nullptr;

bool InitializeBeforeWtfSnapshot() {
    if(!g_resources.Initialize()) return false;
    static FuzzRunner runner(g_resources);
    g_runner=&runner;
    return true;
}

bool ExecuteWtfInput(const std::uint8_t* data, std::size_t size) {
    return g_runner && g_runner->Run(data,size);
}
