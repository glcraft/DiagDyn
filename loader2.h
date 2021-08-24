#pragma once
#include "Common.h"
namespace loader2
{
    void load_module(std::filesystem::path module_path, InterfaceData datas);
    void show_dependences(std::filesystem::path module_path, InterfaceData datas);
}