#pragma once
#include "Common.h"
#include <string>
namespace loader2
{
    void loadModule(std::string path, Data datas);
    void showDeps(std::string path, Data datas);
}