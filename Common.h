#pragma once
#include <string>
struct Data
{
    // arguments
    int maxdepth=2;
    bool showDeps=0;
    
    // variables
    int depth=0;
    std::string indent;
    std::string current_path;
};