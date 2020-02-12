#include "loader2.h"
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <set>
#include "dependencies.h"
namespace loader2
{
    std::set<std::string> s_paths;
    namespace fs = std::filesystem;
    inline std::string moduleName(HMODULE hModule)
    {
        char buffer[MAX_PATH];
        int size = GetModuleFileNameA(hModule, buffer, MAX_PATH);
        return buffer;
    }
    void loadModule(std::string path, Data datas)
    {
        std::cout << datas.indent << path << ": ";
        auto hModule = LoadLibraryA(path.c_str());
        if (hModule)
        {
            std::cout << datas.indent << "OK : ";
            auto path = moduleName(hModule);
            std::cout << path << "\n";
        }
        else
        {
            std::cout << datas.indent << "NOK : erreur " << GetLastError();
            if (fs::exists(fs::path(path)))
            {
                std::cout << std::endl;
                auto tDeps = parse_pe_import_table_names(path);
                for (auto& deps : tDeps)
                {
                    Data d = datas;
                    ++d.depth;
                    d.indent = std::string(d.depth, '\t');
                    loadModule(deps, d);
                }
            }
            else
                std::cout << " (not found)\n";
        }
    }
    void showDeps(std::string path, Data datas)
    {
        
        if (datas.depth==0)
            std::cout << datas.indent << path << std::endl;
        if (fs::exists(fs::path(path)))
        {
            s_paths.insert(path);
            auto tDeps = parse_pe_import_table_names(path);
            for (auto& deps : tDeps)
            {
                auto hModule = LoadLibraryA(deps.c_str());
                if (hModule)
                {
                    std::string depsPath = moduleName(hModule);
                    Data d = datas;
                    ++d.depth;
                    d.indent = std::string(d.depth, '\t');
                    std::cout << d.indent << deps << '(' << depsPath << ") ";
                    if (s_paths.find(depsPath)!=s_paths.end())
                    {
                        std::cout << "(already loaded, pass...)" << std::endl;
                        continue;
                    }
                    std::cout << std::endl;
                    showDeps(depsPath, d);
                }
                else 
                {
                    std::cout << datas.indent <<'\t' << deps <<" (not found or unable to load)"<< std::endl;
                }
            }
        }
    }
}