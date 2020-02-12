#include <iostream>
#include <string>
#include <Windows.h>
#include "loader.h"
#include "loader2.h"


void display_help()
{
    std::cout << "DiagDyn [/show_deps] <module_path>" << std::endl;
}
int main(int argv, char** argc)
{
    using namespace std::string_view_literals;
    SetErrorMode(SEM_FAILCRITICALERRORS);
    Data datas;
    bool show_deps = false;
    std::string path;
    
    if (argv==1)
    {
        std::cerr << "Chemin vers le module nécessaire uniquement. " << std::endl;
        display_help();
        return 1;
    }
    for (int i=1;i<argv;++i)
    {
        if (argc[i]=="/show_deps"sv)
            show_deps=true;
        else
            path=argc[i];
    }
    if (!show_deps)
        loader2::loadModule(path, datas);
    else
        loader2::showDeps(path, datas);
#ifdef _DEBUG
    system("PAUSE");
#endif
    return 0;
}