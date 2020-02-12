#include <iostream>
#include <filesystem>
#include <Windows.h>
#include <vector>
#include <sstream>
#include <iterator>
#include <string>
#include "dependencies.h"
#include "loader.h"

namespace loader
{
    namespace fs = std::filesystem;

    template <char delimiter>
    class WordDelimitedBy : public std::string
    {
    };
    template <char delimiter>
    std::istream &operator>>(std::istream &is, WordDelimitedBy<delimiter> &output)
    {
        std::getline(is, output, delimiter);
        return is;
    }
    template <char delimiter>
    inline std::vector<std::string> split(std::string text)
    {
        std::istringstream iss(text);
        return std::vector<std::string>(std::istream_iterator<WordDelimitedBy<delimiter>>(iss),
                                        std::istream_iterator<WordDelimitedBy<delimiter>>());
    }

    static std::vector<std::string> pathEnv;

    void loadModule(std::string path, Data datas);
    fs::path findDependency(std::string path);
    std::string getCurrentAppFile()
    {
        char buffer[MAX_PATH];
        int size = GetModuleFileNameA(0, buffer, MAX_PATH);
        return buffer;
    }
    fs::path findDependency(std::string deps, std::string current_path)
    {
        //https://docs.microsoft.com/fr-fr/windows/win32/api/winbase/nf-winbase-setdlldirectorya
        int size = 0;
        // 1. The directory from which the application loaded.
        fs::path appFile = current_path;
        fs::path appDir = appFile.parent_path();
        if (fs::exists(appDir / deps))
            return appDir / deps;
        // 2. The directory specified by the lpPathName parameter.
        size = GetDllDirectoryA(0, nullptr) - 1;
        if (size)
        {
            std::string dllPath(size, ' ');
            GetDllDirectoryA(dllPath.size(), (char *)dllPath.data());
            fs::path dllDir(dllPath);
            if (fs::exists(dllDir / deps))
                return dllDir / deps;
        }
        // 3. The system directory. Use the GetSystemDirectory function to get the path of this directory. The name of this directory is System32.
        size = GetSystemDirectoryA(nullptr, 0) - 1;
        if (size)
        {
            std::string sys32Path(size, ' ');
            GetSystemDirectoryA((char *)sys32Path.data(), size + 1);
            fs::path sys32Dir(sys32Path);
            if (fs::exists(sys32Dir / deps))
                return sys32Dir / deps;
        }
        // 4. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. The name of this directory is System.
        // No...

        // 5. The Windows directory. Use the GetWindowsDirectory function to get the path of this directory.
        size = GetWindowsDirectoryA(nullptr, 0) - 1;
        if (size)
        {
            std::string winPath(size, ' ');
            GetWindowsDirectoryA((char *)winPath.data(), size + 1);
            fs::path winDir(winPath);
            if (fs::exists(winDir / deps))
                return winDir / deps;
        }
        //6. The directories that are listed in the PATH environment variable.
        if (pathEnv.empty())
        {
            size = GetEnvironmentVariableA("PATH", nullptr, 0) - 1;
            if (size)
            {
                std::string pathenv(size, ' ');
                GetEnvironmentVariableA("PATH", (char *)pathenv.data(), size + 1);
                pathEnv = split<';'>(pathenv);
            }
        }
        for (const auto &path : pathEnv)
        {
            fs::path pathDir(path);
            if (fs::exists(pathDir / deps))
                return pathDir / deps;
        }
        return fs::path();
    }
    void showDependencies(std::string path, Data datas, bool analyse)
    {
        if (datas.showDeps || analyse)
        {
            auto t = parse_pe_import_table_names(path);
            if (t.empty())
            {
                std::cout << datas.indent << "Pas de dépendance" << std::endl;
                return;
            }
            std::cout << datas.indent << "Dépendances : " << std::endl;
            for (auto &fil : t)
            {
                std::cout << datas.indent << fil << std::endl;
                auto pathDeps = findDependency(fil, datas.current_path);
                if (pathDeps.empty())
                {
                    std::cout << datas.indent << "Dépendence non trouvé." << std::endl;
                    continue;
                }

                if (datas.depth < datas.maxdepth && analyse)
                {
                    Data d = datas;
                    ++d.depth;
                    d.indent = std::string(d.depth, '\t');
                    loadModule(pathDeps.string(), d);
                }
            }
        }
    }
    void loadModule(std::string path, Data datas)
    {
        std::cout << datas.indent << "Chemin complet : " << path << std::endl;
        auto hModule = LoadLibraryA(path.c_str());

        datas.current_path = path;
        //std::string indent(datas.depth, '\t');
        if (hModule)
        {
            std::cout << datas.indent << "Le module a correctement été chargé. " << std::endl;
            if (path.find(".4DX"))
            {
                if (GetProcAddress(hModule, "FourDPackex"))
                    std::cout << datas.indent << "La fonction FourDPackex est correctement chargé. " << std::endl;
            }
            showDependencies(path, datas, false);
            if (FreeLibrary(hModule))
                std::cout << datas.indent << "Le module a correctement été déchargé. " << std::endl;
            else
                std::cout << datas.indent << "Le module a eu un prolème lors du déchargement. " << std::endl;
        }
        else
        {
            std::cout << datas.indent << "Le module n'a pas réussi à charger. " << std::endl;
            int winerr = GetLastError();
            std::cout << datas.indent << "Erreur Windows : " << winerr << std::endl;
            showDependencies(path, datas, true);
        }
    }
} // namespace loader