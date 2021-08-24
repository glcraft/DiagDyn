#include "loader2.h"
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <variant>
#include <unordered_map>
#include <unordered_set>
#include "dependencies.h"
namespace loader2
{
    namespace fs = std::filesystem;
    struct PathHash {
        std::size_t operator()(fs::path const& p) const noexcept {
            return fs::hash_value(p);
        }
    };

    static std::unordered_map<fs::path, uint32_t, PathHash> s_paths2={};

    constexpr auto INDENTATION_STRING = std::string_view("    ");

    struct iter_indent {
        uint32_t depth;
        inline friend std::ostream& operator<<(std::ostream& os, const iter_indent& it) {
            for (uint32_t i=0;i<it.depth;i++) {
                os << INDENTATION_STRING;
            }
            return os;
        }
    };
    struct InternalData {
        using line_ref_t = std::reference_wrapper<uint32_t>;
        using line_t = std::variant<uint32_t, line_ref_t>;
        
        fs::path current_name;
        fs::path current_path;
        uint32_t current_depth=0;
        line_t current_line=line_t{std::in_place_type<uint32_t>, 0};

        InterfaceData interf;

        [[nodiscard]] uint32_t get_line() const noexcept {
            if (current_line.index()==0)
                return std::get<0>(current_line);
            else
                return std::get<1>(current_line);
        }
        void new_line() {
            std::cout << '\n';
            if (current_line.index()==0)
                ++std::get<0>(current_line);
            else
                ++std::get<1>(current_line).get();
        }
        [[nodiscard]] line_ref_t get_line_ref() {
            if (current_line.index()==0)
                return line_ref_t{std::get<0>(current_line)};
            else
                return std::get<1>(current_line);
        }

        
        inline void verbose_msg(std::string_view message, bool force = false) const {
            if (force || interf.verbose)
                std::cout << " (" << message << ")";
        }
        iter_indent indent() const {
            return iter_indent{current_depth};
        }
        inline friend std::ostream& operator<<(std::ostream& os, const InternalData& id) {
            os << id.indent();
            if (id.interf.full_path)
                os  << "\"" << id.current_path.generic_string()<< "\"" ;
            else {
                os << id.current_name.generic_string();
                auto filename = id.current_path.filename();
                if (id.interf.verbose && filename !=id.current_name)
                    os << " -> \""<< id.current_path.generic_string() << "\"";
            }
            return os;
        }
    };


    inline fs::path moduleName(HMODULE hModule)
    {
        wchar_t buffer[1024];
        int size = GetModuleFileNameW(hModule, buffer, 1024);
        return buffer;
    }
    void loadModule(std::string path, InternalData datas)
    {
        // std::cout << datas.indent() << path << ": ";
        // auto hModule = LoadLibraryA(path.c_str());
        // if (hModule)
        // {
        //     std::cout << datas.indent() << "OK : ";
        //     auto path = moduleName(hModule);
        //     std::cout << path << "\n";
        // }
        // else
        // {
        //     std::cout << datas.indent << "NOK : erreur " << GetLastError();
        //     if (fs::exists(fs::path(path)))
        //     {
        //         std::cout << std::endl;
        //         auto tDeps = parse_pe_import_table_names(path);
        //         for (auto& deps : tDeps)
        //         {
        //             Data d = datas;
        //             ++d.depth;
        //             d.indent = std::string(d.depth, '\t');
        //             loadModule(deps, d);
        //         }
        //     }
        //     else
        //         std::cout << " (not found)\n";
        // }
    }
    
    void showDeps(InternalData data)
    {
        std::cout << data;
        auto found_path = s_paths2.find(data.current_name);
        if (found_path != s_paths2.end())
        {
            data.verbose_msg(std::to_string(found_path->second), true);
            return;
        }
        s_paths2.insert(std::pair{data.current_name, data.get_line()});
        if (!fs::exists(data.current_path))
        {
            data.verbose_msg("not found");
            return;
        }
        if (data.interf.max_depth==0 || data.current_depth<=data.interf.max_depth)
        {
            auto tDeps = parse_pe_import_table_names(data.current_path);
            for (auto& dep : tDeps)
            {
                data.new_line();
                auto hModule = LoadLibraryW(dep.wstring().c_str());
                if (!hModule)
                {
                    std::cout << dep;
                    data.verbose_msg("unable to load");
                    data.new_line();
                    continue;
                }
                auto module_path = moduleName(hModule);
                FreeLibrary(hModule);

                showDeps(InternalData{
                    .current_name = dep,
                    .current_path = module_path,
                    .current_depth = data.current_depth+1,
                    .current_line = data.get_line_ref(),

                    .interf = data.interf,
                });
            }
        }
    }

    
    void load_module(std::filesystem::path module_path, InterfaceData datas)
    {
        
    }
    void show_dependences(std::filesystem::path module_path, InterfaceData datas)
    {
        showDeps(InternalData{
            .current_name = module_path.filename(),
            .current_path = module_path,
            .current_depth = 0,
            .current_line = uint32_t{1},

            .interf = datas,
        });
    }
}