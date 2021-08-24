#include <iostream>
#include <string>
#include <charconv>
#include <optional>
#include <Windows.h>
#include "loader2.h"


void display_help()
{
    constexpr auto msg_help = R"(diag_dyn 2.0.0

diag_dyn list [--depth <N>] [--path] [--verbose] [--pause] <path>
    Afficher les bibliothèques dynamiques dont le module dépend.
    <path>          chemin du module à analyser
    --depth <N>     (défaut: 0) Profondeur maximal dans la recherche de dépendances.
                    Si 0 est spécifié, aucune limite appliqué.
    --path          (défaut: non) Affiche le chemin des modules à la place de leur nom.
    --verbose       (défaut: non) Ajoute des messages d'erreur/avertissement.
    --pause         (défaut: non) Marque une pause à la fin.
)";
    std::cerr << msg_help << '\n';
}
void display_error(std::string_view str_err) 
{
    std::cerr << str_err << '\n';
    display_help();
    exit(1);
};
template <class T>
T from_arg(std::string_view arg) {
    T v;
    auto res = std::from_chars(std::data(arg), std::data(arg)+std::size(arg), v, 10);
    if (res.ec == std::errc::invalid_argument)
        display_error("Mauvais argument : attend un nombre pour [depth]");
    else if (res.ec == std::errc::result_out_of_range)
        display_error("Mauvais argument : limite de taille dépassé pour [depth]");
    else
        return v;
}

void func_list(std::vector<std::string_view> args)
{
    using namespace std::string_view_literals;
    InterfaceData datas;
    bool show_deps = false;
    bool full_path = false;
    bool verbose = false;
    bool pause = false;
    std::optional<uint32_t> depth={};
    std::optional<std::string> path;

    for (auto arg : args)
    {
        if (depth && depth.value()==-1) {
            
            uint32_t v = 0;
            auto res = std::from_chars(std::data(arg), std::data(arg)+std::size(arg), v, 10);
            if (res.ec == std::errc::invalid_argument)
                display_error("Mauvais argument : attend un nombre pour [depth]");
            else if (res.ec == std::errc::result_out_of_range)
                display_error("Mauvais argument : limite de taille dépassé pour [depth]");
            else
                depth=v;
        }
        else if (arg=="--pause"sv)
            pause=true;
        else if (arg=="--path"sv)
            full_path=true;
        else if (arg=="--verbose"sv)
            verbose=true;
        else if (arg=="--depth"sv) {
            depth=-1;
        }
        else
            path=arg;
    }
    if (!path)
        display_error("Argument manquant (chemin du module)");
    if (depth.value()==-1)
        display_error("Argument manquant (nombre de [depth])");
    else if (!depth)
        depth=0;

    datas.max_depth = depth.value();
    datas.full_path = full_path;
    datas.verbose = verbose;
    
    loader2::show_dependences(path.value(), datas);

    if (pause)
        system("PAUSE");
}

int main(int argc, char** argv)
{
    SetErrorMode(SEM_FAILCRITICALERRORS);
    uint32_t function=-1;
    
    if (argc==1)
        display_error("");
    {
        auto func = std::string_view(argv[1]);
        if (func == "list")
            function=0;
        // else if (func == "load")
        //     function=1;
    }
    if (function == -1)
        display_error("Argument manquant (fonction inconnue)");

    std::array{func_list}[function](std::vector<std::string_view>{&argv[2], &argv[2]+argc-2});

    return 0;
}