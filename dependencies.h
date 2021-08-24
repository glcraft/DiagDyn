#include <vector>
#include <filesystem>
#include <Windows.h>

//FUNCTION DECLARATIONS
bool verify_image_file(const std::filesystem::path&);
std::vector<char> read_all_bytes(const std::filesystem::path& file);
std::vector<std::filesystem::path> parse_pe_import_table_names(const std::filesystem::path& file);