#include <vector>
#include <string>
#include <Windows.h>

//FUNCTION DECLARATIONS
bool verify_image_file(std::string);
std::vector<char> read_all_bytes(const char* file);
std::vector<std::string> parse_pe_import_table_names(std::string file);