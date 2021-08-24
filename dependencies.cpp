//******************************************************************************
// Link
// https://stackoverflow.com/questions/43670731/programmatically-get-list-of-dlls-used-to-build-a-process-or-library-in-a-non-de


//******************************************************************************
// Headers
#include "Windows.h"

#include <algorithm>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <array>

#include <filesystem>

//******************************************************************************
// Namespaces
namespace fs = std::filesystem;

//******************************************************************************
//FUNCTION DECLARATIONS
bool verify_image_file(const fs::path&);
std::vector<char> read_all_bytes(const fs::path& file);
std::vector<fs::path> parse_pe_import_table_names(const fs::path& file);

//******************************************************************************
// Constants
//        LABEL                                                HEX            DEC
//
const WORD MAGIC_NUM_32BIT          = static_cast<const WORD>(0x10b);     // 267
const WORD MAGIC_NUM_64BIT          = static_cast<const WORD>(0x20b);     // 523
const int IMG_SIGNATURE_OFFSET      = static_cast<const int>(0x3c);       // 60
const int IMPORT_TABLE_OFFSET_32    = static_cast<const int>(0x68);       // 104
const int IMPORT_TABLE_OFFSET_64    = static_cast<const int>(0x78);       // 120
const int IMG_SIGNATURE_SIZE        = static_cast<const int>(0x4);        // 4
const int OPT_HEADER_OFFSET_32      = static_cast<const int>(0x1c);       // 28
const int OPT_HEADER_OFFSET_64      = static_cast<const int>(0x18);       // 24
const int DATA_DIR_OFFSET_32        = static_cast<const int>(0x60);       // 96
const int DATA_DIR_OFFSET_64        = static_cast<const int>(0x70);       // 112
const int DATA_IAT_OFFSET_64        = static_cast<const int>(0xD0);       // 208
const int DATA_IAT_OFFSET_32        = static_cast<const int>(0xC0);       // 192
const int SZ_OPT_HEADER_OFFSET      = static_cast<const int>(0x10);       // 16
const int RVA_AMOUNT_OFFSET_64      = static_cast<const int>(0x6c);       // 108
const int RVA_AMOUNT_OFFSET_32      = static_cast<const int>(0x5c);       // 92
const char * KNOWN_IMG_SIGNATURE    = static_cast<const char*>("PE\0\0");

//******************************************************************************
// Globals
bool is64Bit = false;
bool is32Bit = false;

//******************************************************************************
// Exceptions
class invalid_parameters        : public std::exception { const char* what() const throw()
{ return "You did not provide the solitary command-line parameter of the EXE or DLL to check.\n"; } };

class invalid_image_file        : public std::exception { const char* what() const throw()
{ return "The file detected was not determined to be an image file based off its extension.\n"; } };

class unexpected_rva_offset     : public std::exception { const char* what() const throw()
{ return "An unexpected value was returned for the RVA to File Offset.\n"; } };

class non_image_magic_number    : public std::exception { const char* what() const throw()
{ return "The PE Optional Header's Magic Number did not indicate the file was an image.\n"; } };

class invalid_pe_signature      : public std::exception { const char* what() const throw()
{ return "The PE Signature was not detected.\n"; } };


//******************************************************************************
// PE Parser
std::vector<fs::path> parse_pe_import_table_names(const fs::path& file)
{
    std::vector<char> bytes = read_all_bytes(file);
    std::vector<fs::path> dependencies;

    DWORD * signature_offset_location = (DWORD*)&bytes[IMG_SIGNATURE_OFFSET];
    char * signature = (char*)&bytes[*signature_offset_location];

    if (*signature != *KNOWN_IMG_SIGNATURE)return dependencies;

    DWORD coff_file_header_offset = *signature_offset_location + IMG_SIGNATURE_SIZE;
    IMAGE_FILE_HEADER* coff_file_header = (IMAGE_FILE_HEADER*)&bytes[coff_file_header_offset];
    DWORD optional_file_header_offset = coff_file_header_offset + sizeof(IMAGE_FILE_HEADER);

    WORD size_of_optional_header_offset = coff_file_header_offset + SZ_OPT_HEADER_OFFSET;
    WORD* size_of_optional_header = (WORD*)&bytes[size_of_optional_header_offset];

    //Magic is a 2-Byte value at offset-zero of the optional file header regardless of 32/64 bit
    WORD* magic_number = (WORD*)&bytes[optional_file_header_offset];

    if (*magic_number == MAGIC_NUM_32BIT)is32Bit = true;
    else if (*magic_number == MAGIC_NUM_64BIT)is64Bit = true;
    else
    {
        std::cerr << "Could not parse magic number for 32 or 64-bit PE-format Image File." << std::endl;
        return dependencies;
    }

    if (is64Bit)
    {
        IMAGE_OPTIONAL_HEADER64 * img_opt_header_64 = (IMAGE_OPTIONAL_HEADER64*)&bytes[optional_file_header_offset];
        IMAGE_DATA_DIRECTORY* import_table_data_dir = (IMAGE_DATA_DIRECTORY*)&bytes[optional_file_header_offset + IMPORT_TABLE_OFFSET_64];
        DWORD* import_table_address = (DWORD*)import_table_data_dir;

        DWORD image_section_header_offset = optional_file_header_offset + coff_file_header->SizeOfOptionalHeader;

        for (int i = 0; i < coff_file_header->NumberOfSections; i++)
        {
            IMAGE_SECTION_HEADER* queried_section_header = (IMAGE_SECTION_HEADER*)&bytes[image_section_header_offset];
            if (*import_table_address >= queried_section_header->VirtualAddress &&
                (*import_table_address < (queried_section_header->VirtualAddress + queried_section_header->SizeOfRawData)))
            {
                DWORD import_table_offset = *import_table_address - queried_section_header->VirtualAddress + queried_section_header->PointerToRawData;
                while(true)
                {
                    IMAGE_IMPORT_DESCRIPTOR* import_table_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)&bytes[import_table_offset];
                    if (import_table_descriptor->OriginalFirstThunk == 0)
                    {
                        break;//Signifies end of IMAGE_IMPORT_DESCRIPTORs
                    }
                    // (VA from data directory _entry_ to Image Import Descriptor's element you want) - VA from section header + section header's PointerToRawData
                    DWORD dependency_name_address = import_table_descriptor->Name;//VA not RVA; ABSOLUTE
                    DWORD name_offset = dependency_name_address - queried_section_header->VirtualAddress + queried_section_header->PointerToRawData;
                    char * dependency_name = (char *)&bytes[name_offset];
                    dependencies.push_back((std::string)dependency_name);
                    import_table_offset = import_table_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR);
                }
            }
            image_section_header_offset = image_section_header_offset + sizeof(IMAGE_SECTION_HEADER);
        }
    }
    else//32-bit behavior
    {
        IMAGE_OPTIONAL_HEADER32 * img_opt_header_32 = (IMAGE_OPTIONAL_HEADER32*)&bytes[optional_file_header_offset];
        IMAGE_DATA_DIRECTORY* import_table_data_dir = (IMAGE_DATA_DIRECTORY*)&bytes[optional_file_header_offset + IMPORT_TABLE_OFFSET_32];
        DWORD* import_table_address = (DWORD*)import_table_data_dir;

        DWORD image_section_header_offset = optional_file_header_offset + coff_file_header->SizeOfOptionalHeader;

        for (int i = 0; i < coff_file_header->NumberOfSections; i++)
        {
            IMAGE_SECTION_HEADER* queried_section_header = (IMAGE_SECTION_HEADER*)&bytes[image_section_header_offset];
            if (*import_table_address >= queried_section_header->VirtualAddress &&
                (*import_table_address < (queried_section_header->VirtualAddress + queried_section_header->SizeOfRawData)))
            {
                DWORD import_table_offset = *import_table_address - queried_section_header->VirtualAddress + queried_section_header->PointerToRawData;
                while (true)
                {
                    IMAGE_IMPORT_DESCRIPTOR* import_table_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)&bytes[import_table_offset];
                    if (import_table_descriptor->OriginalFirstThunk == 0)
                    {
                        break;//Signifies end of IMAGE_IMPORT_DESCRIPTORs
                    }
                    // (VA from data directory _entry_ to Image Import Descriptor's element you want) - VA from section header + section header's PointerToRawData
                    DWORD dependency_name_address = import_table_descriptor->Name;//VA not RVA; ABSOLUTE
                    DWORD name_offset = dependency_name_address - queried_section_header->VirtualAddress + queried_section_header->PointerToRawData;
                    char * dependency_name = (char *)&bytes[name_offset];
                    dependencies.push_back((std::string)dependency_name);
                    import_table_offset = import_table_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR);
                }
            }
            image_section_header_offset = image_section_header_offset + sizeof(IMAGE_SECTION_HEADER);
        }
    }

    return dependencies;
}

//******************************************************************************
// File Reader
std::vector<char> read_all_bytes(const fs::path& filename)
{
    std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
    std::ifstream::pos_type pos = ifs.tellg();

    std::vector<char> result(pos);
    ifs.seekg(0, std::ios::beg);
    ifs.read(&result[0], pos);

    return result;
}

//******************************************************************************
// IMAGE-TYPE FILE VERIFIER
bool verify_image_file(const fs::path& file_to_verify)
{
    using namespace std::string_view_literals;
    constexpr auto binary_exts = std::array{".dll"sv, ".exe"sv, ".com"sv};
    if (!fs::exists(file_to_verify))
        return false;
    auto ext = file_to_verify.extension().string();
    for(auto& c : ext)
        c = std::tolower(c);
    return std::find(binary_exts.begin(), binary_exts.end(), ext) != binary_exts.end();
}