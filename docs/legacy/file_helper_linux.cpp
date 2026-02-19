#include <filesystem>
#include <string>
#include <cctype>
#include <cstring>
#include "../include/file_helper.hpp"

namespace fs = std::filesystem;

static bool iequals_ascii(const char* a, const char* b)
{
    while (*a && *b) {
        if (std::tolower((unsigned char)*a) !=
            std::tolower((unsigned char)*b))
            return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

int find_file_ci_c(
    const char* dir,
    const char* target_fname,
    int search_mode, // 0 = CI ext only, 1 = CI stem+ext
    char* found_path,
    int found_path_len 
)
{
  
    // Default: empty output
    if (found_path && found_path_len > 0)
        found_path[0] = '\0';

    try {
        int count = 0;
        std::string single_match_full;  // store only if exactly one

        fs::path target_path(target_fname);
        const std::string target_stem = target_path.stem().string();
        const std::string target_ext  = target_path.extension().string();

        // iterate over directory entries and count case insensitive matches
        for (const auto& e : fs::directory_iterator(dir)) {
            if (!e.is_regular_file()) continue;

            fs::path p = e.path();
            const std::string stem = p.stem().string();
            const std::string ext  = p.extension().string();

            bool match = false;

            if (search_mode == 0) {
                // Stem must match exactly, extension case-insensitive
                match =
                    (stem == target_stem) &&
                    iequals_ascii(ext.c_str(), target_ext.c_str());
            }
            else {
                // Both stem and extension case-insensitive
                match =
                    iequals_ascii(stem.c_str(), target_stem.c_str()) &&
                    iequals_ascii(ext.c_str(),  target_ext.c_str());
            }

            if (match) {
                ++count;

                if (count == 1) {
                    single_match_full = p.string();
                } else {
                    single_match_full.clear();
                }
            }
        }

        // If exactly one match, copy it out
        if (count == 1 && found_path && found_path_len > 0) {
            const auto n = std::min(
                static_cast<int>(single_match_full.size()),
                found_path_len - 1
            );
            std::memcpy(found_path, single_match_full.data(), n);
            found_path[n] = '\0';
        }

        return count;
    }
    catch (...) {
        if (found_path && found_path_len > 0)
            found_path[0] = '\0';
        return -1;
    }
}