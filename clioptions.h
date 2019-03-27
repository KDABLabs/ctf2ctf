#pragma once

#include <vector>
#include <string>
#include <filesystem>

struct CliOptions
{
    std::filesystem::path path;
    std::vector<std::string> exclude;
    std::vector<int64_t> pidWhitelist;
    std::vector<std::string> processWhitelist;
    bool enableStatistics = false;
};

CliOptions parseCliOptions(int argc, char** argv);
