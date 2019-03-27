#pragma once

#include <vector>
#include <string>
#include <filesystem>

struct CliOptions
{
    std::filesystem::path path;
    std::vector<std::string> exclude;
    bool enableStatistics = false;
};

CliOptions parseCliOptions(int argc, char** argv);
