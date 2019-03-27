#include "clioptions.h"

#include <iostream>

#include "args/args.hxx"

CliOptions parseCliOptions(int argc, char** argv)
{
    args::ArgumentParser parser("Convert binary LTTng/Common Trace Format trace data to JSON in Chrome Trace Format", "The converted trace data in JSON format is written to stdout.");
    args::HelpFlag helpArg(parser, "help", "Display this help menu", {'h', "help"});
    args::ValueFlagList<std::string> excludeArg(parser, "name substring", "Exclude events with this name", {'x', "exclude"});
    args::ValueFlagList<int64_t> pidWhitelistArg(parser, "pid", "Only show events for this process id", {"pid-whitelist"});
    args::Flag printStatsArg(parser, "stats", "print statistics to stderr", {"print-stats"});
    args::Positional<std::filesystem::path> pathArg(parser, "path", "The path to an LTTng trace folder, will be searched recursively for trace data");
    try {
        parser.ParseCLI(argc, argv);
    } catch (const args::Help&) {
        std::cout << parser;
        exit(0);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl << parser;
        exit(1);
    }

    const auto path = args::get(pathArg);
    if (!std::filesystem::exists(path)) {
        std::cerr << "path does not exist: " << path << std::endl;
        exit(1);
    }

    return {path, args::get(excludeArg), args::get(pidWhitelistArg), args::get(printStatsArg)};
}
