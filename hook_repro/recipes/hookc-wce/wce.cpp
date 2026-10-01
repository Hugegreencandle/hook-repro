// hookc-wce: runs xahaud's own validateGuards() (include/xrpl/hook/Guard.h, compiled
// unmodified in upstream's GUARD_CHECKER_BUILD mode) on one wasm and prints the
// worst-case instruction counts it computes, as one JSON line on stdout:
//   {"valid":true,"hook":N,"cbak":M}     exit 0
//   {"valid":false}                      exit 1  (checker log on stderr)
//   {"valid":false,"threw":true}         exit 2
// These are the values SetHook passes to hook::computeExecutionFee.
#define GUARD_CHECKER_BUILD
#include "Enum.h"
#include "Guard.h"
#include <cstdio>
#include <fstream>
#include <iterator>
#include <sstream>
#include <vector>

int main(int argc, char** argv)
{
    if (argc != 2)
        return std::fprintf(stderr, "usage: hookc-wce file.wasm\n"), 64;
    std::ifstream in(argv[1], std::ios::binary);
    if (!in)
        return std::fprintf(stderr, "cannot open %s\n", argv[1]), 66;
    std::vector<uint8_t> wasm((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::ostringstream log;
    try
    {
        hook_api::Rules rules;
        auto r = validateGuards(wasm, std::ref<std::ostream>(log), "",
                                hook_api::getImportWhitelist(rules),
                                hook_api::getGuardRulesVersion(rules));
        std::fputs(log.str().c_str(), stderr);
        if (!r)
            return std::printf("{\"valid\":false}\n"), 1;
        std::printf("{\"valid\":true,\"hook\":%llu,\"cbak\":%llu}\n",
                    (unsigned long long)r->first, (unsigned long long)r->second);
        return 0;
    }
    catch (std::exception const& e)
    {
        std::fprintf(stderr, "%s\nthrew: %s\n", log.str().c_str(), e.what());
        return std::printf("{\"valid\":false,\"threw\":true}\n"), 2;
    }
}
