#include <iostream>
#include <stdexcept>
#include <string>

#include "../config/config.hpp"
#include "../dkg/planner.hpp"

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: noise_preproc_plan <config_path>" << std::endl;
        return 1;
    }

    try
    {
        const host::RuntimeConfig config = host::load_runtime_config(argv[1]);
        const host::dkg::DkgPlan plan = host::dkg::build_plan(config);
        for (const std::string& line : host::dkg::format_plan_report(plan))
        {
            std::cout << line << std::endl;
        }
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
}
