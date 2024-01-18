#ifndef INTERNAL_CONFIG
#define INTERNAL_CONFIG

#include <vector>
#include <chrono>

struct InternalConfig
{
    std::chrono::time_point<std::chrono::system_clock> generated_date;
    std::chrono::duration<int, std::ratio<24*60*60>> duration; // days
    std::vector<std::chrono::time_point<std::chrono::system_clock>> activated_dates;
    int activated_count;
    int activated_limit;
};

#endif // INTERNAL_CONFIG