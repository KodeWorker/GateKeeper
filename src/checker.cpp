#include "checker.hpp"

bool DurationCheck(std::chrono::time_point<std::chrono::system_clock> now,
                   std::chrono::time_point<std::chrono::system_clock> generated_date,
                   std::vector<std::chrono::time_point<std::chrono::system_clock>> activated_dates,
                   std::chrono::duration<int, std::ratio<24*60*60>> duration)
{
    std::chrono::time_point<std::chrono::system_clock> expired_date = generated_date + duration;
    return now < expired_date && std::is_sorted(activated_dates.begin(), activated_dates.end());
}

bool ExecutionCountCheck(int activated_count, int activated_limit)
{
    return activated_count < activated_limit;
}

std::string TimePointToString(std::chrono::time_point<std::chrono::system_clock> tp)
{
    std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm = *std::gmtime(&tt); //GMT (UTC)
    std::stringstream ss_info;
    std::string format = "%Y/%m/%d %T";
    ss_info << std::put_time(&tm, format.c_str());
    return ss_info.str();
}

std::chrono::time_point<std::chrono::system_clock> StringToTimePoint(std::string str)
{
    std::tm tm = {};
    std::stringstream ss(str);
    ss >> std::get_time(&tm, "%Y/%m/%d %T");
    std::time_t tt = std::mktime(&tm);
    return std::chrono::system_clock::from_time_t(tt);
}
