#ifndef CHECKER_HPP
#define CHECKER_HPP

#include <string>
#include <vector>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>

bool DurationCheck(std::chrono::time_point<std::chrono::system_clock>,
                   std::chrono::time_point<std::chrono::system_clock>,
                   std::vector<std::chrono::time_point<std::chrono::system_clock>>,
                   std::chrono::duration<int, std::ratio<24*60*60>>);
bool ExecutionCountCheck(int, int);
std::string TimePointToString(std::chrono::time_point<std::chrono::system_clock>);
std::chrono::time_point<std::chrono::system_clock> StringToTimePoint(std::string);

#endif // CHECKER_HPP