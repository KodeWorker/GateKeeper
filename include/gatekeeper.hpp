#ifndef GATEKEEPER_HPP
#define GATEKEEPER_HPP

#include <string>
#include <vector>
#include <chrono>
#include "export.hpp"

struct EXPORT Config
{
    std::chrono::time_point<std::chrono::system_clock> generated_date;
    std::chrono::duration<int, std::ratio<24*60*60>> duration; // days
    int activated_limit;
};

class EXPORT GateKeeper
{
    public:
        GateKeeper();
        ~GateKeeper();
        void GenerateSL(Config, std::string);
        bool ActivateSL(std::string);
        bool VerifySL(std::string);
    private:
        int record_count = 5;
        int key_size = 3072;
        std::string private_key;
        std::string software_lock_path;
        bool LoadPrivateKey();
        std::string GeneratePublicKey();
        bool DurationCheck(std::chrono::time_point<std::chrono::system_clock>,
                           std::chrono::time_point<std::chrono::system_clock>,
                           std::vector<std::chrono::time_point<std::chrono::system_clock>>,
                           std::chrono::duration<int, std::ratio<24*60*60>>);
        bool ExecutionCountCheck(int, int);
        std::string TimePointToString(std::chrono::time_point<std::chrono::system_clock>);
        std::chrono::time_point<std::chrono::system_clock> StringToTimePoint(std::string);
};

#endif // GATEKEEPER_HPP