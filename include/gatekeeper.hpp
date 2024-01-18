#ifndef GATEKEEPER_HPP
#define GATEKEEPER_HPP

#include <string>
#include <vector>
#include <chrono>
#include "export.hpp"

const int KEY_SIZE = 3072;
const int RECORD_COUNT = 5;

struct EXPORT Config
{
    std::chrono::time_point<std::chrono::system_clock> generated_date;
    int duration; // days
    int limit; // activations
    unsigned signature;
};

class EXPORT GateKeeper
{
    public:
        GateKeeper();
        ~GateKeeper();
        void GenerateSL(Config, std::string);
        bool ActivateSL(std::string, unsigned);
        bool VerifySL(std::string, unsigned);
    private:
        int record_count = RECORD_COUNT;
        int key_size = KEY_SIZE;    
};

class EXPORT Guard
{
    public:
        Guard(std::string);
        ~Guard();
        bool Activate(unsigned);
        bool Verify(unsigned);
    private:
        int record_count = RECORD_COUNT;
        int key_size = KEY_SIZE;
        std::string path;
        std::string ciphertext;
};

#endif // GATEKEEPER_HPP