#include <chrono>
#include <iostream>
#include "gatekeeper.hpp"

int main(int, char**)
{
    Config config;
    config.generated_date = std::chrono::system_clock::now();
    config.duration = std::chrono::duration<int, std::ratio<24*60*60>>(30); // 30 days
    config.activated_count = 0;
    config.activated_limit = 10;

    GateKeeper gatekeeper;
    gatekeeper.GenerateSL(config, "test.sl");
    bool is_activated = gatekeeper.ActivateSL("test.sl");
    bool is_verified = gatekeeper.VerifySL("test.sl");

    std::cout << "is_activated: " << is_activated << std::endl;
    std::cout << "is_verified: " << is_verified << std::endl;
    return 0;
}