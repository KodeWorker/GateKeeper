#include <chrono>
#include <iostream>
#include "gatekeeper.hpp"

int main(int, char**)
{
    Config config;
    config.generated_date = std::chrono::system_clock::now();
    config.duration = std::chrono::duration<int, std::ratio<24*60*60>>(30); // 30 days    
    config.activated_limit = 10;
    config.signature = 1;

    GateKeeper gatekeeper;
    gatekeeper.GenerateSL(config, "test.sl");
    bool is_activated = gatekeeper.ActivateSL("test.sl", 1);
    bool is_verified = gatekeeper.VerifySL("test.sl", 1);

    std::cout << "GateKeeper is_activated: " << is_activated << std::endl;
    std::cout << "GateKeeper is_verified: " << is_verified << std::endl;
    
    Guard guard("test.sl");
    is_activated = guard.Activate(1);
    is_verified = guard.Verify(1);

    std::cout << "Guard is_activated: " << is_activated << std::endl;
    std::cout << "Guard is_verified: " << is_verified << std::endl;
    return 0;
}