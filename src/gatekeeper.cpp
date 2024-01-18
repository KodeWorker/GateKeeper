#include <fstream>
#include <iomanip>
#include <algorithm>
#include <nlohmann/json.hpp>

#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp-pem/pem.h"

#include "gatekeeper.hpp"
#include "internal_config.hpp"
#include "private_key.h"

#include <iostream> //temp

GateKeeper::GateKeeper()
{
    LoadPrivateKey();
}

GateKeeper::~GateKeeper()
{

}

void GateKeeper::GenerateSL(Config config, std::string path)
{
    std::string public_key = GeneratePublicKey();

    CryptoPP::RSA::PublicKey rsa_public_key;
    CryptoPP::StringSource public_key_source(public_key, true);
    rsa_public_key.Load(public_key_source);

    // Convert Config to json token
    nlohmann::json info;

    info["generated_date"] = TimePointToString(config.generated_date);
    info["duration_days"] = config.duration.count();
    info["activated_dates"] = {TimePointToString(config.generated_date)};
    info["activated_count"] = 0;
    info["activated_limit"] = config.activated_limit;
    
    std::string token = info.dump(4);

    //Encrypt token
    std::string cipher;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor rsa(rsa_public_key);
    // Encryption
    CryptoPP::StringSource ss_encrypt(token, true, 
                                      new CryptoPP::PK_EncryptorFilter(rng, rsa, 
                                      new CryptoPP::StringSink(cipher)));

    std::string cipher_size = std::to_string(cipher.size());
    std::string padded_cipher_size = std::string(n_zero - std::min(n_zero, (int)(cipher_size.length())), '0') + cipher_size;
    
    // Generate SL
    std::ofstream out(path);
    out << padded_cipher_size << cipher << public_key;
    out.close();
}

bool GateKeeper::ActivateSL(std::string path)
{
    // Parse SL sections
    // Decrypt SL
    // Parse InternalConfig
    // Modify activated info
    // rewrite SL
}

bool GateKeeper::VerifySL(std::string path)
{
    // Parse SL sections
    // Decrypt SL
    // Parse InternalConfig
    // Check license
}

bool GateKeeper::LoadPrivateKey()
{
    std::vector<char> char_vector;
    for(int i = 0; i < RESOURCE_PRIVATE_KEY_len; i++)
    {
        char_vector.push_back(RESOURCE_PRIVATE_KEY[i]);
    }
    private_key = std::string(char_vector.begin(), char_vector.end());
}

std::string GateKeeper::GeneratePublicKey()
{
    //Load private key
    CryptoPP::RSA::PrivateKey rsa_private_key;
    CryptoPP::StringSource ss(private_key.c_str(), true);
    CryptoPP::PEM_Load(ss, rsa_private_key);

    // Create the corresponding public key
    CryptoPP::Integer modulus = rsa_private_key.GetModulus();
    CryptoPP::Integer public_exponent = rsa_private_key.GetPublicExponent();
    CryptoPP::RSA::PublicKey rsa_public_key;
    rsa_public_key.Initialize(modulus, public_exponent);

    // Print or use the public key as needed
    std::string public_key;
    CryptoPP::StringSink public_key_sink(public_key);
    rsa_public_key.DEREncode(public_key_sink);
    return public_key;
}

bool GateKeeper::DurationCheck()
{

}

bool GateKeeper::ExecutionCountCheck()
{

}

std::string GateKeeper::TimePointToString(std::chrono::time_point<std::chrono::system_clock> tp)
{
    std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm = *std::gmtime(&tt); //GMT (UTC)
    std::stringstream ss_info;
    std::string format = "%Y/%m/%d %T";
    ss_info << std::put_time(&tm, format.c_str());
    return ss_info.str();
}