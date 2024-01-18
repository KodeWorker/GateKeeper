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

    // Generate SL
    std::ofstream out(path);
    out << cipher << public_key;
    out.close();
}

bool GateKeeper::ActivateSL(std::string path)
{
    // Parse SL sections
    std::ifstream in(path);
    std::stringstream buffer;  
    buffer << in.rdbuf();  
    std::string ciphertext(buffer.str());

    int cipher_size = key_size / 8;
    std::string cipher_token = ciphertext.substr(0, cipher_size);
    std::string public_key = ciphertext.substr(cipher_size, ciphertext.size() - cipher_size);
    // Decrypt SL
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey rsa_private_key;
    CryptoPP::StringSource ss(private_key.c_str(), true);
    CryptoPP::PEM_Load(ss, rsa_private_key);

    CryptoPP::RSAES_OAEP_SHA_Decryptor rsa_decrypt(rsa_private_key);
    std::string plain_token;
    CryptoPP::StringSource ss_decrypt(cipher_token, true, 
                                      new CryptoPP::PK_DecryptorFilter(rng, rsa_decrypt, 
                                      new CryptoPP::StringSink(plain_token)));
    // Parse InternalConfig
    InternalConfig internal_config;
    nlohmann::json info = nlohmann::json::parse(plain_token);
    internal_config.generated_date = StringToTimePoint(info["generated_date"]);
    internal_config.duration = std::chrono::duration<int, std::ratio<24*60*60>>(info["duration_days"]);
    
    std::vector<std::string> activated_dates_vector = info["activated_dates"].get<std::vector<std::string>>();
    for(auto date : activated_dates_vector)
    {
        internal_config.activated_dates.push_back(StringToTimePoint(date));
    }
    
    internal_config.activated_count = info["activated_count"];
    internal_config.activated_limit = info["activated_limit"];
    // Modify activated info
    internal_config.activated_count++;
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

    internal_config.activated_dates.push_back(now);
    activated_dates_vector.push_back(TimePointToString(now));
    
    if(!DurationCheck(now, internal_config.generated_date, internal_config.activated_dates, internal_config.duration) ||
       !ExecutionCountCheck(internal_config.activated_count, internal_config.activated_limit))
        return false;

    // rewrite SL
    std::vector<std::string> latest_activated_dates;
    if(activated_dates_vector.size() > record_count)
        latest_activated_dates = std::vector<std::string>(activated_dates_vector.end() - record_count, activated_dates_vector.end());
    else
        latest_activated_dates = std::vector<std::string>(activated_dates_vector.begin(), activated_dates_vector.end());
    info["activated_dates"] = latest_activated_dates;
    info["activated_count"] = internal_config.activated_count;
    std::string token = info.dump(4);

    //Encrypt token
    std::string cipher;
    CryptoPP::RSA::PublicKey rsa_public_key;
    CryptoPP::StringSource public_key_source(public_key, true);
    rsa_public_key.Load(public_key_source);
    CryptoPP::RSAES_OAEP_SHA_Encryptor rsa_encrypt(rsa_public_key);
    // Encryption
    CryptoPP::StringSource ss_encrypt(token, true, 
                                      new CryptoPP::PK_EncryptorFilter(rng, rsa_encrypt, 
                                      new CryptoPP::StringSink(cipher)));

    // Generate SL
    std::ofstream out(path);
    out << cipher << public_key;
    out.close();
    return true;
}

bool GateKeeper::VerifySL(std::string path)
{
    // Parse SL sections
    std::ifstream in(path);
    std::stringstream buffer;  
    buffer << in.rdbuf();  
    std::string ciphertext(buffer.str());

    int cipher_size = key_size / 8;
    std::string cipher_token = ciphertext.substr(0, cipher_size);
    std::string public_key = ciphertext.substr(cipher_size, ciphertext.size() - cipher_size);
    // Decrypt SL
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey rsa_private_key;
    CryptoPP::StringSource ss(private_key.c_str(), true);
    CryptoPP::PEM_Load(ss, rsa_private_key);

    CryptoPP::RSAES_OAEP_SHA_Decryptor rsa(rsa_private_key);
    std::string plain_token;
    CryptoPP::StringSource ss_decrypt(cipher_token, true, 
                                      new CryptoPP::PK_DecryptorFilter(rng, rsa, 
                                      new CryptoPP::StringSink(plain_token)));
    // Parse InternalConfig
    InternalConfig internal_config;
    nlohmann::json info = nlohmann::json::parse(plain_token);
    internal_config.generated_date = StringToTimePoint(info["generated_date"]);
    internal_config.duration = std::chrono::duration<int, std::ratio<24*60*60>>(info["duration_days"]);
    
    std::vector<std::string> activated_dates_vector = info["activated_dates"].get<std::vector<std::string>>();
    for(auto date : activated_dates_vector)
    {
        internal_config.activated_dates.push_back(StringToTimePoint(date));
    }
    
    internal_config.activated_count = info["activated_count"];
    internal_config.activated_limit = info["activated_limit"];
    // Modify activated info
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    internal_config.activated_dates.push_back(now);
    
    if(!DurationCheck(now, internal_config.generated_date, internal_config.activated_dates, internal_config.duration) ||
       !ExecutionCountCheck(internal_config.activated_count, internal_config.activated_limit))
        return false;
    else
        return true;

}

bool GateKeeper::LoadPrivateKey()
{
    std::vector<char> char_vector;
    for(int i = 0; i < RESOURCE_PRIVATE_KEY_len; i++)
    {
        char_vector.push_back(RESOURCE_PRIVATE_KEY[i]);
    }
    private_key = std::string(char_vector.begin(), char_vector.end());
    return true;
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

bool GateKeeper::DurationCheck(std::chrono::time_point<std::chrono::system_clock> now,
                               std::chrono::time_point<std::chrono::system_clock> generated_date,
                               std::vector<std::chrono::time_point<std::chrono::system_clock>> activated_dates,
                               std::chrono::duration<int, std::ratio<24*60*60>> duration)
{
    std::chrono::time_point<std::chrono::system_clock> expired_date = generated_date + duration;
    return now < expired_date && std::is_sorted(activated_dates.begin(), activated_dates.end());
}

bool GateKeeper::ExecutionCountCheck(int activated_count, int activated_limit)
{
    return activated_count < activated_limit;
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

std::chrono::time_point<std::chrono::system_clock> GateKeeper::StringToTimePoint(std::string str)
{
    std::tm tm = {};
    std::stringstream ss(str);
    ss >> std::get_time(&tm, "%Y/%m/%d %T");
    std::time_t tt = std::mktime(&tm);
    return std::chrono::system_clock::from_time_t(tt);
}