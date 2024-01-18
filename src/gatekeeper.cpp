#include "gatekeeper.hpp"
#include "internal_config.hpp"
#include "checker.hpp"
#include "resource.hpp"

#include <fstream>
#include <nlohmann/json.hpp>

#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp-pem/pem.h"

GateKeeper::GateKeeper()
{
}

GateKeeper::~GateKeeper()
{

}

void GateKeeper::GenerateSL(Config config, std::string path)
{
    std::string public_key = GetPublicKey();

    CryptoPP::RSA::PublicKey rsa_public_key;
    CryptoPP::StringSource public_key_source(public_key, true);
    CryptoPP::PEM_Load(public_key_source, rsa_public_key);

    // Convert Config to json token
    nlohmann::json info;

    info["generated_date"] = TimePointToString(config.generated_date);
    info["duration_days"] = config.duration;
    info["activated_dates"] = {TimePointToString(config.generated_date)};
    info["activated_count"] = 0;
    info["activated_limit"] = config.limit;
    info["signature"] = config.signature;
    
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
    out << cipher;
    out.close();
}

bool GateKeeper::ActivateSL(std::string path, unsigned signature)
{
    // Parse SL sections
    std::ifstream in(path);
    std::stringstream buffer;  
    buffer << in.rdbuf();  
    std::string ciphertext(buffer.str());

    int cipher_size = key_size / 8;
    std::string cipher_token = ciphertext.substr(0, cipher_size);
    std::string public_key = GetPublicKey();
    // Decrypt SL
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey rsa_private_key;
    CryptoPP::StringSource ss(GetPrivateKey().c_str(), true);
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
    internal_config.signature = info["signature"];
    // Modify activated info
    internal_config.activated_count++;
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

    internal_config.activated_dates.push_back(now);
    activated_dates_vector.push_back(TimePointToString(now));
    
    if(!DurationCheck(now, internal_config.generated_date, internal_config.activated_dates, internal_config.duration) ||
       !ExecutionCountCheck(internal_config.activated_count, internal_config.activated_limit) ||
       internal_config.signature != signature)
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
    CryptoPP::PEM_Load(public_key_source, rsa_public_key);

    CryptoPP::RSAES_OAEP_SHA_Encryptor rsa_encrypt(rsa_public_key);
    // Encryption
    CryptoPP::StringSource ss_encrypt(token, true, 
                                      new CryptoPP::PK_EncryptorFilter(rng, rsa_encrypt, 
                                      new CryptoPP::StringSink(cipher)));

    // Generate SL
    std::ofstream out(path);
    out << cipher;
    out.close();
    return true;
}

bool GateKeeper::VerifySL(std::string path, unsigned signature)
{
    // Parse SL sections
    std::ifstream in(path);
    std::stringstream buffer;  
    buffer << in.rdbuf();  
    std::string ciphertext(buffer.str());

    int cipher_size = key_size / 8;
    std::string cipher_token = ciphertext.substr(0, cipher_size);
    // Decrypt SL
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey rsa_private_key;
    CryptoPP::StringSource ss(GetPrivateKey().c_str(), true);
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
    internal_config.signature = info["signature"];
    // Modify activated info
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    internal_config.activated_dates.push_back(now);
    
    if(!DurationCheck(now, internal_config.generated_date, internal_config.activated_dates, internal_config.duration) ||
       !ExecutionCountCheck(internal_config.activated_count, internal_config.activated_limit) ||
       internal_config.signature != signature)
        return false;
    else
        return true;

}

Guard::Guard(std::string path)
{
    // Parse SL sections
    this->path = path;
    std::ifstream in(path);
    std::stringstream buffer;  
    buffer << in.rdbuf();  
    ciphertext = std::string(buffer.str());
}

Guard::~Guard()
{
}

bool Guard::Activate(unsigned signature)
{
    int cipher_size = key_size / 8;
    std::string cipher_token = ciphertext.substr(0, cipher_size);
    std::string public_key = GetPublicKey();
    // Decrypt SL
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey rsa_private_key;
    CryptoPP::StringSource ss(GetPrivateKey().c_str(), true);
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
    internal_config.signature = info["signature"];
    // Modify activated info
    internal_config.activated_count++;
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

    internal_config.activated_dates.push_back(now);
    activated_dates_vector.push_back(TimePointToString(now));
    
    if(!DurationCheck(now, internal_config.generated_date, internal_config.activated_dates, internal_config.duration) ||
       !ExecutionCountCheck(internal_config.activated_count, internal_config.activated_limit) ||
       internal_config.signature != signature)
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
    CryptoPP::PEM_Load(public_key_source, rsa_public_key);

    CryptoPP::RSAES_OAEP_SHA_Encryptor rsa_encrypt(rsa_public_key);
    // Encryption
    CryptoPP::StringSource ss_encrypt(token, true, 
                                      new CryptoPP::PK_EncryptorFilter(rng, rsa_encrypt, 
                                      new CryptoPP::StringSink(cipher)));

    // Generate SL
    std::ofstream out(path);
    out << cipher;
    out.close();
    return true;
}

bool Guard::Verify(unsigned signature)
{
    int cipher_size = key_size / 8;
    std::string cipher_token = ciphertext.substr(0, cipher_size);
    // Decrypt SL
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey rsa_private_key;
    CryptoPP::StringSource ss(GetPrivateKey().c_str(), true);
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
    internal_config.signature = info["signature"];
    // Modify activated info
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    internal_config.activated_dates.push_back(now);
    
    if(!DurationCheck(now, internal_config.generated_date, internal_config.activated_dates, internal_config.duration) ||
       !ExecutionCountCheck(internal_config.activated_count, internal_config.activated_limit) ||
       internal_config.signature != signature)
        return false;
    else
        return true;
}