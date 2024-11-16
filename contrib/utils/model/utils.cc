#include "utils.h"

#include "ns3/core-module.h"

#include <openssl/x509.h>

//Testing
#include <iomanip> 

#define ERROR_LOG(message) NS_LOG_ERROR("\033[31m[ERROR] " << message << "\033[0m")
#define INFO_LOG(message) NS_LOG_INFO("\033[34m[INFO] " << message << "\033[0m")
#define SUCCESS_LOG(message) NS_LOG_INFO("\033[32m[SUCCESS] " << message << "\033[0m")
#define WARN_LOG(message) NS_LOG_WARN("\033[33m[LOG] " << message << "\033[0m")


using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UtilsLog");

uint8_t*
ConvertToUint8T(std::string message, int& length)
{
    length = message.size();
    uint8_t* packet_buffer = new uint8_t[length];
    memcpy(packet_buffer, message.c_str(), length);

    return packet_buffer;
}

uint8_t*
ConvertToUint8T(EVP_PKEY* pub_key, int& length)
{
    length = i2d_PUBKEY(pub_key, nullptr);
    // INFO_LOG("Size of public key: " << length);
    if (length < 0)
    {
        ERROR_LOG("Error converting X509 to DER format.");
        return nullptr;
    }

    uint8_t* der_uint8t = new uint8_t[length];

    unsigned char* temp = der_uint8t; 
    int convertedLength = i2d_PUBKEY(pub_key, &temp);
    if (convertedLength < 0)
    {
        NS_LOG_ERROR("Error during DER conversion.");
        delete[] der_uint8t;
        return nullptr;
    }

    return der_uint8t;
}

uint8_t*
ConvertToUint8T(X509* cert, int& length)
{
    // First, calculate the length of the DER-encoded data
    length = i2d_X509(cert, nullptr);
    if (length < 0)
    {
        NS_LOG_ERROR("Error converting X509 to DER format.");
        return nullptr;
    }

    // Allocate a uint8_t array to hold the DER data
    uint8_t* der_uint8t = new uint8_t[length];

    // Convert X509 to DER format and store it in der_uint8t
    unsigned char* temp = der_uint8t; // i2d_X509 uses an unsigned char** for output
    int convertedLength = i2d_X509(cert, &temp);
    if (convertedLength < 0)
    {
        NS_LOG_ERROR("Error during DER conversion.");
        delete[] der_uint8t;
        return nullptr;
    }

    return der_uint8t;
}

uint8_t*
ConvertToUint8T(X509_REQ* req, int& length)
{
    length = i2d_X509_REQ(req, nullptr);
    if (length < 0)
    {
        NS_LOG_ERROR("Error converting X509_REQ to DER format.");
        return nullptr;
    }

    // Allocate a uint8_t array to hold the DER data
    uint8_t* der_uint8t = new uint8_t[length];

    // Convert X509_REQ to DER format and store it in der_uint8t
    unsigned char* temp = der_uint8t; // i2d_X509_REQ uses an unsigned char** for output
    int convertedLength = i2d_X509_REQ(req, &temp);
    if (convertedLength < 0)
    {
        NS_LOG_ERROR("Error during DER conversion.");
        delete[] der_uint8t;
        return nullptr;
    }

    return der_uint8t;
}

X509* ConvertToX509(uint8_t* derData, int length)
{
    if (length <= 0)
    {
        ERROR_LOG("UINT8_T DER data length is 0.");
        return nullptr;
    }

    // Set a temporary pointer to the DER data
    const unsigned char* temp = derData;

    // Convert the DER data back to an X509 object
    X509* cert = d2i_X509(NULL, &temp, length);

    if (cert == nullptr)
    {
        ERROR_LOG("Error converting DER format to X509.");
    }

    return cert;
}


EVP_PKEY* ConvertToEVP_PKEY(uint8_t* derData, int length)
{
    if (length <= 0)
    {
        ERROR_LOG("UINT8_T DER data length is 0.");
        return nullptr;
    }

    // Set a temporary pointer to the DER data
    const unsigned char* temp = derData;

    // Convert the DER data back to an EVP_PKEY object
    EVP_PKEY* publicKey = d2i_PUBKEY(NULL, &temp, length);

    if (publicKey == nullptr)
    {
        ERROR_LOG("Error converting DER format to EVP_PKEY.");
    }

    return publicKey;
}



uint8_t*
GeneratePacketBuffer(uint8_t type, uint8_t* content, int total_size)
{
    uint8_t* packet_buffer = new uint8_t[total_size];
    packet_buffer[0] = type;
    

    memcpy(packet_buffer + 1, content, total_size); 

    return packet_buffer;
}

uint8_t* GeneratePacketBuffer(uint8_t packet_type, uint8_t* signing_time, int signature_size, 
                               uint8_t* signed_data, uint8_t* certificate, 
                               int certificate_size, int total_size)
{
    uint8_t* packet_buffer = new uint8_t[total_size];

    int offset = 0;

    packet_buffer[offset] = packet_type;
    offset += 1;

    memcpy(packet_buffer + offset, signing_time, 4);
    offset += 4;

    packet_buffer[offset] = static_cast<uint8_t>(signature_size);  // Ensuring it's in the correct type
    offset += 1;

    memcpy(packet_buffer + offset, signed_data, signature_size);
    offset += signature_size;

    memcpy(packet_buffer + offset, certificate, certificate_size);
    offset += certificate_size;

    // if (offset == total_size) {
        // SUCCESS_LOG("Total size and offset matched");
    // }

    return packet_buffer;
}



std::string ConvertToHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::string ConvertToHex(const uint8_t* data, int size) {
    std::ostringstream oss;
    for (int i = 0; i < size; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

