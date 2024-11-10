#ifndef UTILS_H
#define UTILS_H

#include "ns3/core-module.h"

#include <openssl/x509.h>

using namespace ns3;

uint8_t* ConvertToUint8T(EVP_PKEY* req, int& length);
uint8_t* ConvertToUint8T(X509* cert, int& length);
uint8_t* ConvertToUint8T(X509_REQ* req, int& length);

X509* ConvertToX509(uint8_t* derData, int length);
EVP_PKEY* ConvertToEVP_PKEY(uint8_t* derData, int length);

uint8_t* GeneratePacketBuffer(uint8_t type, uint8_t* content, int content_size);
uint8_t* GeneratePacketBuffer(uint8_t packet_type,
                              uint8_t* signing_time,
                              int signature_size,
                              uint8_t* signed_data,
                              uint8_t* node_certificate,
                              int node_certificate_size,
                              int total_size);

std::string ConvertToHex(const std::vector<uint8_t>& data);
std::string ConvertToHex(const uint8_t* data, int size);

#endif /* UTILS_H */
