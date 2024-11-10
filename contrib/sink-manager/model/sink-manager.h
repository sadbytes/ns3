#ifndef SINK_MANAGER_H
#define SINK_MANAGER_H

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ssid.h"
#include "ns3/yans-wifi-helper.h"

#include <openssl/x509.h>

using namespace ns3;

class SinkManager
{
  public:
    EVP_PKEY* ca_keypair = nullptr;
    EVP_PKEY* ca_public_key = nullptr;
    X509* ca_cert = nullptr;
    EVP_PKEY_CTX* pctx = nullptr;

    uint8_t* converted_ca_public_key;
    int converted_ca_public_key_size;

    void InitializeCA();
    X509* GenerateUserCertificate(X509_REQ* csr);
    X509_REQ* ConvertToX509_REQ(uint8_t* derData, int length);


  public:
    Ptr<Node> sink;
    InetSocketAddress address;
    Ptr<Socket> sinkSocket;

    SinkManager(Ptr<Node> node, InetSocketAddress address);
    void HandleSocketReceive(Ptr<Socket> socket);
    void SendMessage(InetSocketAddress destination_address, const uint8_t* buffer, int buffer_length);
};
#endif /* SINK_MANAGER_H */
