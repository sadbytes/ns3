#ifndef NODE_MANAGER_H
#define NODE_MANAGER_H

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ssid.h"
#include "ns3/yans-wifi-helper.h"

#include <openssl/x509.h>

using namespace ns3;

class NodeManager
{
  public:
    static std::vector<InetSocketAddress> node_address_list;
    static float energy_consumed; 
    static float GetAverageEnergy(int total_nodes);


  public:
    Ptr<Node> node;
    uint16_t node_id;
    InetSocketAddress node_address;
    Ptr<Socket> node_socket;
    InetSocketAddress sink_address;
    std::vector<InetSocketAddress> request_sent;
    float total_energy_consumed = 0;

    NodeManager(Ptr<Node> node,
                uint16_t node_id,
                InetSocketAddress address,
                InetSocketAddress sinkAddress);
    ~NodeManager();
    void SendMessage(InetSocketAddress destination_address,
                     const uint8_t* buffer,
                     int buffer_length);
    void HandleSocketReceive(Ptr<Socket> socket);
    void StartConnectionWithNeighbours();
    void ConnectWithNeighbourNode(InetSocketAddress address);

  public:
    EVP_PKEY* node_keypair = nullptr;
    X509_REQ* node_csr = nullptr;
    X509* node_certificate = nullptr;
    EVP_PKEY* sink_public_key = nullptr;

    void GenerateKeypairAndCSR();
    void CertificateEnrollment();
    bool VerifyCertificate(X509* cert);
    uint8_t* SignData(const uint8_t* data, size_t data_size, int& sig_size);
    bool VerifyData(const uint8_t* data,
                    size_t data_size,
                    const uint8_t* signature,
                    int sig_size,
                    X509* node_certificate);
};
#endif
