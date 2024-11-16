#ifndef NODE_MANAGER_H
#define NODE_MANAGER_H

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"

#include <openssl/x509.h>

using namespace ns3;

class NodeManager
{
  public:
    static std::vector<InetSocketAddress> node_address_list;
    static int total_nodes;
    static float energy_consumed; 
    static float GetAverageEnergy();


  public:
    Ptr<Node> node;
    uint16_t node_id;
    InetSocketAddress node_address;
    Ptr<Socket> node_socket;
    InetSocketAddress sink_address;
    std::vector<InetSocketAddress> request_sent;
    std::vector<InetSocketAddress> verified_nodes;
    // std::vector<InetSocketAddress> blacklisted_nodes;

    float start_time;
    float total_energy_consumed = 0;
    float active_mode_time = 0; // time taken doing processing things
    int total_bytes_sent;
    int total_bytes_received;

    int sink_distance_score; // range from 1-100
    std::pair<ns3::InetSocketAddress, uint8_t> best_socored_neighbour = std::make_pair(InetSocketAddress("10.1.1.0"), 0);

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

    void SinkPathBroadcastRequest();
    void SinkPathBroadcastResponse(InetSocketAddress address);
    void ParseSinkPathBroadcastResponse(InetSocketAddress address, uint8_t *packet_content);
    void SendDataToBestNode();

    float ActiveModeEnergyConsumption(float time_taken); // time_taken in seconds
    float PowerDownModeEnergyConsumption(float time_taken); // time_taken in seconds
    float DataTransmitEnergyConsumption(int data_size); // in bytes
    float DataReceiveEnergyConsumption(int data_size); // in bytes

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
