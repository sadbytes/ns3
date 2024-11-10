#include "malicious-node-manager.h"

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/utils.h"


#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT                                                                      \
    std::clog << "\033[36m[" << Simulator::Now().GetSeconds() << "][" << malicous_node_address.GetIpv4()    \
              << "] "
#define ERROR_LOG(message) NS_LOG_ERROR("\033[31m[ERROR] " << message << "\033[0m")
#define INFO_LOG(message) NS_LOG_INFO("\033[34m[INFO] " << message << "\033[0m")
#define SUCCESS_LOG(message) NS_LOG_INFO("\033[32m[SUCCESS] " << message << "\033[0m")
#define WARN_LOG(message) NS_LOG_WARN("\033[33m[LOG] " << message << "\033[0m")

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("MaliciousNodeManagerLog");

MaliciousNodeManager::MaliciousNodeManager(Ptr<Node> node, InetSocketAddress address)
    : malicous_node(node),
      malicous_node_address(address)
{
    malicous_node_socket =
        Socket::CreateSocket(node, TypeId::LookupByName("ns3::UdpSocketFactory"));
    malicous_node_socket->Bind(address);
    malicous_node_socket->SetRecvCallback(
        MakeCallback(&MaliciousNodeManager::HandleSocketReceive, this));
}

void
MaliciousNodeManager::SendMessage(InetSocketAddress destination_address,
                         const uint8_t* buffer,
                         int buffer_length)
{
    Ptr<Packet> packet = Create<Packet>(buffer, buffer_length);
    malicous_node_socket->SendTo(packet, 0, destination_address);
}

void
MaliciousNodeManager::HandleSocketReceive(Ptr<ns3::Socket> socket)
{
    Address received_from;
    Ptr<Packet> packet = socket->RecvFrom(received_from);
    int packet_size = static_cast<int>(packet->GetSize());
    InetSocketAddress destination_address = InetSocketAddress::ConvertFrom(received_from);

    std::vector<uint8_t> received_data(packet_size);
    packet->CopyData(received_data.data(), received_data.size());

    int packet_content_size = received_data.size() - 1;
    uint8_t* packet_content = new uint8_t[packet_content_size];
    std::copy(received_data.begin() + 1, received_data.end(), packet_content);

    int request_type = static_cast<int>(received_data[0]);

    switch (request_type)
    {
    case 2: {
        uint8_t packet_buffer[2];
        packet_buffer[0] = 6;
        packet_buffer[1] = 100;
        SendMessage(destination_address, packet_buffer, 2);
    }
    case 5: {
        ERROR_LOG("Black hole attack occured!!!");
    }
    }
}