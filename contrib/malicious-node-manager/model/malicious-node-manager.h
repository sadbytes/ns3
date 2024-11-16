#ifndef MALICIOUS_NODE_MANAGER_H
#define MALICIOUS_NODE_MANAGER_H

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/utils.h"

using namespace ns3;

class MaliciousNodeManager
{
  public:
    Ptr<Node> malicous_node;
    InetSocketAddress malicous_node_address;
    Ptr<Socket> malicous_node_socket;
    

    MaliciousNodeManager(Ptr<Node> node, InetSocketAddress address);
    void AddMaliciousNodeToWSN();
    void HandleSocketReceive(Ptr<Socket> socket);
    void SendMessage(InetSocketAddress destination_address, const uint8_t* buffer, int buffer_length);
};

#endif /* MALICIOUS_NODE_MANAGER_H */
