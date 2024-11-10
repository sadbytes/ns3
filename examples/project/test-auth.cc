#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/node-manager.h"
#include "ns3/point-to-point-module.h"
#include "ns3/sink-manager.h"
#include "ns3/ssid.h"
#include "ns3/yans-wifi-helper.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("test-auth-log");

int
main()
{
    LogComponentEnable("test-auth-log", LOG_LEVEL_INFO);
    LogComponentEnable("SinkManagerLog", LOG_LEVEL_INFO);

    int total_nodes = 2;
    // std::vector<SinkManager> SinkManagerContainer;

    NodeContainer nodes;
    nodes.Create(total_nodes);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));
    NetDeviceContainer nodeDevices = p2p.Install(nodes);

    NS_LOG_INFO("Installing internet stack.");
    InternetStackHelper internet;
    internet.Install(nodes);

    NS_LOG_INFO("Assigning IP addresses.");
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(nodeDevices);

    SinkManager sink = SinkManager(nodes.Get(0), InetSocketAddress(interfaces.GetAddress(0), 8080));
    NodeManager node = NodeManager(nodes.Get(1),
                                   1,
                                   InetSocketAddress(interfaces.GetAddress(1), 8080),
                                   sink.address);
    // Simulator::Schedule(Seconds(0.1), std::bind(&NodeManager::SignData, &node, "HELLO"));

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}