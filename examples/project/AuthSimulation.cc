#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/node-manager.h"
#include "ns3/point-to-point-module.h"
#include "ns3/sink-manager.h"
#include "ns3/utils.h"
// #include "ns3/malicious-node-manager.h"

#include <random>

#define ERROR_LOG(message) NS_LOG_ERROR("\033[31m[ERROR] " << message << "\033[0m")
#define INFO_LOG(message) NS_LOG_INFO("\033[34m[LOG] " << message << "\033[0m")
#define SUCCESS_LOG(message) NS_LOG_INFO("\033[34m[LOG] " << message << "\033[0m")

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("AuthSimulationLog");

int
main()
{
    LogComponentEnable("AuthSimulationLog", LOG_LEVEL_ALL);
    LogComponentEnable("SinkManagerLog", LOG_LEVEL_ALL);
    LogComponentEnable("NodeManagerLog", LOG_LEVEL_ALL);
    // LogComponentEnable("MaliciousNodeManagerLog", LOG_LEVEL_ALL);
    LogComponentEnable("UtilsLog", LOG_LEVEL_ALL);

    int total_nodes = 20;
    NodeManager::total_nodes = total_nodes;

    std::vector<NodeManager> NodeItemContainer;

    Ptr<Node> sink = CreateObject<Node>();

    // Ptr<Node> malicious_node = CreateObject<Node>();

    NodeContainer devices;
    devices.Add(sink);
    devices.Create(total_nodes);
    // devices.Add(malicious_node);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("500kbps"));
    // Increased data rate for now, will be set to normal when a queue system is developed.
    // Else different sized traffic breaks the simulation flow and causes error in some part.
    // csma.SetChannelAttribute("DataRate", StringValue("12.4kbps"));
    csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));
    NetDeviceContainer nodeDevices = csma.Install(devices);

    INFO_LOG("Installing internet stack.");
    InternetStackHelper internet;
    internet.Install(devices);

    INFO_LOG("Assigning IP addresses.");
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(nodeDevices);

    SinkManager sinkManager = SinkManager(sink, InetSocketAddress(interfaces.GetAddress(0), 8080));
    // MaliciousNodeManager malicious_node_manger = MaliciousNodeManager(malicious_node, InetSocketAddress(interfaces.GetAddress(-1), 8080));

    std::vector<std::unique_ptr<NodeManager>> nodeManagerContainer;

    for (uint8_t node_id = 1; node_id <= total_nodes; ++node_id)
    {
        nodeManagerContainer.push_back(
            std::make_unique<NodeManager>(devices.Get(node_id),
                                          node_id,
                                          InetSocketAddress(interfaces.GetAddress(node_id), 8080),
                                          sinkManager.address));
    }

    // Simulator::Schedule(Seconds(20),
    //                     [&]() { nodeManagerContainer[0]->SinkPathBroadcastRequest(); });

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}