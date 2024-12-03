#include "node-manager.h"

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/utils.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

// Testing
#include <iomanip>
#include <openssl/err.h>
#include <random>

#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT                                                                      \
    std::clog << "\033[36m[" << Simulator::Now().GetSeconds() << "][" << node_address.GetIpv4()    \
              << "] "
#define ERROR_LOG(message) NS_LOG_ERROR("\033[31m[ERROR] " << message << "\033[0m")
#define INFO_LOG(message) NS_LOG_INFO("\033[34m[INFO] " << message << "\033[0m")
#define SUCCESS_LOG(message) NS_LOG_INFO("\033[32m[SUCCESS] " << message << "\033[0m")
#define WARN_LOG(message) NS_LOG_WARN("\033[33m[LOG] " << message << "\033[0m")

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("NodeManagerLog");

std::random_device rd; 
std::mt19937 gen(rd());
std::uniform_int_distribution<> distrib(1, 100); 

std::vector<ns3::InetSocketAddress> NodeManager::node_address_list;
float NodeManager::energy_consumed = 0.0f;
int NodeManager::total_nodes = 0;

NodeManager::NodeManager(Ptr<Node> node,
                         uint16_t node_id,
                         InetSocketAddress address,
                         InetSocketAddress sinkAddress)
    : node(node),
      node_id(node_id),
      node_address(address),
      sink_address(sinkAddress)
{
    start_time = Simulator::Now().GetSeconds();

    sink_distance_score = distrib(gen);

    // uint8_t lastByte = node_address.GetIpv4().Get() & 0xFF;
    // INFO_LOG(node_address.GetIpv4() << "  " << static_cast<int>(lastByte));
    // INFO_LOG("Generating Node " << node_id << " CSR");
    GenerateKeypairAndCSR();

    node_socket = Socket::CreateSocket(node, TypeId::LookupByName("ns3::UdpSocketFactory"));
    node_socket->Bind(address);
    node_socket->SetRecvCallback(MakeCallback(&NodeManager::HandleSocketReceive, this));

    CertificateEnrollment();
}

NodeManager::~NodeManager()
{
    float total_energy_consumed_power_down_mode = PowerDownModeEnergyConsumption(
        Simulator::Now().GetSeconds() - start_time - active_mode_time);

    float total_energy_consumed_active_mode = ActiveModeEnergyConsumption(active_mode_time);

    total_energy_consumed += total_energy_consumed_power_down_mode;
    total_energy_consumed += total_energy_consumed_active_mode;

    INFO_LOG("Node " << node_id << " consumed " << total_energy_consumed << "J");
    // , Sent "<< total_bytes_sent << " bytes and Received " << total_bytes_received         << "
    // bytes.");

    energy_consumed += total_energy_consumed;
    if (node_id == total_nodes)
    {
        INFO_LOG("Average Energy consumed: " << GetAverageEnergy() << "Joules");
    }
}

void
NodeManager::SendMessage(InetSocketAddress destination_address,
                         const uint8_t* buffer,
                         int buffer_length)
{
    // INFO_LOG("Sending data from " << node_address.GetIpv4() << " to "
                                //   << destination_address.GetIpv4() << " of size " << buffer_length);
    total_bytes_sent += buffer_length;
    total_energy_consumed += DataTransmitEnergyConsumption(buffer_length);

    Ptr<Packet> packet = Create<Packet>(buffer, buffer_length);
    node_socket->SendTo(packet, 0, destination_address);
    // INFO_LOG("Message sent to: ");
}

void
NodeManager::GenerateKeypairAndCSR()
{
    float function_start_time = Simulator::Now().GetSeconds();

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
    {
        ERROR_LOG("Error initializing ECC key generation");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    if (EVP_PKEY_keygen(pctx, &node_keypair) <= 0)
    {
        ERROR_LOG("Error generating ECC key");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY_CTX_free(pctx);

    node_csr = X509_REQ_new();
    if (!node_csr || X509_REQ_set_pubkey(node_csr, node_keypair) <= 0)
    {
        ERROR_LOG("Error creating or setting public key in CSR");
        X509_REQ_free(node_csr);
        return;
    }

    if (X509_REQ_sign(node_csr, node_keypair, EVP_sha256()) <= 0)
    {
        ERROR_LOG("Error signing CSR");
        X509_REQ_free(node_csr);
        return;
    }

    SUCCESS_LOG("User private key and CSR generated successfully.");

    active_mode_time += Simulator::Now().GetSeconds() - function_start_time;
}

bool
NodeManager::VerifyCertificate(X509* cert)
{
    float function_start_time = Simulator::Now().GetSeconds();

    if (!cert || !sink_public_key)
    {
        ERROR_LOG("Certificate or public key is missing.");
        return false;
    }

    // Verify the certificate using the public key directly
    int result = X509_verify(cert, sink_public_key);

    if (result != 1)
    {
        ERROR_LOG("Certificate verification failed.");
        return false;
    }

    active_mode_time += Simulator::Now().GetSeconds() - function_start_time;

    // INFO_LOG("Certificate verified successfully.");
    return true;
}

uint8_t*
NodeManager::SignData(const uint8_t* data, size_t data_size, int& sig_size)
{
    float function_start_time = Simulator::Now().GetSeconds();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ERROR_LOG("Failed to create EVP_MD_CTX: " << ERR_error_string(ERR_get_error(), nullptr));
        sig_size = 0;
        return nullptr;
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, node_keypair) != 1)
    {
        ERROR_LOG(
            "Failed to initialize DigestSign: " << ERR_error_string(ERR_get_error(), nullptr));
        EVP_MD_CTX_free(ctx);
        sig_size = 0;
        return nullptr;
    }

    if (EVP_DigestSignUpdate(ctx, data, data_size) != 1)
    {
        ERROR_LOG("Failed to update DigestSign: " << ERR_error_string(ERR_get_error(), nullptr));
        EVP_MD_CTX_free(ctx);
        sig_size = 0;
        return nullptr;
    }

    size_t temp_sig_size = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &temp_sig_size) != 1)
    {
        ERROR_LOG("Failed to finalize DigestSign (get size): " << ERR_error_string(ERR_get_error(),
                                                                                   nullptr));
        EVP_MD_CTX_free(ctx);
        sig_size = 0;
        return nullptr;
    }

    uint8_t* signature = new uint8_t[temp_sig_size];
    sig_size = static_cast<int>(temp_sig_size);
    if (EVP_DigestSignFinal(ctx, signature, &temp_sig_size) != 1)
    {
        ERROR_LOG("Failed to finalize DigestSign: " << ERR_error_string(ERR_get_error(), nullptr));
        EVP_MD_CTX_free(ctx);
        delete[] signature;
        sig_size = 0;
        return nullptr;
    }

    if (!VerifyData(data, data_size, signature, sig_size, node_certificate))
    {
        ERROR_LOG("Self Signature Verification Failed");
        EVP_MD_CTX_free(ctx);
        sig_size = 0;
        return nullptr;
    }

    EVP_MD_CTX_free(ctx);

    active_mode_time += Simulator::Now().GetSeconds() - function_start_time;

    return signature;
}

bool
NodeManager::VerifyData(const uint8_t* data,
                        size_t data_size,
                        const uint8_t* signature,
                        int sig_size,
                        X509* cert)
{
    float function_start_time = Simulator::Now().GetSeconds();

    EVP_PKEY* public_key = X509_get_pubkey(cert);
    if (!public_key)
    {
        ERROR_LOG("Failed to extract public key from certificate");
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ERROR_LOG("Failed to create EVP_MD_CTX: " << ERR_error_string(ERR_get_error(), nullptr));
        EVP_PKEY_free(public_key);
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) != 1)
    {
        ERROR_LOG(
            "Failed to initialize DigestVerify: " << ERR_error_string(ERR_get_error(), nullptr));
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, data, data_size) != 1)
    {
        ERROR_LOG("Failed to update DigestVerify: " << ERR_error_string(ERR_get_error(), nullptr));
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    int verify_result = EVP_DigestVerifyFinal(ctx, signature, sig_size);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);

    if (verify_result == 2)
    {
        ERROR_LOG("Signature verification failed: " << ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }

    active_mode_time += Simulator::Now().GetSeconds() - function_start_time;

    return true;
}

void
NodeManager::StartConnectionWithNeighbours()
{
    uint8_t size = node_address_list.size();
    node_address_list.push_back(node_address);
    for (uint8_t i = 0; i < size; ++i)
    {
        ConnectWithNeighbourNode(node_address_list[i]);
    }
}

void
NodeManager::ConnectWithNeighbourNode(InetSocketAddress address)
{
    for (int i = 0; i < request_sent.size(); ++i)
    {
        if (request_sent[i] == address)
        {
            return;
        }
    }

    uint8_t neighbour_identifier = address.GetIpv4().Get() & 0xFF;

    float current_time = Simulator::Now().GetSeconds();
    uint8_t signing_time[4];
    std::memcpy(signing_time, &current_time, 4);

    size_t total_size = 5;
    uint8_t* data = new uint8_t[total_size];
    data[0] = neighbour_identifier;
    std::memcpy(data + 1, signing_time, 4);

    int signature_size = 0;
    uint8_t* signed_data = SignData(data, total_size, signature_size);

    uint8_t packet_type = 7;

    int cert_size;
    uint8_t* node_cert_buffer = ConvertToUint8T(node_certificate, cert_size);

    int pack_buffer_size = 1 + 4 + 1 + signature_size + cert_size;
    uint8_t* packet_buffer = GeneratePacketBuffer(packet_type,
                                                  signing_time,
                                                  signature_size,
                                                  signed_data,
                                                  node_cert_buffer,
                                                  cert_size,
                                                  pack_buffer_size);
    request_sent.push_back(address);
    INFO_LOG("Sending verification request to " << address.GetIpv4());
    SendMessage(address, packet_buffer, pack_buffer_size);
}

void
NodeManager::CertificateEnrollment()
{
    uint8_t request_type = 1;
    int request_content_length = 0;
    uint8_t* request_content = ConvertToUint8T(node_csr, request_content_length);
    // INFO_LOG("SIZE of request content: " << request_content_length);

    int total_size = 2 + request_content_length;
    uint8_t* packet_buffer = GeneratePacketBuffer(request_type, request_content, total_size);

    Simulator::Schedule(Seconds(0.1), // add delay based on thier id
                        &NodeManager::SendMessage,
                        this,
                        sink_address,
                        packet_buffer,
                        total_size);
}

void
NodeManager::HandleSocketReceive(Ptr<ns3::Socket> socket)
{
    Address received_from;
    Ptr<Packet> packet = socket->RecvFrom(received_from);
    int packet_size = static_cast<int>(packet->GetSize());
    InetSocketAddress destination_address = InetSocketAddress::ConvertFrom(received_from);

    // INFO_LOG("Node " << node_address.GetIpv4() << " received data from "
    //                  << destination_address.GetIpv4() << " of packet of size " << packet_size
    //                  << " bytes");

    total_energy_consumed += DataReceiveEnergyConsumption(packet_size);
    total_bytes_received += packet_size;

    std::vector<uint8_t> received_data(packet_size);
    packet->CopyData(received_data.data(), received_data.size());

    int packet_content_size = received_data.size() - 1;
    uint8_t* packet_content = new uint8_t[packet_content_size];
    std::copy(received_data.begin() + 1, received_data.end(), packet_content);

    int request_type = static_cast<int>(received_data[0]);
    // int response_size = 0;
    switch (request_type)
    {
    case 2: {
        SinkPathBroadcastResponse(destination_address);
        break;
    }

    case 3: {
        SUCCESS_LOG("Reveived data from NODE " << destination_address.GetIpv4());
        break;
    }

    case 6: {
        ParseSinkPathBroadcastResponse(destination_address, packet_content);
        break;
    }

    case 7: {
        int offset = 0;

        uint8_t signing_time[4];
        memcpy(signing_time, packet_content + offset, 4);
        offset += 4;

        int signature_size = static_cast<int>(packet_content[offset]);
        offset += 1;

        uint8_t* signed_data = new uint8_t[signature_size];
        memcpy(signed_data, packet_content + offset, signature_size);
        offset += signature_size;

        int neighbour_certificate_size = packet_content_size - offset;

        uint8_t* neighbour_certificate = new uint8_t[neighbour_certificate_size];
        memcpy(neighbour_certificate, packet_content + offset, neighbour_certificate_size);

        X509* cert = ConvertToX509(neighbour_certificate, neighbour_certificate_size);
        if (VerifyCertificate(cert))
        {
            // SUCCESS_LOG("Certificate of node " << destination_address.GetIpv4() << " verified.");

            uint8_t self_identifier = node_address.GetIpv4().Get() & 0xFF;
            size_t total_size = 5;
            uint8_t* data = new uint8_t[5];
            data[0] = self_identifier;
            std::memcpy(data + 1, signing_time, 4);

            if (VerifyData(data, total_size, signed_data, signature_size, cert))
            {
                // SUCCESS_LOG("Signature of node " << destination_address.GetIpv4() << " verified.");
                SUCCESS_LOG("Node " << destination_address.GetIpv4() << " verified.");
                verified_nodes.push_back(destination_address);
                ConnectWithNeighbourNode(destination_address);
            }
            else
            {
                ERROR_LOG("Failed to verify the signature of " << destination_address.GetIpv4());
            }
        }
        else
        {
            ERROR_LOG("Failed to verify the certificate of " << destination_address.GetIpv4());
        }
        break;
    }

    case 8: {
        sink_public_key = ConvertToEVP_PKEY(packet_content, packet_content_size);
        // INFO_LOG(packet_content_size);
        if (EVP_PKEY_size(sink_public_key) > 0)
        {
            SUCCESS_LOG("Node " << node_address.GetIpv4() << " received sink public key");
            StartConnectionWithNeighbours();
        }
        else
        {
            ERROR_LOG("Failed to save CA public key.");
        }
        break;
    }

    case 9: {
        node_certificate = ConvertToX509(packet_content, packet_content_size);
        SUCCESS_LOG("Node " << node_address.GetIpv4() << " received certificate from "
                            << InetSocketAddress::ConvertFrom(received_from).GetIpv4());
        break;
    }

    default: {
        ERROR_LOG("Packet type " << request_type << " not matched.");
        break;
    }
    }
}

float
NodeManager::GetAverageEnergy()
{
    if (total_nodes == 0)
    {
        return 0.0f;
    }
    return energy_consumed / total_nodes;
}

float
NodeManager::ActiveModeEnergyConsumption(float time_taken) // time_taken in seconds
{
    return 0.0138 * time_taken;
}

float
NodeManager::PowerDownModeEnergyConsumption(float time_taken) // time_taken in seconds
{
    return 0.0000075 * time_taken;
}

float
NodeManager::DataTransmitEnergyConsumption(int data_size)
{
    return 50 * 8 * data_size * 0.0000001;
}

float
NodeManager::DataReceiveEnergyConsumption(int data_size) 
{
    return 25 * 8 * data_size * 0.0000001;
}

void
NodeManager::SinkPathBroadcastRequest()
{
    uint8_t size = node_address_list.size();
    uint8_t packet_type = 2;
    for (uint8_t i = 0; i < size; ++i)
    {
        if (node_address != node_address_list[i])
        {
            SendMessage(node_address_list[i], &packet_type, 1);
        }
    }
    INFO_LOG("Node " << node_address.GetIpv4() << " is sending best path broadcast request");
    Simulator::Schedule(Seconds(5), &NodeManager::SendDataToBestNode, this);
}

void
NodeManager::SinkPathBroadcastResponse(InetSocketAddress address)
{
    int packet_type = 6;
    uint8_t* packet_buffer = new uint8_t(2);
    packet_buffer[0] = packet_type;
    packet_buffer[1] = sink_distance_score;

    // INFO_LOG("Sending sink distance score of " << sink_distance_score << " to " << address.GetIpv4());
    Simulator::Schedule(Seconds(0.1), &NodeManager::SendMessage,this, address, packet_buffer, 2);
}

void
NodeManager::ParseSinkPathBroadcastResponse(InetSocketAddress address, uint8_t* packet_content)
{
    // INFO_LOG("Received Score from " << address.GetIpv4());
    bool is_address_present = false;
    uint8_t size = verified_nodes.size();
    for (uint8_t i = 0; i < size; ++i)
    {
        if (verified_nodes[i] == address)
        {
            is_address_present = true;
        }
    }

    if (!is_address_present)
    {
        ERROR_LOG("Black hole attack detected, ignoring respose from " << address.GetIpv4());
    }
    else
    {
        int score = static_cast<int>(packet_content[0]);
        if (score > best_socored_neighbour.second)
        {
            INFO_LOG("Current best score " << score << " is from Node: " << address.GetIpv4());
            best_socored_neighbour.first = address;
            best_socored_neighbour.second = score;
        }
    }
}


void NodeManager::SendDataToBestNode()
{
    int packet_type = 3;
    uint8_t* packet_buffer = new uint8_t(3);
    packet_buffer[0] = packet_type;
    std::memcpy(packet_buffer+1, "OK", 2);

    INFO_LOG("Node with the best score is " << best_socored_neighbour.first.GetIpv4());
    SendMessage(best_socored_neighbour.first, packet_buffer, 3);
}