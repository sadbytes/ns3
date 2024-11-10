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
#include <openssl/md5.h>

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

std::vector<ns3::InetSocketAddress> NodeManager::node_address_list;
float NodeManager::energy_consumed = 0.0f;
float NodeManager::GetAverageEnergy(int total_nodes)
{
    if (total_nodes == 0) {
        return 6.9f; 
    }
    return energy_consumed / total_nodes;
}

NodeManager::NodeManager(Ptr<Node> node,
                         uint16_t node_id,
                         InetSocketAddress address,
                         InetSocketAddress sinkAddress)
    : node(node),
      node_id(node_id),
      node_address(address),
      sink_address(sinkAddress)
{
    uint8_t lastByte = node_address.GetIpv4().Get() & 0xFF;
    INFO_LOG(node_address.GetIpv4() << "  " << static_cast<int>(lastByte));
    INFO_LOG("Generating Node CSR");
    GenerateKeypairAndCSR();

    node_socket = Socket::CreateSocket(node, TypeId::LookupByName("ns3::UdpSocketFactory"));
    node_socket->Bind(address);
    node_socket->SetRecvCallback(MakeCallback(&NodeManager::HandleSocketReceive, this));

    CertificateEnrollment();
}

NodeManager::~NodeManager()
{
    // INFO_LOG("Total energy consumed by node on address " << node_address.GetIpv4() << " is "
                                                        //  << (total_energy_consumed * 0.0000001)
                                                        //  << " Joules");
    energy_consumed += total_energy_consumed * 0.0000001;
    INFO_LOG(GetAverageEnergy(node_address_list.size()));
}

void
NodeManager::SendMessage(InetSocketAddress destination_address,
                         const uint8_t* buffer,
                         int buffer_length)
{
    INFO_LOG("Sending data from " << node_address.GetIpv4() << " to "
                                  << destination_address.GetIpv4());
    float energy_consumed = 50 * 8 * buffer_length;
    total_energy_consumed += energy_consumed;
    INFO_LOG("Energy consumed by node to send the data: " << energy_consumed << "pJ");
    Ptr<Packet> packet = Create<Packet>(buffer, buffer_length);
    node_socket->SendTo(packet, 0, destination_address);
    // INFO_LOG("Message sent to: ");
}

void
NodeManager::GenerateKeypairAndCSR()
{
    // Generate ECC private key
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
    {
        ERROR_LOG("Error initializing ECC key generation");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    // Generate ECC key pair
    if (EVP_PKEY_keygen(pctx, &node_keypair) <= 0)
    {
        ERROR_LOG("Error generating ECC key");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY_CTX_free(pctx);

    // Create CSR and set public key
    node_csr = X509_REQ_new();
    if (!node_csr || X509_REQ_set_pubkey(node_csr, node_keypair) <= 0)
    {
        ERROR_LOG("Error creating or setting public key in CSR");
        X509_REQ_free(node_csr);
        return;
    }

    // Sign the CSR
    if (X509_REQ_sign(node_csr, node_keypair, EVP_sha256()) <= 0)
    {
        ERROR_LOG("Error signing CSR");
        X509_REQ_free(node_csr);
        return;
    }

    SUCCESS_LOG("User private key and CSR generated successfully.");
}

bool
NodeManager::VerifyCertificate(X509* cert)
{
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

    INFO_LOG("Certificate verified successfully.");
    return true;
}

uint8_t*
NodeManager::SignData(const uint8_t* data, size_t data_size, int& sig_size)
{
    // Create a context for the signing operation
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

    return signature;
}

bool
NodeManager::VerifyData(const uint8_t* data,
                        size_t data_size,
                        const uint8_t* signature,
                        int sig_size,
                        X509* cert)
{
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
    return true;
}

void
NodeManager::StartConnectionWithNeighbours()
{
    node_address_list.push_back(node_address);
    for (uint8_t i = 0; i < node_address_list.size() - 1; ++i)
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

    Simulator::Schedule(Seconds(1),
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
    InetSocketAddress destination_address = InetSocketAddress::ConvertFrom(received_from);

    INFO_LOG("Node " << node_address.GetIpv4() << " received data from "
                     << destination_address.GetIpv4() << " of packet of size " << packet->GetSize()
                     << " bytes");
    float energy_consumed = 25 * 8 * packet->GetSize();
    total_energy_consumed += energy_consumed;
    INFO_LOG("Energy consumed by node to receive the data: " << energy_consumed << "pJ");

    std::vector<uint8_t> received_data(packet->GetSize());
    packet->CopyData(received_data.data(), received_data.size());

    int packet_content_size = received_data.size() - 1;
    uint8_t* packet_content = new uint8_t[packet_content_size];
    std::copy(received_data.begin() + 1, received_data.end(), packet_content);

    int request_type = static_cast<int>(received_data[0]);
    // int response_size = 0;
    switch (request_type)
    {
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
            SUCCESS_LOG("Certificate of node " << destination_address.GetIpv4() << " verified.");

            uint8_t self_identifier = node_address.GetIpv4().Get() & 0xFF;
            size_t total_size = 5;
            uint8_t* data = new uint8_t[5];
            data[0] = self_identifier;
            std::memcpy(data + 1, signing_time, 4);

            if (VerifyData(data, total_size, signed_data, signature_size, cert))
            {
                SUCCESS_LOG("Signature of node " << destination_address.GetIpv4() << " verified.");
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
        INFO_LOG(packet_content_size);
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
