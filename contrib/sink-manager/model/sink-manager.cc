#include "sink-manager.h"

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/utils.h"

#include <err.h>
#include <openssl/x509.h>

// Testing
#include <iomanip>

#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT                                                                      \
    std::clog << "\033[35m[" << Simulator::Now().GetSeconds() << "][" << address.GetIpv4() << "] "
#define ERROR_LOG(message) NS_LOG_ERROR("\033[31m[ERROR] " << message << "\033[0m")
#define INFO_LOG(message) NS_LOG_INFO("\033[34m[LOG] " << message << "\033[0m")
#define SUCCESS_LOG(message) NS_LOG_INFO("\033[32m[LOG] " << message << "\033[0m")
#define WARN_LOG(message) NS_LOG_WARN("\033[33m[LOG] " << message << "\033[0m")

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SinkManagerLog");


SinkManager::SinkManager(Ptr<Node> node, InetSocketAddress address)
    : sink(node),
      address(address)
{
    INFO_LOG("Creating new sink on address " << address.GetIpv4() << ":" << address.GetPort());

    InitializeCA();

    sinkSocket = Socket::CreateSocket(sink, TypeId::LookupByName("ns3::UdpSocketFactory"));
    sinkSocket->Bind(address);
    sinkSocket->SetRecvCallback(MakeCallback(&SinkManager::HandleSocketReceive, this));
}

void
SinkManager::InitializeCA()
{
    // Generate ECC private key
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
    // wanted to used NID_X9_62_prime192v1 but it's not available currently in my openssl
    // installation
    //  openssl ecparam -list_curves
    {
        ERROR_LOG("Error initializing ECC key generation");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    if (EVP_PKEY_keygen(pctx, &ca_keypair) <= 0)
    {
        ERROR_LOG("Error generating ECC key");
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY_CTX_free(pctx);

    // Create self-signed certificate
    ca_cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(ca_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(ca_cert), 31536000L); // 1 year validity

    X509_set_pubkey(ca_cert, ca_keypair);

    // Self-sign the certificate
    if (X509_sign(ca_cert, ca_keypair, EVP_sha256()) == 0)
    {
        ERROR_LOG("Error signing CA certificate.");
        X509_free(ca_cert);
        return;
    }

    // Store the public key
    ca_public_key = X509_get_pubkey(ca_cert);
    converted_ca_public_key = ConvertToUint8T(ca_public_key, converted_ca_public_key_size);

    SUCCESS_LOG("CA keypair and certificate generated successfully.");
}

X509*
SinkManager::GenerateUserCertificate(X509_REQ* csr)
{
    // Create a new X509 certificate
    X509* user_cert = X509_new();
    if (!user_cert)
    {
        INFO_LOG("Error creating new X509 certificate");
        return NULL;
    }

    // Set the version (1 for X509v3)
    X509_set_version(user_cert, 2);

    // Set the serial number
    ASN1_INTEGER* serial_number = ASN1_INTEGER_new();
    ASN1_INTEGER_set(serial_number, 1); // This should be a unique number
    X509_set_serialNumber(user_cert, serial_number);
    ASN1_INTEGER_free(serial_number);

    // Set the validity period
    X509_gmtime_adj(X509_get_notBefore(user_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(user_cert), 365 * 24 * 60 * 60); // Valid for 1 year

    // Set the subject name from the CSR
    // X509_NAME* subject_name = X509_REQ_get_subject_name(csr);
    // X509_set_subject_name(user_cert, subject_name);

    // Set the public key from the CSR
    EVP_PKEY* public_key = X509_REQ_get_pubkey(csr);
    if (!public_key)
    {
        ERROR_LOG("Error extracting public key from CSR.");
        X509_free(user_cert);
        return nullptr;
    }
    X509_set_pubkey(user_cert, public_key);
    EVP_PKEY_free(public_key);

    // Set the issuer name (CA certificate)
    // X509_NAME* issuer_name = X509_get_subject_name(ca_cert);
    // X509_set_issuer_name(user_cert, issuer_name);

    // Sign the certificate with the CA's private key
    if (X509_sign(user_cert, ca_keypair, EVP_sha256()) == 0)
    {
        ERROR_LOG("Error signing user certificate.");
        X509_free(user_cert);
        return NULL;
    }

    return user_cert;
}

X509_REQ*
SinkManager::ConvertToX509_REQ(uint8_t* derData, int length)
{
    // Set a temporary pointer to the DER data
    const unsigned char* temp = derData;

    // Convert the DER data back to an X509_REQ object
    X509_REQ* req = d2i_X509_REQ(NULL, &temp, length);

    if (length <= 0)
    {
        ERROR_LOG("UINT8_T DER data length is 0.");
    }
    if (req == nullptr)
    {
        ERROR_LOG("Error converting DER format to X509_REQ.");
        ERROR_LOG(req);
    }

    return req;
}

void
SinkManager::SendMessage(InetSocketAddress destination_address,
                         const uint8_t* buffer,
                         int buffer_length)
{
    // if (message.size() > 1024)
    // {
    //     NS_LOG_WARN("Message size exceeds buffer capacity");
    //     return;
    // }

    // uint8_t buffer[1024];
    // memcpy(buffer, message.c_str(), message.size());
    // INFO_LOG("Buffer Length: " << buffer_length);
    // // INFO_LOG("Buffer: " << buffer);
    // INFO_LOG("Destination IP: " << destination_address.GetIpv4());
    // INFO_LOG("Destination PORT: " << destination_address.GetPort());
    INFO_LOG("Sending data from " << address.GetIpv4() << " to " << destination_address.GetIpv4());
    float energy_consumed = 59.2 * buffer_length;
    INFO_LOG("Energy consumed by sink to send the data: " << energy_consumed << "µJ");
    Ptr<Packet> packet = Create<Packet>(buffer, buffer_length);
    sinkSocket->SendTo(packet, 0, destination_address);
    // INFO_LOG("Message sent to: ");
}

void
SinkManager::HandleSocketReceive(Ptr<ns3::Socket> socket)
{
    // std::ostringstream oss;
    Address received_from;
    Ptr<Packet> packet = socket->RecvFrom(received_from);
    uint8_t received_packet_size = packet->GetSize();
    InetSocketAddress destination_address = InetSocketAddress::ConvertFrom(received_from);

    INFO_LOG("Sink Received from " << InetSocketAddress::ConvertFrom(received_from).GetIpv4()
                                   << " of Size: " << packet->GetSize());                                   
    float energy_consumed = 28.6 * received_packet_size;                                   
    INFO_LOG("Energy consumed by sink to receive the data: " << energy_consumed << "µJ");


    uint8_t* received_data = new uint8_t[received_packet_size];

    // Copy packet data directly into the vector
    packet->CopyData(received_data, received_packet_size);

    int packet_content_size = received_packet_size - 1;
    uint8_t* packet_content = new uint8_t[packet_content_size];
    memcpy(packet_content, received_data + 1, packet_content_size);

    int request_type = static_cast<int>(received_data[0]);
    int response_size = 0;
    switch (request_type)
    {
    case 1: {
        uint8_t* response_content = ConvertToUint8T(
            GenerateUserCertificate(ConvertToX509_REQ(packet_content, packet_content_size)),
            response_size);
        if (!response_content)
        {
            ERROR_LOG("Error converting user certificate to DER format.");
            break;
        }
        uint8_t response_type = 9;
        int total_size = 2 + response_size;
        uint8_t* response_buffer =
            GeneratePacketBuffer(response_type, response_content, total_size);

        // InetSocketAddress destination_address =
        //     InetSocketAddress(InetSocketAddress::ConvertFrom(received_from).GetIpv4(), 8080);
        INFO_LOG("Sending User Certificate to " << destination_address.GetIpv4());
        Simulator::Schedule(Seconds(0.01),
                            &SinkManager::SendMessage,
                            this,
                            destination_address,
                            response_buffer,
                            total_size);

        response_type = 8;
        total_size = 2 + converted_ca_public_key_size;
        uint8_t* public_key_buffer =
            GeneratePacketBuffer(response_type, converted_ca_public_key, total_size);
        if (public_key_buffer == nullptr) {
            ERROR_LOG("Failed to generate public key buffer");
        }
        Simulator::Schedule(Seconds(0.01),
                            &SinkManager::SendMessage,
                            this,
                            destination_address,
                            public_key_buffer,
                            total_size);
        // delete[] public_key_buffer;

        break;
    }
    default:
        ERROR_LOG("Packet type " << request_type << " not matched.");
        break;
    }

    // delete[] received_data;
    // delete[] packet_content;
}