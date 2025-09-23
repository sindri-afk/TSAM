#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <stdlib.h>
#include <stdio.h>

std::uint8_t group_id = 0;

struct iphdr {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed)); // this ensures no padding is added by the compiler

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed)); 

int getSignature(int secretPort) {
    /*
    1. Generate a 32 bit secret number (and remember it for later)
    2. Send me a message where the first byte is the letter 'S' followed by 4 bytes containing your secret number (in network byte order),
        and the rest of the message is a comma-separated list of the RU usernames of all your group members.
    3. I will reply with a 5-byte message, where the first byte is your group ID and the remaining 4 bytes are a 32 bit challenge number (in network byte order)
    4. Combine this challenge using the XOR operation with the secret number you generated in step 1 to obtain a 4 byte signature.
    5. Reply with a 5-byte message: the first byte is your group number, followed by the 4-byte signature (in network byte order).
    6. If your signature is correct, I will respond with a secret port number. Good luck!
    7. Remember to keep your group ID and signature for later, you will need them for
    */
    std::uint32_t secretNumber = 7; 
    std::string usernames = "sindrib23,benjaminr23,oliver23";
    std::string ip = "130.208.246.98";
    int target_port = secretPort;
    std::uint32_t signature = 0;

    // create a udp socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1; 
    }

    // set timeout
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)); 

    // create destination address
    struct sockaddr_in dest_addr; 
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(target_port); 
    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

    // create message
    char message[1024];
    message[0] = 'S';
    std::uint32_t netSecretNum = htonl(secretNumber); 
    memcpy(message + 1, &netSecretNum, sizeof(netSecretNum));
    memcpy(message + 5, usernames.c_str(), usernames.size());
    int message_length = 5 + usernames.size();

    // send message
    if (sendto(sock, message, message_length, 0, (const sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // receive the reply
    char reply[1024];
    struct sockaddr_in reply_addr;
    socklen_t addr_len = sizeof(reply_addr);
    int bytes_received = recvfrom(sock, reply, sizeof(reply) - 1, 0, (struct sockaddr*)&reply_addr, &addr_len);
    if (bytes_received < 0) {
        perror("recvfrom");
        close(sock);
        return -1;
    }
    if (bytes_received == 5) {
        group_id = reply[0]; // the first byte received is the group id
        uint32_t challenge;
        memcpy(&challenge, reply + 1, 4); // we are copying the rest of the bytes starting at reply[1], and pasting it into the challenge variable
        
        std::cout << "\n" << std::endl; // here I want to print a new line, to separate the ports that respond

        challenge = ntohl(challenge); // we must convert FROM network byte order to host byte order.
        std::cout << "Group ID: " << (int)group_id << ", Challenge: " << challenge << std::endl;
        // calculate the signature:: Combine this challenge using the XOR operation with the secret number you generated in step 1 to obtain a 4 byte signature.
        signature = challenge ^ secretNumber;
        std::cout << "Signature: " << signature << std::endl;

        // send the signature back to the server
        char signature_message[5];
        signature_message[0] = group_id;
        uint32_t netSignature = htonl(signature);
        memcpy(signature_message + 1, &netSignature, sizeof(netSignature));
        if (sendto(sock, signature_message, sizeof(signature_message), 0, (const sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto signature");
            close(sock);
            return -1;
        }

        // receive the secret port
        char second_response[1024];

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));


        struct sockaddr_in second_response_addr;
        socklen_t second_addr_len = sizeof(second_response_addr);
        int second_bytes_received = recvfrom(sock, second_response, sizeof(second_response) - 1, 0, (struct sockaddr*)&second_response_addr, &second_addr_len);
        if (second_bytes_received < 0) {
            perror("recvfrom secret port");
            close(sock);
            return -1;
        }
        second_response[second_bytes_received] = '\0';
        std::string message = second_response;
        std::cout << "\n" << std::endl; 
        std::cout << "Port "<< secretPort << ": " << message << std::endl; 
        close(sock);
        std::cout << "Signature to return: " << signature << std::endl;
        return signature;
    }
    return -1; 
}

std::string sendSignaturePort(int port, uint32_t signature) {
    std::string ip = "130.208.246.98";
    uint32_t netSignature = htonl(signature);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { 
        perror("socket");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)); 

    struct sockaddr_in dest_addr; 
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port); 
    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

// Send only 4 bytes: signature in network byte order
if (sendto(sock, &netSignature, sizeof(netSignature), 0, (const sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
    perror("Sending to SignaturePort");
    close(sock);
    return -1; 
}

    char response[1024];
    struct sockaddr_in receive_addr; 
    socklen_t addr_len = sizeof(receive_addr);

    int bytes_received = recvfrom(sock, response, sizeof(response) - 1, 0, (struct sockaddr*)&receive_addr, &addr_len);
    if (bytes_received < 0) {
        perror("recvfrom");
        close(sock);
        return -1;
    }

    response[bytes_received] = '\0';
    std::cout << "SignaturePort response: " << response << std::endl;


    close(sock);
    return std::string(response, bytes_received);
}

uint16_t checksumCalc(const void* data, size_t length) {
    const uint8_t* b = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;

    while (length > 1) {
        uint16_t word = (b[0] << 8) | b[1];
        sum += word;
        b += 2;
        length -= 2;
    }
    if (length == 1) { 
        uint16_t word = (b[0] << 8);
        sum += word;
    }

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t res = static_cast<uint16_t>(~sum);
    if (res == 0) res = 0xFFFF;
    return res;
}

int sendChecksumPort(int port, uint32_t signature, const std::string& response) {
    iphdr ipheader{};
    ip_header.version = 4; 
    ip_header.ihl = 5;
    ip_header.tos = 0;
    ip_header.tot_len = htons(sizeof(iphdr) + sizeof(udphdr) + response.size());
    ip_header.id = htons(54321);
    ip_header.frag_off = 0;
    ip_header.ttl = 64;
    ip_header.protocol = IPPROTO_UDP;
    ip_header.check = 0;
    ip_header.saddr = src_ip;
    ip_header.daddr = inet_addr("130.208.246.98");

    udphdr udpheader{};
    udp_header.source = htons(12345);
    udp_header.dest = htons(port);
    udp_header.len = htons(sizeof(udphdr) + response.size());
    udp_header.check = 0;

    // Calculate checksums

    return 0;
}

int main(int argc, char* argv[]) {
    system("clear");
    std::uint32_t secretNumber = 7; // 'x00\x00\x00\x07' 
    std::string usernames = "sindrib23,benjaminr23,oliver23";
    std::string ip = "130.208.246.98";
    int secretPort = std::atoi(argv[1]); // SecretPort
    int checksumPort = std::atoi(argv[2]); // checksum port
    int evilPort = std::atoi(argv[3]); // evilPort 

    uint32_t signature = getSignature(secretPort);

    // std::cout << "\n" << std::endl; // here I want to print a new line, to separate the ports that respond
    // std::cout << "Signature to send: " << signature << std::endl;
    // std::cout << "Signature to send in network byte order: " << htonl(signature) << std::endl;

    // sendEvilPort(evilPort, signature);
    std::cout << "Signature in main: " << signature << std::endl;
    std::string signatureResponse = sendSignaturePort(checksumPort, signature);
    std::cout << "Signature response: " << signatureResponse << std::endl;

    sendChecksumPort(checksumPort, signature, signatureResponse);

    // std::string message = "S\x00\x00\x00\x00\x07sindrib23,benjaminr23,oliver23";

    return 0;
}
// á eftir að klára EvilPort,checksum port og EXPSTN port
// við fáum að vita checksum port þegar við sendum signature á signature port og fáum skilaboð til baka


