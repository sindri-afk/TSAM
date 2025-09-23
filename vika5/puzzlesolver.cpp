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

// struct ip_header {
//     uint8_t ip_hl:4; 
//     uint8_t ip_v:4;
//     uint8_t ip_tos;
//     uint16_t ip_len;
//     uint16_t ip_id;
//     uint16_t ip_off;
//     uint8_t ip_ttl;
//     uint8_t ip_p;
//     uint16_t ip_sum;
//     struct in_addr ip_src; // source address 
//     struct in_addr ip_dst; // destination address
// };

// struct udp_header {
//     uint16_t uh_sport; // source port
//     uint16_t uh_dport; // destination port
//     uint16_t uh_ulen;  // udp length
//     uint16_t uh_sum;   // udp checksum  
// };

// // Checksum function
// unsigned short checksum(unsigned short *buf, int nwords) {
//     unsigned long sum;
//     for (sum = 0; nwords > 0; nwords--) {
//         sum += *buf++;
//     }
//     sum = (sum >> 16) + (sum & 0xffff);
//     sum += (sum >> 16);
//     return (unsigned short)(~sum);
// }

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
    std::int32_t secretNumber = 7; 
    std::string usernames = "sindrib23,benjaminr23,oliver23";
    std::string ip = "130.208.246.98";
    int target_port = secretPort;
    uint32_t signature = 0;

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
    uint32_t netSecretNum = htonl(secretNumber); 
    memcpy(message + 1, &netSecretNum, sizeof(netSecretNum));
    strcpy(message + 5, usernames.c_str()); // the reason I don't use memcpy here is because usernames is a string, and I want to copy the whole string including the null terminator
    int message_length = 5 + usernames.length();

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
        uint8_t group_id = reply[0]; // the first byte received is the group id
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
        return signature;
    }
    return -1; 
}

int sendSignaturePort(int port, uint32_t signature) {
    // here we send the signature port, the signature we got
    std::string ip = "130.208.246.98";
    uint32_t netSignature = htonl(signature); // convert to network byte order
    // create a UDP socket
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
    dest_addr.sin_port = htons(port); // Convert port to network byte order
    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr); // Convert

    // create & send message

    ssize_t sent = sendto(sock, &netSignature, sizeof(netSignature), 0, (const sockaddr*)&dest_addr, sizeof(dest_addr));
    if (sent < 0) { perror("sendto"); close(sock); return -1; }
    if (sent != (ssize_t)sizeof(netSignature)) {
        std::cerr << "Only sent " << sent << " bytes\n";
    }

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // receive the message
    char buffer[1024];
    struct sockaddr_in sender_addr;
    socklen_t sender_addr_len = sizeof(sender_addr);
    int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender_addr, &sender_addr_len);
    if ( bytes_received < 0) {
        perror("recvfrom evilport");
        close(sock);
        return -1; 
    }  

    buffer[bytes_received] = '\0';
    std::string messageReceived = buffer;
    std::cout << "\n" << std::endl; // here I want to print a new line, to separate the ports that respond
    std::cout << "Message received from the signature port " << port << ": " << messageReceived << std::endl;
    close(sock);
    return 0; 
}

// int sendEvilPort(int port, uint32_t signature) {
//     std::string ip = "130.208.246.98";
    
//     // Create a raw socket
//     int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
//     if (sock < 0) {
//         perror("socket");
//         return -1;
//     }
    
//     // Enable IP_HDRINCL to build our own IP header
//     int one = 1;
//     if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
//         perror("setsockopt");
//         close(sock);
//         return -1;
//     }
    
//     // Calculate packet sizes
//     const int ip_header_len = sizeof(struct ip_header);
//     const int udp_header_len = sizeof(struct udp_header);
//     const int payload_len = sizeof(signature);
//     const int total_len = ip_header_len + udp_header_len + payload_len;
    
//     // Build the packet
//     char packet[1024];
//     memset(packet, 0, sizeof(packet));
    
//     // Pointers to headers and payload
//     struct ip_header *ip_hdr = (struct ip_header*)packet;
//     struct udp_header *udp_hdr = (struct udp_header*)(packet + ip_header_len);
//     uint32_t *sig_ptr = (uint32_t*)(packet + ip_header_len + udp_header_len);
    
//     // Fill IP header
//     ip_hdr->ip_v = 4;                    // IPv4
//     ip_hdr->ip_hl = 5;                   // 5 * 4 = 20 bytes
//     ip_hdr->ip_tos = 0;                  // Type of service
//     ip_hdr->ip_len = htons(total_len);   // Total length
//     ip_hdr->ip_id = htons(54321);        // Identification
//     ip_hdr->ip_off = htons(0x8000);      // Set evil bit (high bit)
//     ip_hdr->ip_ttl = 64;                 // Time to live
//     ip_hdr->ip_p = IPPROTO_UDP;          // UDP protocol
//     ip_hdr->ip_sum = 0;                  // Will calculate checksum
    
//     // Set source and destination addresses
//     inet_pton(AF_INET, "192.168.1.100", &ip_hdr->ip_src);
//     inet_pton(AF_INET, ip.c_str(), &ip_hdr->ip_dst);
    
//     // Calculate IP checksum
//     ip_hdr->ip_sum = checksum((unsigned short*)ip_hdr, ip_header_len);
    
//     // Fill UDP header
//     udp_hdr->uh_sport = htons(12345);    // Source port
//     udp_hdr->uh_dport = htons(port);     // Destination port (evil port)
//     udp_hdr->uh_ulen = htons(udp_header_len + payload_len); // UDP length
//     udp_hdr->uh_sum = 0;                 // Optional for IPv4
    
//     // Add signature payload (network byte order)
//     *sig_ptr = htonl(signature);
    
//     // Set destination address
//     struct sockaddr_in dest_addr;
//     memset(&dest_addr, 0, sizeof(dest_addr));
//     dest_addr.sin_family = AF_INET;
//     dest_addr.sin_port = htons(port);
//     inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);
    
//     // Send the packet
//     ssize_t sent = sendto(sock, packet, total_len, 0, 
//                          (struct sockaddr*)&dest_addr, sizeof(dest_addr));
//     if (sent < 0) {
//         perror("sendto evil port");
//         close(sock);
//         return -1;
//     }
    
//     std::cout << "Sent evil packet with signature: " << signature << " to port: " << port << std::endl;
    
//     // Wait for response (use a regular socket for receiving)
//     close(sock); // Close raw socket
    
//     // Create a normal UDP socket to receive response
//     int recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
//     if (recv_sock < 0) {
//         perror("socket for receive");
//         return -1;
//     }
    
//     // Bind to any port
//     struct sockaddr_in recv_addr;
//     memset(&recv_addr, 0, sizeof(recv_addr));
//     recv_addr.sin_family = AF_INET;
//     recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//     recv_addr.sin_port = htons(0); // Let OS choose port
    
//     if (bind(recv_sock, (struct sockaddr*)&recv_addr, sizeof(recv_addr)) < 0) {
//         perror("bind");
//         close(recv_sock);
//         return -1;
//     }
    
//     // Set timeout
//     struct timeval tv;
//     tv.tv_sec = 2;
//     tv.tv_usec = 0;
//     setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
//     // Receive response
//     char buffer[1024];
//     struct sockaddr_in sender_addr;
//     socklen_t sender_len = sizeof(sender_addr);
    
//     int bytes_received = recvfrom(recv_sock, buffer, sizeof(buffer), 0, 
//                                  (struct sockaddr*)&sender_addr, &sender_len);
//     if (bytes_received > 0) {
//         buffer[bytes_received] = '\0';
//         std::cout << "Response from evil port: " << buffer << std::endl;
//     } else {
//         perror("recvfrom evil port");
//     }
    
//     close(recv_sock);
//     return 0;
// }

int sendChecksumPort(int port, uint32_t signature) {
    return 0; 
}

int main(int argc, char* argv[]) {
    std::int32_t secretNumber = 7; // 'x00\x00\x00\x07' 
    std::string usernames = "sindrib23,benjaminr23,oliver23";
    std::string ip = "130.208.246.98";
    int secretPort = std::atoi(argv[1]); // SecretPort
    int signaturePort = std::atoi(argv[2]); // checksum port 
    int evilPort = std::atoi(argv[3]); // evilPort 

    uint32_t signature = getSignature(secretPort);

    std::cout << "\n" << std::endl; // here I want to print a new line, to separate the ports that respond
    std::cout << "Signature to send: " << signature << std::endl;
    std::cout << "Signature to send in network byte order: " << htonl(signature) << std::endl;

    // sendEvilPort(evilPort, signature);
    sendSignaturePort(signaturePort, signature);

    // std::string message = "S\x00\x00\x00\x00\x07sindrib23,benjaminr23,oliver23";

    return 0;
}
// á eftir að klára EvilPort,checksum port og EXPSTN port
// við fáum að vita checksum port þegar við sendum signature á signature port og fáum skilaboð til baka


