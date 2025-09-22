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


int getSignature(int port) {
    /*
    Þetta fall fær gefið það port sem segir: Greetings from S.E.C.R.E.T.
    það sendir skilaboðin sem við þurfum að senda, og fær til baka 5 bita skilaboð
    fyrsta bita er group id, og næstu 4 bita er það sem kallað er 'challenge'
    svo reiknar það út signature með því að XORa challenge við secret number sem við bjuggum til, og með því reiknum við signature
    SIGNATURE er síðan það sem öll hin portin þurfa að fá!
    */
    std::int32_t secretNumber = 7;
    std::string usernames = "sindrib23,benjaminr23,oliver23";
    std::string ip = "130.208.246.98";

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
    // create message
    char message[1024];
    message[0] = 'S';
    uint32_t netSecretNum = htonl(secretNumber); // we must convert the
    // signature INTO network byte order, to send it to the server
    memcpy(message + 1, &netSecretNum, sizeof(netSecretNum));
    strcpy(message + 5, usernames.c_str());
    int message_length = 5 + usernames.length();

    // send message
    if (sendto(sock, message, message_length, 0, (const sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // receive the message
    char buffer[1024];
    struct sockaddr_in sender_addr;
    socklen_t sender_addr_len = sizeof(sender_addr);
    int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender_addr, &sender_addr_len);
    if ( bytes_received < 0) {
        perror("recvfrom");
        close(sock);
        return -1; 
    }

    buffer[bytes_received] = '\0';
    std::string messageReceived = buffer;
    std::cout << "Message received: " << messageReceived << std::endl;
    uint32_t signature = -1;
    // parse challenge
    if (bytes_received == 5) {
        uint8_t group_id = buffer[0]; // the first byte received is the group id
        uint32_t challenge;
        memcpy(&challenge, buffer + 1, 4); // we are copying the rest of the bytes starting at buffer[1], and pasting it into the challenge variable
        challenge = ntohl(challenge); // we must convert FROM network byte order to host byte order.
        std::cout << "Group ID: " << (int)group_id << ", Challenge: " << challenge << std::endl;
        // calculate the signature:: Combine this challenge using the XOR operation with the secret number you generated in step 1 to obtain a 4 byte signature.
        signature = challenge ^ secretNumber;
        std::cout << "Signature: " << signature << std::endl;
    }
    close(sock);
    return signature;
    // 3096433192
}

int sendSignaturePort(int port, uint32_t signature) {
    // here we send the signature port, the signature we got
    std::string ip = "130.208.246.98";
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

    ssize_t sent = sendto(sock, &signature, sizeof(signature), 0, (const sockaddr*)&dest_addr, sizeof(dest_addr));
    if (sent < 0) { perror("sendto"); close(sock); return -1; }
    if (sent != (ssize_t)sizeof(signature)) {
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

int sendEvilPort(int port, uint32_t signature) {
    /*
    Þetta fall fær gefið það port sem segir: The dark side of network programming is a pathway to many
    það sendir skilaboðin sem við þurfum að senda, og fær til baka skilaboð sem við prentum út
    1 bita sem er 'E', og næstu 4 bita er signature sem við reiknuðum út í getSignature fallinu
    4 bita signature er í network byte order
    */
    std::string ip = "130.208.246.98";
    // create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1; 
    }

    // set timeout
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // create destination address
    struct sockaddr_in dest_addr; 
    memset(&dest_addr, 0, sizeof(dest_addr)); 
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port); // Convert port to network byte order
    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr); // Convert

    // create & send message

    char message[4];
    memcpy(message, &signature, sizeof(signature)); // copy the 4 bytes of signature into message[0] to message[3]

    ssize_t sent = sendto(sock, message, sizeof(message), 0, (const sockaddr*)&dest_addr, sizeof(dest_addr));
    if (sent < 0) { perror("sendto"); close(sock); return -1; }
    if (sent != (ssize_t)sizeof(message)) {
        std::cerr << "Only sent " << sent << " bytes\n";
    }
    std::cout << "Sent 4-byte signature to port " << port << "\n";

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
    std::cout << "Message received from evil port: " << messageReceived << std::endl;
    close(sock);
    return 0; 
}

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
    uint32_t netSignature = htonl(signature);

    std::cout << "\n" << std::endl; // here I want to print a new line, to separate the ports that respond
    std::cout << "Signature to send: " << signature << std::endl;
    std::cout << "Signature to send in network byte order: " << netSignature << std::endl;

    sendEvilPort(evilPort, netSignature);
    sendSignaturePort(signaturePort, netSignature);

    // std::string message = "S\x00\x00\x00\x00\x07sindrib23,benjaminr23,oliver23";

    return 0;
}
// á eftir að klára EvilPort,checksum port og EXPSTN port
// við fáum að vita checksum port þegar við sendum signature á signature port og fáum skilaboð til baka


