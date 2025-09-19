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

int main(int argc, char* argv[]) {
    std::int32_t secretNumber = 7; // 'x00\x00\x00\x07' 
    std::string usernames = "sindrib23,benjaminr23,oliver23";
    std::string ip = "130.208.246.98";
    int secretPort = std::atoi(argv[1]); // SecretPort
    int signaturePort = std::atoi(argv[2]); // signaturePort

    uint32_t netSignature;

    // std::string message = "S\x00\x00\x00\x00\x07sindrib23,benjaminr23,oliver23";

    // create UDP socket
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
    dest_addr.sin_port = htons(secretPort); // Convert port to network byte order
    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr); // Convert IP string to binary

    // create message 
    char message[1024]; 
    message[0] = 'S';
    uint32_t netSecretNum = htonl(secretNumber); // we must convert the signature INTO network byte order, to send it to the server 
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
    std::cout << "Sending message of length: " << message_length << std::endl;
    
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

    // parse challenge
    if (bytes_received == 5) {
        uint8_t group_id = buffer[0]; // the first byte received is the group id 
        uint32_t challenge;
        memcpy(&challenge, buffer + 1, 4); // we are copying the rest of the bytes starting at buffer[1], and pasting it into the challenge variable
        challenge = ntohl(challenge); // we must convert FROM network byte order to host byte order.
        std::cout << "Group ID: " << (int)group_id << ", Challenge: " << challenge << std::endl;

        // calculate the signature:: Combine this challenge using the XOR operation with the secret number you generated in step 1 to obtain a 4 byte signature.
        uint32_t signature = challenge ^ secretNumber;
        netSignature = htonl(signature);

        char response[5];
        response[0] = group_id;
        memcpy(response + 1, &netSignature, 4); 

        std::cout << "Sending signature: " << signature << std::endl;

        if (sendto(sock, response, 5, 0, (const sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sending response failed");
            close(sock);
            return -1;
        }

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender_addr, &sender_addr_len);
        if (bytes_received < 0 ) {
            perror("getting response after signature sent failed | recvfrom()"); 
            close(sock);
            return -1;
        }

        buffer[bytes_received] = '\0';
        std::cout << "SUCCESS! Secret port: " << buffer << std::endl;


        // ---------- PORT number 2!!! --------------
        // here we send port 4011 the signature.
        // create destination address
        struct sockaddr_in sig_dest_addr; 
        memset(&sig_dest_addr, 0, sizeof(sig_dest_addr));
        sig_dest_addr.sin_family = AF_INET; 
        sig_dest_addr.sin_port = htons(signaturePort); // Convert port to network byte order
        inet_pton(AF_INET, ip.c_str(), &sig_dest_addr.sin_addr); // Convert IP string to binary

        // send message
        if (sendto(sock, &netSignature, sizeof(netSignature), 0, (const sockaddr*)&sig_dest_addr, sizeof(sig_dest_addr)) < 0) {
            perror("sendto signatuePort");
            close(sock);
            return -1;
        }

        // receive message 
        char sig_buffer[1024];
        struct sockaddr_in sig_sender_addr;
        socklen_t sig_sender_addr_len = sizeof(sig_sender_addr);
        int sig_bytes_received = recvfrom(sock, sig_buffer, sizeof(sig_buffer), 0, (struct sockaddr*)&sig_sender_addr, &sig_sender_addr_len);
        if (sig_bytes_received < 0) {
            perror("recvfrom failed, nothing received from port 4011");
            close(sock);
            return -1; 
        }

        sig_buffer[bytes_received] = '\0';

        std::string sig_MessageReceived = sig_buffer;

        std::cout << "Message received: " << sig_MessageReceived << std::endl; 

        close(sock);
    }
    return 0;
}



// 1. get the port - 1
// 2. create UDP socket -1 
// 3. set timeout -1 
// 4. prepare destination address structure -1 
// 5. build the message - 1 
// 6. send the message - 1 
// 7. receive challenge response - 1
// 8. check if response came from the correct port - ? 
// 9. parse challenge
// 10. calculate signature
// 11. send signature response
// 12. receive final response (secret port)
// 13. check if response came from the correct port
// 14. parse secret port
// 15. print secret port
// 16. close socket
// 17. return/exit