#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }

    int target_port = std::atoi(argv[1]);
    std::string ip = "130.208.246.98";
    uint32_t secretNumber = 7;
    std::string usernames = "sindrib23,benjaminr23,oliver23"; // No spaces!

    // Create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Set timeout
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // Prepare destination address (S.E.C.R.E.T. port)
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET; 
    dest_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

    // Build the message
    char message[100];
    message[0] = 'S';
    uint32_t netSecretNum = htonl(secretNumber);
    memcpy(message + 1, &netSecretNum, sizeof(netSecretNum));
    strcpy(message + 5, usernames.c_str());
    int message_length = 5 + usernames.length();

    std::cout << "Sending to port " << target_port << ": 'S' + secret(" << secretNumber << ") + usernames" << std::endl;

    // Send initial message
    if (sendto(sock, message, message_length, 0, (const sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    // Receive challenge response
    char buffer[1024];
    struct sockaddr_in response_addr;
    socklen_t addr_len = sizeof(response_addr);
    
    int bytes_received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, 
                                 (struct sockaddr*)&response_addr, &addr_len);
    
    if (bytes_received < 0) {
        perror("recvfrom");
        std::cerr << "No response from port " << target_port << std::endl;
        close(sock);
        return -1;
    }

    // Check if response came from the correct port
    if (ntohs(response_addr.sin_port) != target_port) {
        std::cerr << "Response came from wrong port: " << ntohs(response_addr.sin_port) 
                  << " (expected: " << target_port << ")" << std::endl;
        close(sock);
        return -1;
    }

    std::cout << "Received " << bytes_received << " bytes from port " << target_port << std::endl;

    if (bytes_received == 5) {
        // Parse challenge
        uint8_t group_id = buffer[0];
        uint32_t challenge;
        memcpy(&challenge, buffer + 1, 4);
        challenge = ntohl(challenge);

        std::cout << "Group ID: " << (int)group_id << ", Challenge: " << challenge << std::endl;

        // Calculate signature
        uint32_t signature = challenge ^ secretNumber;
        uint32_t net_signature = htonl(signature);

        // Send signature response
        char response[5];
        response[0] = group_id;
        memcpy(response + 1, &net_signature, 4);

        std::cout << "Sending signature: " << signature << std::endl;

        if (sendto(sock, response, 5, 0, (const sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto signature");
            close(sock);
            return -1;
        }

        // Receive final response (secret port)
        bytes_received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, 
                                 (struct sockaddr*)&response_addr, &addr_len);
        
        if (bytes_received < 0) {
            perror("recvfrom final");
            close(sock);
            return -1;
        }

        buffer[bytes_received] = '\0';
        std::cout << "SUCCESS! Secret port: " << buffer << std::endl;

    } else {
        std::cout << "Unexpected response size: " << bytes_received << " bytes" << std::endl;
        for (int i = 0; i < bytes_received; i++) {
            std::cout << (int)(unsigned char)buffer[i] << " ";
        }
        std::cout << std::endl;
    }

    close(sock);
    return 0;
}