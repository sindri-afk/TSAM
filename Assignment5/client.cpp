#include <iostream>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
// what does the client do?
// it takes the servers ip and port as command line arguements
// it creates a TCP socket!
// connects to the server
// prints a success message if connected 
// close the socket and exit

int connect_to_server(const std::string& server_ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0); 
    if (sock == -1) {
        std::cerr << "[ERROR]: Could not create socket.\n";
        return -1;
    }

    sockaddr_in server_addr{}; // create a struct to hold the server address
    server_addr.sin_family = AF_INET; // IPv4
    server_addr.sin_port = htons(port); // convert port to network byte order

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "[ERROR]: Invalid address\n";
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[ERROR]: Connection failed\n";
        close(sock);
        return -1;
    }

    std::cout << "[INFO]: Successfully connected to " << server_ip << " on port " << port << ".\n";
    return sock;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "[ERROR]: Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }

    std::string server_ip = argv[1];
    int port = std::stoi(argv[2]);

    int sock = connect_to_server(server_ip, port);
    if (sock == -1) {
        return 1;
    }

    // Here you can add code to communicate with the server

    close(sock);
    std::cout << "[INFO]: Client shut down.\n";
    return 0;
}