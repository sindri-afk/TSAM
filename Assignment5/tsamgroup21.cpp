#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>

void start_server(int port);

int main(int argc, char* argv[]) {
    if (argc!= 2) {std::cout << "incorrect number of arguements" << std::endl; return 1;}
    int port = std::stoi(argv[1]);
    start_server(port);
    return 0; 
}

void start_server(int port) {
    int server_fd;
    sockaddr_in server_addr{}, client_addr{};
    socklen_t client_len = sizeof(client_addr);

    // 1. Create the TCP socket
    // this is the entry point to any network program, this is how our program "asks" the OS for network access
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        std::cerr << "Error: Could not create socket.\n";
        return;
    }

    std::cout << "[INFO] Socket created successfully.\n";

    // 2. Allow the socket to reuse the address quickly after closing
    // we do this because otherwise we might have to wait a few minutes before being able to bind to the same port again
    int opt = 1; // this is basically just a boolean flag 
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Warning: setsockopt failed.\n";
    }

    // 3. Bind the socket to the given port; assigning a local address/port to the socket
    server_addr.sin_family = AF_INET;         // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY; // accept connections on any network interface
    server_addr.sin_port = htons(port);       // convert port to network byte order

    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error: Bind failed (port might be in use?)\n";
        close(sock);
        return;
    }
    std::cout << "[INFO] Server bound to port " << port << ".\n";

    // 4. Tell the OS we want to listen for incoming connections
    if (listen(sock, 5) < 0) {
        std::cerr << "Error: Listen failed.\n";
        close(sock);
        return;
    }
    std::cout << "[INFO] Server is now listening for connections...\n";

    // 5. Accept one client connection (this blocks until someone connects)
    // the way to connect is to use 'telnet localhost <port>' from a terminal
    int client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_len);
    if (client_sock < 0) {
        std::cerr << "Error: Accept failed.\n";
        close(sock);
        return;
    }

    // 6. Print the client’s IP and port
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    std::cout << "[INFO] Client connected from " << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";

    // 7. (Placeholder for later message handling)

    // 8. Close sockets
    close(client_sock);
    close(sock);
    std::cout << "[INFO] Server shut down.\n";
}
