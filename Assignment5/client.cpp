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

// Helper function to send a command and receive response
std::string send_command_and_receive(int sock, const std::string& command) {
    // Frame the message according to protocol: <SOH><length><STX><command><ETX>
    uint16_t length = 5 + command.length(); // SOH + length(2) + STX + command + ETX
    uint16_t network_length = htons(length);
    
    std::string framed_message;
    framed_message += (char)0x01; // SOH
    framed_message += std::string(reinterpret_cast<char*>(&network_length), 2); // length
    framed_message += (char)0x02; // STX  
    framed_message += command; // command
    framed_message += (char)0x03; // ETX
    
    // Send the framed message
    std::cout << "<SEND>: " << command << std::endl;
    ssize_t sent = send(sock, framed_message.c_str(), framed_message.length(), 0);
    if (sent <= 0) {
        return "ERROR: Failed to send";
    }
    
    // Receive response
    char buffer[6000];
    ssize_t received = recv(sock, buffer, sizeof(buffer), 0);
    
    if (received > 0) {
        // Parse the response
        if (received >= 5 && buffer[0] == 0x01 && buffer[3] == 0x02 && buffer[received-1] == 0x03) {
            std::string response(buffer + 4, received - 5);
            std::cout << "<RECV>: " << response << std::endl;
            return response;
        }
    }
    
    return "ERROR: Invalid or no response";
}

int connect_to_server(const std::string& server_ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0); 
    if (sock == -1) {
        std::cerr << "<ERROR>: Could not create socket.\n";
        return -1;
    }

    sockaddr_in server_addr{}; // create a struct to hold the server address
    server_addr.sin_family = AF_INET; // IPv4
    server_addr.sin_port = htons(port); // convert port to network byte order

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "<ERROR>: Invalid address\n";
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "<ERROR>: Connection failed\n";
        close(sock);
        return -1;
    }

    std::cout << "<INFO>: Successfully connected to " << server_ip << " on port " << port << ".\n";
    return sock;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "<ERROR>: Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }

    std::string server_ip = argv[1];
    int port = std::stoi(argv[2]);

    int sock = connect_to_server(server_ip, port);
    if (sock == -1) {
        return 1;
    }

    std::cout << "\n======= TESTING SERVER COMMANDS =======\n";
    
    // Test 1: HELO command (this should establish connection)
    std::cout << "\n--- Test 1: HELO Command ---\n";
    send_command_and_receive(sock, "HELO,A5_TEST");
    
    // Test 2: SERVERS command (should list connected servers)
    std::cout << "\n--- Test 2: SERVERS Command ---\n";
    send_command_and_receive(sock, "SERVERS");
    
    // Test 3: SENDMSG command (send a message)
    std::cout << "\n--- Test 3: SENDMSG Command ---\n";
    send_command_and_receive(sock, "SENDMSG,A5_21,A5_TEST,Hello from test client!");
    
    // Test 4: GETMSGS command (retrieve messages)
    std::cout << "\n--- Test 4: GETMSGS Command ---\n";
    send_command_and_receive(sock, "GETMSGS,A5_TEST");
    
    // Test 5: STATUSREQ command (get server status)
    std::cout << "\n--- Test 5: STATUSREQ Command ---\n";
    send_command_and_receive(sock, "STATUSREQ");
    
    // Test 6: Another SENDMSG to test multiple messages
    std::cout << "\n--- Test 6: Another SENDMSG ---\n";
    send_command_and_receive(sock, "SENDMSG,A5_21,A5_TEST,Second message for testing!");
    
    // Test 7: GETMSGS again to see if messages accumulate
    std::cout << "\n--- Test 7: GETMSGS Again ---\n";
    send_command_and_receive(sock, "GETMSGS,A5_TEST");
    
    // Test 8: Invalid command (test error handling)
    std::cout << "\n--- Test 8: Invalid Command ---\n";
    send_command_and_receive(sock, "INVALID_COMMAND");
    
    std::cout << "\n======= ALL TESTS COMPLETED =======\n";

    close(sock);
    std::cout << "<INFO>: Client shut down.\n";
    return 0;
}