#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <thread>
#include <fstream>
#include <ctime>
#include <vector>
#include <map>
#include <queue>
#include <mutex>
#include <string>

// define the framing characters and their hex values
#define SOH 0x01
#define STX 0x02
#define ETX 0x03

// Server information structure
// this is needed to keep track of connected servers because we need to route messages correctly
struct ServerInfo {
    std::string groupId;
    std::string host;
    int port;
    int socket;
    bool connected;
};

// Message structure  
// this is needed to store messages that are pending delivery
struct Message {
    std::string toGroupId;
    std::string fromGroupId;
    std::string content;
};

// Global variables for server state
std::vector<ServerInfo> connectedServers;
std::map<std::string, std::queue<Message>> pendingMessages;
std::mutex serversMutex;
std::mutex messagesMutex;
std::string myGroupId = "A5_21"; // Change this to your actual group ID

// Logging function
void log_message(const std::string& message) {
    std::ofstream log("server.log", std::ios::app);
    if (!log.is_open()) return;

    // Get current time
    std::time_t now = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    // Write timestamp + message
    log << "[" << buf << "] " << message << std::endl;
}

// Message protocol functions
// This function will be used to frame messages that we send to other servers
std::string frameMessage(const std::string& command) {
    uint16_t length = 5 + command.length(); // SOH + length(2) + STX + command + ETX
    uint16_t networkLength = htons(length);
    
    std::string framedMessage;
    framedMessage += (char)SOH;
    framedMessage += std::string(reinterpret_cast<char*>(&networkLength), 2);
    framedMessage += (char)STX;
    framedMessage += command;
    framedMessage += (char)ETX;
    
    return framedMessage;
}

// This function will be used to parse received messages and extract the command
std::string parseMessage(const char* buffer, ssize_t length) {
    if (length < 5 || buffer[0] != SOH || buffer[3] != STX || buffer[length-1] != ETX) {
        return "";
    }
    
    uint16_t expectedLength;
    memcpy(&expectedLength, buffer + 1, 2);
    expectedLength = ntohs(expectedLength);
    
    if (expectedLength != length) {
        return "";
    }
    
    return std::string(buffer + 4, length - 5);
}

// This function will be used to actually send framed messages to other servers
bool sendFramedMessage(int socket, const std::string& command) {
    std::string framedMessage = frameMessage(command);
    ssize_t sent = send(socket, framedMessage.c_str(), framedMessage.length(), 0);
    log_message("SENT: " + command);
    return sent == (ssize_t)framedMessage.length();
}

// Function declarations
void start_server(int port);
void handle_client(int client_sock, sockaddr_in client_addr);

// This function will process the SERVERS command and return the list of connected servers
std::string process_servers_request() {
    std::string response = "SERVERS";
    std::lock_guard<std::mutex> lock(serversMutex);
    
    for (size_t i = 0; i < connectedServers.size(); ++i) {
        if (i == 0) response += ",";
        else response += ";";
        
        const auto& server = connectedServers[i];
        response += server.groupId + "," + server.host + "," + std::to_string(server.port);
    }
    
    log_message("Sending SERVERS response: " + response);
    return response;
}

// Command processing functions
std::string process_helo(const std::string& fromGroupId) {
    log_message("RECV: HELO from " + fromGroupId);
    std::cout << "successful" << std::endl;
    
    // Add the connecting server to our list if not already present
    {
        std::lock_guard<std::mutex> lock(serversMutex);
        bool found = false;
        for (const auto& server : connectedServers) {
            if (server.groupId == fromGroupId) {
                found = true;
                break;
            }
        }
        
        if (!found && connectedServers.size() < 8) { // Max 8 connections
            ServerInfo newServer;
            newServer.groupId = fromGroupId;
            newServer.connected = true;
            // Note: host and port would need to be extracted from connection info
            connectedServers.push_back(newServer);
            log_message("Added server " + fromGroupId + " to connected servers list");
        }
    }
    
    return process_servers_request(); // Reply with SERVERS command
}


std::string process_getmsgs(const std::string& groupId) {
    std::lock_guard<std::mutex> lock(messagesMutex);
    
    if (pendingMessages[groupId].empty()) {
        return ""; // No messages
    }
    
    // Return the first message for this group
    Message msg = pendingMessages[groupId].front();
    pendingMessages[groupId].pop();
    
    std::string response = "MSG," + msg.fromGroupId + "," + msg.content;
    log_message("Delivering message to " + groupId + ": " + response);
    return response;
}

// This function will process the SENDMSG command and store the message for later delivery
void process_sendmsg(const std::string& toGroupId, const std::string& fromGroupId, const std::string& content) {
    Message msg;
    msg.toGroupId = toGroupId;
    msg.fromGroupId = fromGroupId;
    msg.content = content;
    
    {
        // Store the message in the pendingMessages queue because the recipient might not be connected
        std::lock_guard<std::mutex> lock(messagesMutex);
        pendingMessages[toGroupId].push(msg);
    }
    
    log_message("Stored message from " + fromGroupId + " to " + toGroupId + ": " + content);
}

// This function will process the STATUSREQ command and return the status of pending messages
std::string process_statusreq() {
    std::string response = "STATUSRESP";
    std::lock_guard<std::mutex> lock(messagesMutex);
    
    bool first = true;
    for (const auto& entry : pendingMessages) {
        if (!entry.second.empty()) {
            if (first) {
                response += ",";
                first = false;
            } else {
                response += ",";
            }
            response += entry.first + "," + std::to_string(entry.second.size());
        }
    }
    
    log_message("Sending status response: " + response);
    return response;
}

// 

std::string sendInstructorServerHelo() {
    std::string command = "HELO," + myGroupId; 
    int port = 5001;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error: Could not create socket to connect to instructor server.\n";
        return "";
    }

    // here we are going to connect to the instructor server running on 130.208.246.98 on port 5001
    sockaddr_in instructor_address{};
    instructor_address.sin_family = AF_INET;
    instructor_address.sin_port = htons(port);
    instructor_address.sin_addr.s_addr = inet_addr("130.208.246.98");

    std::cout << "[INFO] Connecting to instructor server at 130.208.246.98:" << "port: " << port << std::endl;

    if (connect(sock, (struct sockaddr*)&instructor_address, sizeof(instructor_address)) < 0) {
        log_message("Error: Could not connect to instructor server.");
        std::cout << "[ERROR] Could not connect to instructor server." << std::endl;
        close(sock);
        return "";
    }
    std::cout << "[INFO] Connected to instructor server." << std::endl;
    log_message("Connected to instructor server.");

    if (!sendFramedMessage(sock, command)) {
        log_message("Error: Could not send HELO to instructor server.");
        std::cout << "[ERROR] Could not send HELO to instructor server." << std::endl;
        close(sock);
        return "";
    }

    std::cout << "[INFO] Sent HELO to instructor server." << std::endl;

    // receive respsonse
    char buffer[1024];
    ssize_t received = recv(sock, buffer, sizeof(buffer), 0);
    if (received > 0) {
        std::string response = parseMessage(buffer, received);
        log_message("RECV from instructor server: " + response);
        std::cout << "[INFO] Received from instructor server: " << response << std::endl;
        close(sock);
        return response;
    } else {
        log_message("Error: Could not receive response from instructor server.");
        std::cout << "[ERROR] Could not receive response from instructor server." << std::endl;
        close(sock);
        return "";
    }
}

// This function will handle commands received from a connected client
void handle_server_command(int client_sock, const std::string& command) {
    log_message("RECV: " + command);
    
    std::string response = "";
    
    if (command.substr(0, 4) == "HELO") {
        // we want to find the comma, and then extract the groupID
        size_t commaPos = command.find(',');
        if (commaPos != std::string::npos) {
            std::string fromGroupId = command.substr(commaPos + 1);
            response = process_helo(fromGroupId);
        }
    }
    else if (command == "SERVERS") {
        response = process_servers_request();
    }
    else if (command.substr(0, 8) == "GETMSGS,") {
        std::string groupId = command.substr(8);
        response = process_getmsgs(groupId);
    }
    else if (command.substr(0, 8) == "SENDMSG,") {
        // Parse: SENDMSG,TO_GROUP_ID,FROM_GROUP_ID,Message content
        size_t firstComma = command.find(',');
        size_t secondComma = command.find(',', firstComma + 1);
        size_t thirdComma = command.find(',', secondComma + 1);
        
        if (firstComma != std::string::npos && secondComma != std::string::npos && thirdComma != std::string::npos) {
            std::string toGroupId = command.substr(firstComma + 1, secondComma - firstComma - 1);
            std::string fromGroupId = command.substr(secondComma + 1, thirdComma - secondComma - 1);
            std::string content = command.substr(thirdComma + 1);
            process_sendmsg(toGroupId, fromGroupId, content);
        }
    }
    else if (command.substr(0, 9) == "KEEPALIVE") {
        // Process keepalive - extract message count if needed
        log_message("Received KEEPALIVE from client");
    }
    else if (command == "STATUSREQ") {
        response = process_statusreq();
    }
    else {
        log_message("Unknown command received: " + command);
    }
    
    if (!response.empty()) {
        sendFramedMessage(client_sock, response);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1;
    }
    int port = std::stoi(argv[1]);
    start_server(port);
    sendInstructorServerHelo();
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

    while (true) {
        // 5. Accept an incoming connection; this call blocks until a client connects
        // when a client connects, we get a new socket dedicated to this client
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            std::cerr << "Error: Accept failed.\n";
            continue; // don’t kill the server, keep accepting
        }

        // Spawn a thread to handle this client
        std::thread client_thread(handle_client, client_sock, client_addr);
        client_thread.detach(); // don’t block waiting for it
    }

}

// This function will handle communication with a connected client
// it will read messages, format them in the correct format which we have defined
// and it will the determine the what function to call based on the command.
void handle_client(int client_sock, sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);
    
    log_message("Client connected from " + std::string(client_ip) + ":" + std::to_string(client_port));

    char buffer[6000];
    
    // Keep the connection open and handle multiple messages
    while (true) {
        ssize_t bytes = recv(client_sock, buffer, sizeof(buffer), 0);
        
        if (bytes <= 0) {
            // Connection closed or error
            log_message("Client disconnected: " + std::string(client_ip) + ":" + std::to_string(client_port));
            break;
        }
        
        // Parse the framed message
        std::string command = parseMessage(buffer, bytes);
        
        if (!command.empty()) {
            log_message("Received valid framed message from " + std::string(client_ip));
            handle_server_command(client_sock, command);
        } else {
            log_message("Received invalid or malformed message from " + std::string(client_ip));
        }
    }
    
    close(client_sock);
}