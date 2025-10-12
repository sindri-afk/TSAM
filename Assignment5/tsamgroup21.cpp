#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

void start_server(int port) {
    // here we want to a. create socket, b. bind the socket, c. listen, d. accept
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket creation failed");
        return;
    } else {
        std::cout << "\n" << "socket created successfully" << std::endl; 
    }

    // set socket options to reuse address
    int opt = 1; 
    


}

int main() {
    return 0; 
}