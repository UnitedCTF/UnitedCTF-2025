/*
** client.c -- a stream socket client demo
*/

#include "common.h"

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define MAXDATASIZE 4096 // max number of bytes we can get at once

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int connect_to(char* hostname, char* port)
{
    int rv;
    char s[INET6_ADDRSTRLEN];
    int sockfd;

    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, port, &hints, &servinfo)) != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        inet_ntop(p->ai_family,
            get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
        std::cout << "Attempting connection to " << s << std::endl;

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client: connect");
            close(sockfd);
            continue;
        }

        break;
    }

    if (p == NULL) {
        std::cerr << "Error: Failed to connect!" << std::endl;
        return 2;
    }

    inet_ntop(p->ai_family,
            get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    std::cout << "Connected to " << s << std::endl;

    freeaddrinfo(servinfo); // all done with this structure

    return sockfd;
}

uint32_t get_seed(int sockfd)
{
    uint32_t seed;
    int numbytes;

    if ((numbytes = recv(sockfd, &seed, 4, 0)) == -1) {
        perror("recv");
        exit(1);
    }

    if (numbytes != 4) {
        std::cerr << "Error: Expected 4 bytes but got " << numbytes << std::endl;
        exit(1);
    }

    seed = ntohl(seed);

    return seed;
}

void receiveResponse(int sockfd)
{
    std::cout << "Received message from server:" << std::endl;

    std::string buffer(MAXDATASIZE, '\0');
    int numbytes = -1;
    while (numbytes != 0) {
        if ((numbytes = recv(sockfd, buffer.data(), MAXDATASIZE, 0)) == -1) {
            perror("recv");
            exit(1);
        }

        std::cout << std::string(buffer.data(), numbytes);
    }
}

int main(int argc, char *argv[])
{
    std::cout << \
        "Français :" << std::endl << \
        "Ceci est le client de connexion aux serveurs du KGB." << std::endl << \
        "Pour vous authentifier, vous devez fournir la phrase de passe secrète." << std::endl << \
        "Cependant, cette phrase de passe change à chaque tentative de connexion!" << std::endl << std::endl << \
        "English :" << std::endl << \
        "This is the client to connect to the KGB servers." << std::endl << \
        "To authenticate, you need to provide the secret passphrase." << std::endl << \
        "However, this passphrase changes at each connection attempt!" << std::endl << std::endl;

    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <hostname> <port>" << std::endl;
        exit(1);
    }

    int sockfd = connect_to(argv[1], argv[2]);

    uint32_t seed = get_seed(sockfd);

    PassphraseGenerator generator(seed);

    std::string fullMessage;
    uint32_t length = generator.getLength();

    for (size_t i = 0; i < length; i++) {
        std::cout << "Enter next word: ";
        std::string word;

        std::getline(std::cin, word);

        if (word != generator.generateWord()) {
            std::cerr << "Error: Wrong word!" << std::endl;
            close(sockfd);
            return 1;
        }

        fullMessage += word;
        if (i != length - 1) {
            fullMessage += '-';
        }
    }

    std::cout << "Sending passphrase to server..." << std::endl;

    fullMessage += '\n';

    if (send(sockfd, fullMessage.c_str(), fullMessage.size(), 0) == -1) {
        perror("send");
        exit(1);
    }

    receiveResponse(sockfd);

    close(sockfd);

    return 0;
}
