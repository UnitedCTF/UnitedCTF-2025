#include "common.h"

#include <iostream>
#include <fstream>
#include <random>
#include <limits>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <arpa/inet.h>

using time_point = std::chrono::time_point<std::chrono::steady_clock>;
using std::chrono::steady_clock;

std::string getFlag()
{
    std::ifstream file("flag.txt");
    if (!file) {
        throw std::runtime_error("Failed to open flag.txt");
    }

    std::string flag;
    std::getline(file, flag);

    return flag;
}

uint32_t generateSeed()
{
    std::random_device dev;
    std::mt19937 rng(dev());

    std::uniform_int_distribution<std::mt19937::result_type> dist(0,std::numeric_limits<uint32_t>::max());

    return dist(rng);
}

void printSeed(uint32_t seed)
{
    seed = htonl(seed);

    char buffer[4];
    memcpy(buffer, &seed, 4);

    std::cout << std::string(buffer, 4);
}

int main()
{
    time_point start = steady_clock::now();

    std::string flag = getFlag();

    uint32_t seed = generateSeed();
    printSeed(seed);

    PassphraseGenerator generator(seed);
    std::string passphrase = generator.generateAll();

    std::string inputPassphrase;
    std::getline(std::cin, inputPassphrase);

    time_point end = steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (duration > 1000) {
        std::cout << "Trop lent! Too slow!" << std::endl;
        return 1;
    }

    if (inputPassphrase != passphrase) {
        std::cout << "Mauvaise phrase de passe! Wrong passphrase!" << std::endl;
        return 1;
    }

    std::cout << "Correct! Vous êtes authentifié comme administrateur suprême du KGB!" << std::endl;
    std::cout << "Voici votre récompense: " << flag << std::endl;
    std::cout << "Correct! You are authenticated as the supreme administrator of the KGB!" << std::endl;
    std::cout << "Here is your reward: " << flag << std::endl;

    return 0;
}
