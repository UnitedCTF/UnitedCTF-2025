#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void generate_secret_code(char* code, size_t len) {
    FILE* file = fopen("/dev/urandom", "r"); 
    if(!file) {
        fprintf(stderr, "\nfailed to open secret code vault\n");
        exit(-1);
    }

    fread(code, 1, len, file);
}

char LANGUAGE[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void decode_language(char* out) {
    char input[64];
    printf("\n>> ");
    scanf("%63s", input);

    char* in = input;

    uint32_t buf = 0;
    int count = 0;

    do {
        char next = *in;
        if(next == '=') {
            ++out;
            continue;
        }

        char* lang_ptr = strchr(LANGUAGE, next);
        if(!lang_ptr) {
            printf("\nJe ne reconnais pas cette lettre: \"%c\". Visiblement, vous ne parlez pas notre langue!\n", next);
            exit(-1);
        }

        int lang_pos = lang_ptr - LANGUAGE;
        buf <<= 6;
        buf |= lang_pos;

        if(++count % 4 == 0) {
            *(out++) = (buf & 0xff0000) >> 16;
            *(out++) = (buf & 0xff00) >> 8;
            *(out++) = buf & 0xff;
        }
    } while(*(++in) != 0);

    if(count % 4 != 0) {
        while(count % 4 != 0) {
            buf <<= 6;
            ++count;
        }

        *(out++) = (buf & 0xff0000) >> 16;
        *(out++) = (buf & 0xff00) >> 8;
        *(out++) = buf & 0xff;
    }
}

void prompt_door() {
    char secret_code[16];
    generate_secret_code(secret_code, sizeof(secret_code));

    char decoded[16];
    decode_language(decoded);

    if(memcmp(decoded, secret_code, sizeof(secret_code)) == 0) {
        printf("\nVous avez été reconnu comme un Inca, voici notre secret le plus précieux:\n");
        system("cat /flag.txt");
    } else {
        printf("\nMauvais code. Vous n'êtes pas un vrai Inca, partez!\n");
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("\r-\\./-/'\\-\\./-/'\\-\\./-/'\\-\\./-\\-\\./-/'\\-\\./-/'\\-\n");
    printf(" /                                           /\n");
    printf(" \\     Bienvenue au Temple du Condor         \\\n");
    printf(" /   Veuillez prononcer le code secret...    /\n");
    printf(" \\                                           \\\n");
    printf("-/'\\-\\./-/'\\-\\./-/'\\-\\./-/-\\./-/'\\-\\./-/'\\-\\./-\n");

    prompt_door();
}