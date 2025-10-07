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

void prompt_door() {
    char secret_code[16];
    generate_secret_code(secret_code, sizeof(secret_code));

    char input[17];
    printf("\n>> ");
    fgets(input, sizeof(input), stdin);

    char* eol = strchr(input, '\n');
    if(eol) *eol = '\0';

    if(strcmp(input, secret_code) == 0) {
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
    printf(" \\    Bienvenue au Temple de la Lune         \\\n");
    printf(" /   Veuillez prononcer le code secret...    /\n");
    printf(" \\                                           \\\n");
    printf("-/'\\-\\./-/'\\-\\./-/'\\-\\./-/-\\./-/'\\-\\./-/'\\-\\./-\n");

    prompt_door();
}