#include <stdio.h> 
#include <unistd.h> 
#include <string.h> 
#include <fcntl.h> 
#include <stdlib.h> 

static char win[128]; 
static volatile unsigned char is_premium = 0; 

static void boarding_pass_upgrade(void) {
    if (is_premium == 0)
        puts("[Imprimante] Classe Économie uniquement — pas de surclassement possible."); 
    else { 
        puts("[Imprimante] Code de surclassement détecté sur la carte d’embarquement :"); 
        int f = open("/tmp/flag.txt", O_RDONLY); 
        if (f >= 0) { 
            ssize_t n = read(f, win, sizeof(win) - 1); 
            if (n < 0) n = 0; 
            win[n] = '\0'; 
            close(f); 
        } else 
            strcpy(win, "flag-fake");  
    } 
} 
            
static void boarding_pass(void) { 
    FILE *bp = fopen("/dev/null", "r"); 
    void const* bp_buf = malloc(0x100); 
    puts("[Borne] Veuillez insérer votre carte d’embarquement :"); 
    read(0, bp, 0x1e0); 
    puts("[Imprimante] Impression de la carte d’embarquement en cours..."); 
    fread(bp_buf, 1, 1, bp); 
} 

static void print_baggage(void) { 
    FILE *bp = fopen("/dev/null", "w"); 
    void const* bg_buf = malloc(0x100); 
    puts("[Borne] Entrez le nombre de bagages enregistrés :"); 
    read(0, bp, 0x1e0); 
    if (is_premium == 0) { 
        puts("[Borne] Statut : Classe Économie."); 
    } else { 
        puts("[Imprimante] Impression des étiquettes bagages Premium..."); 
        fwrite(bg_buf, 1, 0x100, bp); 
    } 
} 

int main(void) { 
    setvbuf(stdout, NULL, _IONBF, 0);
    char line[8]; 
    for (;;) { 
        puts("\n=== Borne d’enregistrement — Aéroport Jakarta ==="); 
        puts("1) Lire la carte d’embarquement"); 
        puts("2) Surclasser la carte d’embarquement"); 
        puts("3) Imprimer les étiquettes bagages"); 
        puts("4) Quitter"); 
        puts("> "); 
        fflush(stdout); 
        if (!fgets(line, sizeof(line), stdin)) break; 
        switch (line[0]) { 
            case '1': boarding_pass(); break; 
            case '2': boarding_pass_upgrade(); break; 
            case '3': print_baggage(); break; 
            case '4': return 0; 
            default: puts("Choix invalide."); 
        } 
    } 
    return 0; 
}


