#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

void print_banner() {
    printf("=================================\n");
    printf("  Swiss Precision Time Control   \n");
    printf("  Horloger Suisse TimeDateCtl    \n");
    printf("=================================\n\n");
}

void show_help() {
    printf("Usage: timedatectl [COMMAND]\n\n");
    printf("Commands:\n");
    printf("  status              Show current time/date settings\n");
    printf("  show-timesync       Show time synchronization settings\n");
    printf("  set-timezone ZONE   Set system timezone\n");
    printf("  help                Show this help message\n\n");
    printf("Swiss precision guaranteed!\n");
}

void show_status() {
    printf("Local time: ");
    fflush(stdout);
    system("date");
    
    printf("Universal time: ");
    fflush(stdout);
    system("date -u");
    
    printf("Time zone: ");
    fflush(stdout);
    system("cat /etc/timezone 2>/dev/null || echo 'UTC'");
}

void show_timesync() {
    printf("Time synchronization status:\n");
    printf("NTP service: ");
    fflush(stdout);
    system("systemctl is-active ntp 2>/dev/null || echo 'inactive'");
    
    printf("System clock synchronized: ");
    fflush(stdout);
    system("timedatectl status | grep 'System clock synchronized' 2>/dev/null || echo 'Unknown'");
}

void set_timezone(char *timezone) {
    char command[512];
    
    printf("[Swiss Horloger] Setting timezone to: %s\n", timezone);
    
    // VULNERABILITY: Command injection through unsanitized input
    // The timezone parameter is directly concatenated into a system command
    snprintf(command, sizeof(command), "ln -sf /usr/share/zoneinfo/%s /etc/localtime", timezone);
    
    printf("[Swiss Horloger] Executing: %s\n", command);
    system(command);
    
    printf("[Swiss Horloger] Timezone updated with Swiss precision!\n");
}

int main(int argc, char *argv[]) {
    // Set real and effective UID to root (setuid behavior)
    if (setuid(0) != 0) {
        perror("setuid failed");
        // Continue anyway for demo purposes
    }
    
    print_banner();
    
    if (argc < 2) {
        printf("No command specified.\n\n");
        show_help();
        return 1;
    }
    
    if (strcmp(argv[1], "status") == 0) {
        show_status();
    }
    else if (strcmp(argv[1], "show-timesync") == 0) {
        show_timesync();
    }
    else if (strcmp(argv[1], "set-timezone") == 0) {
        if (argc < 3) {
            printf("Error: Timezone not specified\n");
            printf("Usage: timedatectl set-timezone ZONE\n");
            return 1;
        }
        set_timezone(argv[2]);
    }
    else if (strcmp(argv[1], "help") == 0) {
        show_help();
    }
    else {
        printf("Unknown command: %s\n\n", argv[1]);
        show_help();
        return 1;
    }
    
    return 0;
} 