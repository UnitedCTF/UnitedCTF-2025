#define _GNU_SOURCE

#include "auto_decrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <mntent.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#define PASSPHRASE_SIZE 0

const char data[PASSPHRASE_SIZE];

char checksums[4][65];

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <device> <cryptname>\n", argv[0]);
        return 1;
    }

    fprintf(stderr, "Hello, I am the auto-decryption program.\n");
    fprintf(stderr, "I will decrypt the LUKS partition for you, but only if you pass all my checks.\n");
    fprintf(stderr, "Let's get started...\n");

    sleep(5);

    // Calculate the SHA256 hash of ./init
    char hash[65];
    if (sha256_file("/init", hash) != 0)
    {
        fprintf(stderr, "Error calculating hash: %s\n", strerror(errno));
        return 1;
    }

    if (strcmp(hash, "9a25937d2434df2e0cb94f5082c3deafa4fef487b59c88c64e2a584de17d807b") != 0)
    {
        fprintf(stderr, "Hash does not match expected value.\n");
        return 1;
    }
    else
    {
        fprintf(stderr, "Hash of /init matches expected value.\n");
    }

    sleep(1);

    if (check_parent() != 0)
    {
        fprintf(stderr, "Parent check failed.\n");
        return 1;
    }

    sleep(1);

    if (check_uname() != 0)
    {
        fprintf(stderr, "uname check failed.\n");
        return 1;
    }

    sleep(1);

    if (check_mounts() != 0)
    {
        fprintf(stderr, "Mounts check failed.\n");
        return 1;
    }

    sleep(1);

    if (check_ptrace() != 0)
    {
        fprintf(stderr, "ptrace check failed.\n");
        return 1;
    }

    sleep(1);

    if (check_integrity(argv[1], argv[2]) != 0)
    {
        fprintf(stderr, "Integrity check failed.\n");
        return 1;
    }

    return 0;
}

void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int sha256_string(const char *str, int str_length, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        handleErrors();

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
        handleErrors();

    if (EVP_DigestUpdate(mdctx, str, str_length) != 1)
        handleErrors();

    unsigned int digestLen;
    if (EVP_DigestFinal_ex(mdctx, hash, &digestLen) != 1)
        handleErrors();

    sha256_hash_string(hash, outputBuffer);
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int sha256_file(char *path, char outputBuffer[65])
{
    FILE *file = fopen(path, "rb");
    if (!file)
        return -1;

    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        handleErrors();

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
        handleErrors();

    const int bufSize = 32768;
    unsigned char *buffer = (unsigned char *)malloc(bufSize);

    int bytesRead = 0;
    if (!buffer)
        return ENOMEM;

    while ((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        // SHA256_Update(&sha256, buffer, bytesRead);
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1)
            handleErrors();
    }

    unsigned char *hash = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
    if (!hash)
        handleErrors();

    unsigned int digestLength;
    if (EVP_DigestFinal_ex(mdctx, hash, &digestLength) != 1)
        handleErrors();

    sha256_hash_string(hash, outputBuffer);
    fclose(file);
    free(buffer);
    return 0;
}

void digest_message(const char *message, unsigned char **digest, unsigned int *digestLen)
{
    EVP_MD_CTX *mdctx;

    if ((mdctx = EVP_MD_CTX_new()) == NULL)
        handleErrors();

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
        handleErrors();

    if (1 != EVP_DigestUpdate(mdctx, message, strlen(message)))
        handleErrors();

    if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
        handleErrors();

    if (1 != EVP_DigestFinal_ex(mdctx, *digest, digestLen))
        handleErrors();

    EVP_MD_CTX_free(mdctx);
}

int check_parent()
{
    pid_t ppid = getppid();
    if (ppid != 1)
    {
        fprintf(stderr, "Parent process is not init (PID: 1). Current parent PID: %d\n", ppid);
        return -1;
    }
    else
    {
        fprintf(stderr, "Parent process is init (PID: 1).\n");
    }

    char procPath[64];
    snprintf(procPath, sizeof(procPath), "/proc/%d/cmdline", ppid);

    FILE *cmdlineFile = fopen(procPath, "r");
    if (!cmdlineFile)
    {
        fprintf(stderr, "Failed to open %s: %s\n", procPath, strerror(errno));
        return -1;
    }

    char cmdline[4096];
    size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, cmdlineFile);
    fclose(cmdlineFile);

    if (len == 0)
    {
        fprintf(stderr, "Failed to read parent cmdline\n");
        return -1;
    }
    cmdline[len] = '\0';

    char *firstPart = cmdline;
    char *secondPart = cmdline + strlen(cmdline) + 1; // Skip the null terminator

    if (strcmp(firstPart, "/usr/bin/ash") != 0 || strcmp(secondPart, "/init") != 0)
    {
        fprintf(stderr, "Parent process is not as expected\n");
        return -1;
    }
    else
    {
        fprintf(stderr, "Parent process is the expected script.\n");
    }

    if (sha256_file("/hooks/encrypt", checksums[0]) != 0)
    {
        fprintf(stderr, "Error calculating hash\n");
        return 1;
    }

    return 0;
}

int check_uname()
{
    struct utsname unameInfo;
    uname(&unameInfo);

    if ((strcmp(unameInfo.release, "6.16.2-arch1-1") != 0) || (strstr(unameInfo.version, "20 Aug 2025") == NULL))
    {
        fprintf(stderr, "You are not running the right OS version.\n");
        return -1;
    }

    fprintf(stderr, "You are running the right OS version.\n");
    return 0;
}

int check_mounts()
{
    struct mntent *ent;
    FILE *mountsFile;

    mountsFile = setmntent("/proc/mounts", "r");
    if (mountsFile == NULL)
    {
        perror("setmntent");
        return -1;
    }

    bool foundRootfs = false;
    while (NULL != (ent = getmntent(mountsFile)))
    {
        if ((strcmp(ent->mnt_type, "rootfs") == 0) && (strcmp(ent->mnt_dir, "/") == 0))
        {
            foundRootfs = true;
            break;
        }
    }

    endmntent(mountsFile);

    if (!foundRootfs)
    {
        fprintf(stderr, "Root filesystem not found.\n");
        return -1;
    }

    fprintf(stderr, "Root filesystem found.\n");

    return 0;
}

int check_ptrace()
{
    FILE *processStatus;

    processStatus = fopen("/proc/self/status", "r");
    if (processStatus == NULL)
    {
        fprintf(stderr, "Failed to open /proc/self/status: %s\n", strerror(errno));
        return -1;
    }

    char line[256];
    bool ptraceFound = false;
    while (fgets(line, sizeof(line), processStatus) != NULL)
    {
        if (strncmp(line, "TracerPid:", 10) == 0)
        {
            int tracerPid;
            if (sscanf(line + 10, "%d", &tracerPid) != 1)
            {
                fprintf(stderr, "Failed to parse TracerPid\n");
                fclose(processStatus);
                return -1;
            }
            if (tracerPid != 0)
            {
                fprintf(stderr, "Process is being traced by PID: %d\n", tracerPid);
                fclose(processStatus);
                return -1;
            }
            else
            {
                ptraceFound = true;
                break;
            }
        }
    }

    fclose(processStatus);

    if (!ptraceFound)
    {
        fprintf(stderr, "TracerPid not found in /proc/self/status\n");
        return -1;
    }

    fprintf(stderr, "ptrace check succeeded.\n");
    return 0;
}

void xor_decrypt(const char *key, const char *data, char *output, int keyLength, int outputSize)
{
    int i;
    for (i = 0; i < outputSize; i++)
    {
        output[i] = data[i] ^ key[i % keyLength];
    }
    output[i] = '\0';
}

int check_integrity(char *devname, char *cryptname)
{
    // Create a function pointer to main
    int (*main_ptr)(int, char **) = &main;

    int programSize = 0x1500;

    // Copy contents of main to a buffer
    unsigned char *buffer = (unsigned char *)malloc(programSize);
    if (buffer == NULL)
    {
        fprintf(stderr, "Memory allocation failed.\n");
        return -1;
    }

    // Copy the contents of main to the buffer
    memcpy(buffer, main_ptr, programSize);

    // Calculate the SHA256 hash of the buffer
    sha256_string((const char *)buffer, programSize, checksums[1]);
    free(buffer);

    sha256_file("/usr/bin/cryptsetup", checksums[2]);

    char checksums_combined[193]; // 3 * 65 characters + 1 for null terminator
    snprintf(checksums_combined, sizeof(checksums_combined), "%s%s%s", checksums[0], checksums[1], checksums[2]);

    sha256_string(checksums_combined, strlen(checksums_combined), checksums[3]);

    char output[sizeof(data) + 1];

    xor_decrypt(data, checksums[3], output, sizeof(data), sizeof(data));
    output[sizeof(data)] = '\0';

    return decrypt_disk(devname, cryptname, output);
}

int decrypt_disk(char *devname, char *cryptname, char *key)
{
    fprintf(stderr, "All checks completed. Executing cryptsetup\n");

    int pipeFd[2];
    if (pipe(pipeFd) == -1)
    {
        fprintf(stderr, "Pipe creation failed: %s\n", strerror(errno));
        return -1;
    }

    int forkPid = fork();
    if (forkPid < 0)
    {
        fprintf(stderr, "Fork failed: %s\n", strerror(errno));
        return -1;
    }
    if (forkPid > 0)
    {
        // Parent process
        fprintf(stderr, "Parent process (PID: %d) created child process (PID: %d)\n", getpid(), forkPid);

        close(pipeFd[0]);
        if (write(pipeFd[1], key, sizeof(data)) == -1)
        {
            fprintf(stderr, "Write to pipe failed: %s\n", strerror(errno));
            close(pipeFd[1]);
            return -1;
        }

        close(pipeFd[1]);

        fprintf(stderr, "Parent process waiting for child to finish...\n");

        int status;
        if (waitpid(forkPid, &status, 0) == -1)
        {
            fprintf(stderr, "Waitpid failed: %s\n", strerror(errno));
            return -1;
        }

        if (WIFEXITED(status))
        {
            fprintf(stderr, "Child process exited with status %d\n", WEXITSTATUS(status));
        }
        else if (WIFSIGNALED(status))
        {
            fprintf(stderr, "Child process was terminated by signal %d\n", WTERMSIG(status));
        }
        else
        {
            fprintf(stderr, "Child process did not exit normally\n");
        }

        return 0;
    }
    else
    {
        // Child process
        close(pipeFd[1]);
        dup2(pipeFd[0], STDIN_FILENO);
        close(pipeFd[0]);

        fprintf(stderr, "Child process executing cryptsetup with device %s and cryptname %s\n", devname, cryptname);

        if (execl("/usr/bin/cryptsetup",
                  "cryptsetup",
                  "open",
                  "--type", "luks",
                  "--key-file=-",
                  devname,
                  cryptname,
                  NULL) == -1)
        {
            fprintf(stderr, "execl failed: %s\n", strerror(errno));
            return -1;
        }

        return 0;
    }

    return 0;
}
