#ifndef AUTO_DECRYPT_H
#define AUTO_DECRYPT_H

int sha256_file(char *path, char outputBuffer[65]);
int check_parent();
int check_uname();
int check_mounts();
int check_ptrace();
int check_integrity(char* devname, char* cryptname);
int decrypt_disk(char* devname, char* cryptname, char* key);


#endif
