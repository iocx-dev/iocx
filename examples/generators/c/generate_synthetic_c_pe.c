#include <stdio.h>

const char* iocs[] = {
    "https://c2.example.com/api",
    "evil-domain.net",
    "attacker@example.org",
    "C:\\Users\\Victim\\Documents\\secrets.txt",
    "\\\\fileserver01\\malware\\dropper.exe",
    "\\\\10.0.0.42\\c$\\Windows\\Temp\\evil.ps1",
    "192.168.56.101",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aGVsbG8gd29ybGQ=",
};

int main() {
    printf("ok\n");
    return 0;
}

/* compile using MinGW
  sudo apt install mingw-w64
  x86_64-w64-mingw32-gcc -o pe_with_iocs.exe pe_with_iocs.c
*/
