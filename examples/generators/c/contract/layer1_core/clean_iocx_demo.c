#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv)
{
   // A clean, realistic filepath for IOCX to extract
   const char *demo_path = "C:\\Users\\Public\\Documents\\iocx_demo.exe";
   printf("Demo file path: %s\n", demo_path);

   // Also print argv[0] for realism (not required for IOC extraction)
   if (argc > 0 && argv[0]) {
       printf("Executable path: %s\n", argv[0]);
   }

   printf("IOCX demo: deterministic PE analysis.\n");

   SYSTEMTIME st;
   GetSystemTime(&st);

   printf("Current UTC time: %04d-%02d-%02d %02d:%02d:%02d\n",
          st.wYear, st.wMonth, st.wDay,
          st.wHour, st.wMinute, st.wSecond);

   return 0;
