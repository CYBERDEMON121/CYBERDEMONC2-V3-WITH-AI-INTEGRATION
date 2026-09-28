#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD actionReason, LPVOID reservedPointer) {
  switch (actionReason) {
    case DLL_PROCESS_ATTACH:
    MessageBox(NULL, "Hello from malware.dll!", "=^..^=", MB_OK);
    break;
    case DLL_PROCESS_DETACH:
    break;
    case DLL_THREAD_ATTACH:
    break;
    case DLL_THREAD_DETACH:
    break;
  }
  return TRUE;
}
