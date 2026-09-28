# Process Injection — Astra Labs

Companion code for the process injection video on the Astra YouTube channel.

## Requirements

- Kali Linux (attacker)
- Windows VM (victim, isolated)
- MinGW-w64: `sudo apt install mingw-w64`
- Metasploit Framework
- Process Hacker on the Windows VM

## Compile

```bash
x86_64-w64-mingw32-gcc processInjection.c -o processInjection.exe -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

## Usage

```bash
processInjection.exe <PID>
```

Pass the PID of your target process as the argument. Shellcode generation is covered in the video.

## Disclaimer

For educational use only. Run this in an isolated lab environment that you own and control.
