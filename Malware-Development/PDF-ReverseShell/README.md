# Reverse Shell Disguised as a PDF (PoC)

This project demonstrates a simple Python-based **reverse shell** that launches alongside a decoy **PDF document**, mimicking a harmless file to trick users into executing the payload.

This is a **proof of concept** created **strictly for educational purposes** and should only be used in controlled lab environments.

---

## Objective

Build a reverse shell that connects back to a listener when executed, while simultaneously displaying a fake PDF to avoid suspicion.

This project accompanies a full [YouTube walkthrough](https://www.youtube.com/@Astra-labs) where I explain each step, from writing the code to compiling the executable.

---

## How It Works

When the payload is executed:

1. A separate thread opens a PDF (`FakeResume.pdf`) using the system default PDF viewer.
2. The main thread initiates a reverse shell to a remote IP and port using Python's `socket` module.
3. This creates the illusion of a benign file while gaining shell access to the target machine.

---

## Build Instructions

To compile this into a standalone Windows executable using `pyinstaller`, make sure to include the decoy PDF and icon file with your build. Make sure to run the following command in the same directory as the cloned project.

```bash
pyinstaller --onefile --noconsole --icon=pdf.ico --add-data "FakeResume.pdf;." --name resume .\resume.py
```

---

## Files Included

reverse-shell/
 -   resume.py # Reverse shell logic + PDF launcher
 -   FakeResume.pdf # Decoy PDF document
 -   pdf.ico # Fake PDF icon
 -   README.md

---

## Notes

- This script is intentionally simple and **not designed to evade antivirus or EDR**.
- Intended for researchers, students, and red teamers studying malware behavior and payload development in a safe environment.

---

## Legal & Ethical Notice

Use this code **only** in isolated lab environments and with full authorization.\
**Do not** deploy or distribute in unauthorized or real-world contexts.

---

## Follow Along

- 📺 [YouTube: ASTRA Labs](https://www.youtube.com/@Astra-labs) – Full reverse shell video

---
