# Gesture-Gate
A palm based encryption and decryption system made to lock folder using AES algorithm.

Requirements :-
PYTHON 3.10+
Virtual Environment

Install the following tools also:-
opencv-python
mediapipe 
pycryptodome (AES)
customtkinter (GUI)

Run cleanUI.py is the core file.
Rest files are the backbone scripts of Core File.

Palm co-ordinates will be stored in registered_left/right.json

Make sure your webcam is stable or else the decryption/encryption won't work.

For worst cases, if decryption dosen't works, 
Delete both .json files and register your palm again.
Still no then use file simple.py and the password is mentioned 
in the file.

⚠️ Disclaimer
This project demonstrates a gesture-based encryption and decryption system. While the encryption and decryption logic is functional, users are strongly advised to keep a backup of all important files before using the system.

If an encryption process is interrupted or fails unexpectedly, there is a risk of data loss. To avoid this, always copy your files into the elements folder before running any encryption.

Please note that this system is a research-driven prototype. It is not intended for production use or sensitive data handling without further development and professional-grade tools.

Commands :-

Download this repository.
Run 
pip install opencv-python, mediapipe, pycryptodome, customtkinter

python cleanUI.py
