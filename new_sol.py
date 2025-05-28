import cv2
import mediapipe as mp
import numpy as np
import json
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

FOLDER = 'elements'
PASSWORD = 'Abc123$%45'  # Must match the one used for encryption
SALT = b'James-Salvatore'          # Must match the one used for encryption

REGISTER_FILE_LEFT = 'registered_left.json'
REGISTER_FILE_RIGHT = 'registered_right.json'

mp_hands = mp.solutions.hands
mp_drawing = mp.solutions.drawing_utils

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext)
    out_path = filepath[:-4]  # Remove .enc
    with open(out_path, 'wb') as f:
        f.write(plaintext)
    os.remove(filepath)

def load_landmarks(filename):
    if not os.path.exists(filename):
        return None
    with open(filename, 'r') as f:
        arr = np.array(json.load(f))
    return arr

def is_real_right_hand(results):
    # Webcam is mirrored: real right hand appears as 'Left' to MediaPipe
    if results.multi_handedness:
        for hand in results.multi_handedness:
            if hand.classification[0].label == 'Left':
                return True
    return False

def is_real_left_hand(results):
    # Webcam is mirrored: real left hand appears as 'Right' to MediaPipe
    if results.multi_handedness:
        for hand in results.multi_handedness:
            if hand.classification[0].label == 'Right':
                return True
    return False

def match_landmarks(landmarks, registered, threshold=0.12):
    arr = np.array([[lm.x, lm.y, lm.z] for lm in landmarks.landmark])
    if registered is None:
        return False
    diff = np.linalg.norm(arr - registered)
    return diff < threshold
    print("Matching diff:", diff)    
    

def palm_unlock(palm_type):
    if palm_type == 'right':
        reg_file = REGISTER_FILE_RIGHT
        hand_check = is_real_right_hand
        prompt = 'Show your REAL RIGHT palm to unlock...'
    else:
        reg_file = REGISTER_FILE_LEFT
        hand_check = is_real_left_hand
        prompt = 'Show your REAL LEFT palm to unlock...'
    registered = load_landmarks(reg_file)
    if registered is None:
        print(f"No registered {palm_type} palm found. Please register first.")
        return False

    cap = cv2.VideoCapture(0)
    with mp_hands.Hands(
        static_image_mode=False,
        max_num_hands=1,
        min_detection_confidence=0.7,
        min_tracking_confidence=0.7
    ) as hands:
        unlocked = False
        print(prompt)
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
            image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            image.flags.writeable = False
            results = hands.process(image)
            image.flags.writeable = True
            image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)

            if results.multi_hand_landmarks and hand_check(results):
                hand_landmarks = results.multi_hand_landmarks[0]
                for idx, lm in enumerate(hand_landmarks.landmark):
                    h, w, _ = image.shape
                    cx, cy = int(lm.x * w), int(lm.y * h)
                    cv2.circle(image, (cx, cy), 10, (0, 255, 255), -1)
                mp_drawing.draw_landmarks(image, hand_landmarks, mp_hands.HAND_CONNECTIONS)
                if match_landmarks(hand_landmarks, registered):
                    cv2.putText(image, 'Unlocked!', (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 1, (0,255,0), 3)
                    cv2.imshow('Palm Unlock', image)
                    print("Unlocked. Proceeding to decrypt files...")
                    unlocked = True
                    cv2.waitKey(1000)
                    break
            cv2.putText(image, prompt, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,255,255), 2)
            cv2.imshow('Palm Unlock', image)
            if cv2.waitKey(5) & 0xFF == 27:
                break
        cap.release()
        cv2.destroyAllWindows()
    return unlocked

def decrypt_folder():
    key = PBKDF2(PASSWORD, SALT, dkLen=32)
    folder_path = os.path.join(os.getcwd(), FOLDER)
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path) and filename.endswith('.enc'):
            decrypt_file(file_path, key)
            print(f'Decrypted: {filename}')


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        palm_type = sys.argv[1].lower()
        if palm_type not in ('right', 'left'):
            print("Invalid palm type argument. Use 'right' or 'left'.")
            exit(1)
    else:
        print("Which palm do you want to use for unlocking?")
        print("1. Real RIGHT palm\n2. Real LEFT palm")
        choice = input("Enter 1 or 2: ").strip()
        if choice == '1':
            palm_type = 'right'
        elif choice == '2':
            palm_type = 'left'
        else:
            print("Invalid choice.")
            exit(1)
    if palm_unlock(palm_type):
        decrypt_folder()
        print("All files in 'jack' have been decrypted!")
    else:
        print("Palm authentication failed. Files remain locked.")
