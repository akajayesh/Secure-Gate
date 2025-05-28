import cv2
import mediapipe as mp
import numpy as np
import json
import os

mp_hands = mp.solutions.hands
mp_drawing = mp.solutions.drawing_utils

REGISTER_FILE = 'registered_right.json'

cap = cv2.VideoCapture(0)

# Helper to draw bigger dots
class CustomDrawing:
    @staticmethod
    def draw_landmarks(image, hand_landmarks, connections):
        for idx, lm in enumerate(hand_landmarks.landmark):
            h, w, _ = image.shape
            cx, cy = int(lm.x * w), int(lm.y * h)
            cv2.circle(image, (cx, cy), 10, (0, 255, 255), -1)  # Big yellow dots
        if connections:
            mp_drawing.draw_landmarks(image, hand_landmarks, connections)

def save_landmarks(landmarks):
    arr = np.array([[lm.x, lm.y, lm.z] for lm in landmarks.landmark])
    with open(REGISTER_FILE, 'w') as f:
        json.dump(arr.tolist(), f)

def load_landmarks():
    if not os.path.exists(REGISTER_FILE):
        return None
    with open(REGISTER_FILE, 'r') as f:
        arr = np.array(json.load(f))
    return arr

def is_real_right_hand(results):
    if results.multi_handedness:
        for hand in results.multi_handedness:
            if hand.classification[0].label == 'Left':
                return True
    return False

def align_landmarks(landmarks):
    arr = np.array([[lm.x, lm.y, lm.z] for lm in landmarks.landmark])
    arr -= arr.mean(axis=0)
    arr /= np.linalg.norm(arr)
    return arr
    
def match_landmarks(landmarks, registered, threshold=0.08):
    arr = np.array([[lm.x, lm.y, lm.z] for lm in landmarks.landmark])
    if registered is None:
        return False
    diff = np.linalg.norm(arr - registered)
    return diff < threshold

with mp_hands.Hands(
    static_image_mode=False,
    max_num_hands=1,
    min_detection_confidence=0.7,
    min_tracking_confidence=0.7
) as hands:
    unlocked = False
    registered = load_landmarks()
    if registered is not None:
        registered = np.array(registered)
# ... existing code ...
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        image.flags.writeable = False
        results = hands.process(image)
        image.flags.writeable = True
        image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
    
        if results.multi_hand_landmarks and is_real_right_hand(results):
            hand_landmarks = results.multi_hand_landmarks[0]
            CustomDrawing.draw_landmarks(image, hand_landmarks, mp_hands.HAND_CONNECTIONS)
            if registered is not None and match_landmarks(hand_landmarks, registered):
                if not unlocked:
                    print("Your Right Palm is Registered")
                    unlocked = True
            else:
                unlocked = False
        else:
            unlocked = False
    
        cv2.putText(image, 'Press r to register your Right palm', (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,255,255), 2)
        cv2.imshow('Palm Unlock', image)
        key = cv2.waitKey(5) & 0xFF
        if key == 27:
            break
        elif key == ord('r') and results.multi_hand_landmarks and is_real_right_hand(results):
            save_landmarks(results.multi_hand_landmarks[0])
            print('Right palm registered!')
            registered = load_landmarks()
            break  # Exit loop after registration
cap.release()
cv2.destroyAllWindows()