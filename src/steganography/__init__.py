import cv2
import numpy as np
import os

d = {chr(i): i for i in range(255)}
c = {i: chr(i) for i in range(255)}

def encrypt():
    filepath = input("Enter the image path: ")
    if not os.path.exists(filepath):
        print("Invalid file path!")
        return

    img = cv2.imread(filepath)
    if img is None:
        print("Error: Unable to read image.")
        return

    msg = input("Enter the secret message: ")
    password = input("Enter a passcode: ")
    msg_length = len(msg)
    if msg_length > img.shape[0] * img.shape[1]:
        print("Error: Message too long for the image.")
        return

    img[0, 0, 0] = msg_length
    img[0, 0, 1] = ord(password[0]) if len(password) > 0 else 0

    n, m, z = 0, 1, 0
    for i in range(msg_length):
        img[n, m, z] = d[msg[i]]
        n = (n + 1) % img.shape[0]
        m = (m + 1) % img.shape[1]
        z = (z + 1) % 3

    encrypted_path = "encryptedImage.png"
    cv2.imwrite(encrypted_path, img.astype(np.uint8))
    print(f"Encryption completed. Encrypted image saved as '{encrypted_path}'")

def decrypt():
    filepath = input("Enter the encrypted image path: ")
    if not os.path.exists(filepath):
        print("Invalid file path!")
        return

    img = cv2.imread(filepath)
    if img is None:
        print("Error: Unable to read image.")
        return

    msg_length = img[0, 0, 0]
    if msg_length <= 0 or msg_length > img.shape[0] * img.shape[1]:
        print("Error: Image does not contain a valid encrypted message.")
        return

    user_pass = input("Enter passcode for decryption: ")
    stored_pass_hint = chr(img[0, 0, 1]) if img[0, 0, 1] > 0 else ""

    if stored_pass_hint and user_pass[0] != stored_pass_hint:
        print("Error: Incorrect passcode.")
        return
    message = ""
    n, m, z = 0, 1, 0
    for _ in range(msg_length):
        message += c.get(img[n, m, z], '?')
        n = (n + 1) % img.shape[0]
        m = (m + 1) % img.shape[1]
        z = (z + 1) % 3

    print(f"Decrypted message: {message}")

def main():
    print("What do you want to do?")
    print("1. Encryption")
    print("2. Decryption")

    choice = input("Enter your choice (1 or 2): ")
    if choice == "1":
        encrypt()
    elif choice == "2":
        decrypt()
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()