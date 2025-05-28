import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import sys
import subprocess
from functools import partial
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Script constants
REGISTER_LEFT_SCRIPT = 'register_left.py'
REGISTER_RIGHT_SCRIPT = 'register_right.py'
PALM_DECRYPT_SCRIPT = 'new_sol.py'
FALLBACK_DECRYPT_SCRIPT = 'simple.py'
SALT = b'\x00\x01\x02\x03\x04\x05\x06\x07'

# === Core UI Components ===

class LogPanel(ctk.CTkTextbox):
    def __init__(self, master, **kwargs):
        super().__init__(master, height=80, state='disabled', **kwargs)
        self.tag_config('info', foreground='#00bfff')
        self.tag_config('success', foreground='#00c853')
        self.tag_config('error', foreground='#ff1744')
    def log(self, message, tag='info'):
        self.configure(state='normal')
        self.insert('end', message + '\n', tag)
        self.see('end')
        self.configure(state='disabled')

class ProgressPopup(ctk.CTkToplevel):
    def __init__(self, master, title, max_value):
        super().__init__(master)
        self.title(title)
        self.geometry('400x120')
        self.resizable(False, False)
        self.lift()
        self.focus_force()

        self.progress = ctk.CTkProgressBar(self, width=350)
        self.progress.pack(pady=30)
        self.progress.set(0)
        self.label = ctk.CTkLabel(self, text='Starting...', font=('Segoe UI', 14))
        self.label.pack()
        self.max_value = max_value
        self.value = 0
        self.protocol('WM_DELETE_WINDOW', self.disable_event)
    def update_progress(self, value, text=None):
        self.value = value
        self.progress.set(value / self.max_value)
        if text:
            self.label.configure(text=text)
        self.update()
    def disable_event(self):
        pass
    def close(self):
        self.destroy()

class WelcomeFrame(ctk.CTkFrame):
    def __init__(self, master, on_continue):
        super().__init__(master)
        self.pack(expand=True, fill='both')
        ctk.CTkLabel(self, text='Welcome to Secure-Gate',
                     font=('Segoe UI', 26, 'bold')).pack(pady=40)
        ctk.CTkLabel(self, text='Secure your files with palm gestures and AES encryption.',
                     font=('Segoe UI', 18)).pack(pady=10)
        ctk.CTkButton(self, text='Continue', command=on_continue, width=180,
                      font=('Segoe UI', 16)).pack(pady=40)

class SettingsFrame(ctk.CTkFrame):
    def __init__(self, master, on_back, theme_callback):
        super().__init__(master)
        self.pack(expand=True, fill='both')
        ctk.CTkLabel(self, text='Settings', font=('Segoe UI', 24, 'bold')).pack(pady=20)
        ctk.CTkLabel(self, text='Theme:', font=('Segoe UI', 16)).pack(pady=10)
        self.theme_var = ctk.StringVar(value=ctk.get_appearance_mode())
        theme_menu = ctk.CTkOptionMenu(self, variable=self.theme_var,
                                       values=['Light', 'Dark', 'System'], command=theme_callback)
        theme_menu.pack(pady=10)
        ctk.CTkButton(self, text='Back', command=on_back, width=120, font=('Segoe UI', 16)).pack(pady=30)

class MainFrame(ctk.CTkFrame):
    def __init__(self, master, log_panel, progress_callback, palm_reg_callback, settings_callback):
        super().__init__(master)
        self.pack(expand=True, fill='both')
        self.log_panel = log_panel
        self.progress_callback = progress_callback
        self.palm_reg_callback = palm_reg_callback
        self.settings_callback = settings_callback
        self.selected_folder = None
        self.selected_files = []
        self.create_widgets()

    def create_widgets(self):
        ctk.CTkLabel(self, text='Select Folder for Encryption/Decryption',
                     font=('Segoe UI', 20, 'bold')).pack(pady=10)

        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(pady=5)
        ctk.CTkButton(btn_frame, text='Browse Folder', command=self.browse_folder,
                      width=140, font=('Segoe UI', 16)).pack(side='left', padx=10)
        ctk.CTkButton(btn_frame, text='Clear Selection', command=self.clear_selection,
                      width=140, font=('Segoe UI', 16)).pack(side='left', padx=10)

        self.file_listbox = tk.Listbox(self, selectmode='extended', width=60, height=8, font=('Segoe UI', 12))
        self.file_listbox.pack(pady=10)

        action_frame = ctk.CTkFrame(self)
        action_frame.pack(pady=10)
        # a) Encrypt
        ctk.CTkButton(action_frame, text='Encrypt', command=self.encrypt_selected,
                      width=120, font=('Segoe UI', 16)).pack(side='left', padx=10)
        # b) Decrypt
        ctk.CTkButton(action_frame, text='Decrypt', command=self.decrypt_selected,
                      width=120, font=('Segoe UI', 16)).pack(side='left', padx=10)

        palm_frame = ctk.CTkFrame(self)
        palm_frame.pack(pady=10)
        # c) Reg_Right
        ctk.CTkButton(palm_frame, text='Reg_Right', command=partial(self.palm_reg_callback, 'right'),
                      width=120, font=('Segoe UI', 16)).pack(side='left', padx=10)
        # d) Reg_Left
        ctk.CTkButton(palm_frame, text='Reg_Left', command=partial(self.palm_reg_callback, 'left'),
                      width=120, font=('Segoe UI', 16)).pack(side='left', padx=10)
        # e) Settings
        ctk.CTkButton(palm_frame, text='Settings', command=self.settings_callback,
                      width=120, font=('Segoe UI', 16)).pack(side='left', padx=10)

    def browse_folder(self):
        folder = filedialog.askdirectory(title='Select Folder')
        if folder:
            self.selected_folder = folder
            self.selected_files = []
            self.file_listbox.delete(0, 'end')
            for root, _, files in os.walk(folder):
                for f in files:
                    path = os.path.join(root, f)
                    self.selected_files.append(path)
                    self.file_listbox.insert('end', path)
            self.log_panel.log(f"Added files from folder: {folder}", 'info')

    def clear_selection(self):
        self.selected_folder = None
        self.selected_files.clear()
        self.file_listbox.delete(0, 'end')
        self.log_panel.log("Selection cleared.", 'info')

    def encrypt_selected(self):
        if not self.selected_files:
            messagebox.showwarning('No Selection', 'Please select a folder to encrypt.')
            return
        self.progress_callback('encrypt', self.selected_files)

    def decrypt_selected(self):
        folder = self.selected_folder
        if not folder:
            messagebox.showwarning('No Folder', 'No folder selected for decryption.')
            return
        files = [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith('.enc')]
        if not files:
            messagebox.showwarning('No Encrypted Files', 'No encrypted files found in the selected folder.')
            return
        self.progress_callback('decrypt', files)

# === Decryption Support Functions ===

def derive_key(password):
    return PBKDF2(password, SALT, dkLen=32, count=100_000)

'''
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding.")
    return data[:-pad_len]
'''

def aes_encrypt_file(filepath, password, progress_cb=None):
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    out_path = filepath + '.enc'

    with open(filepath, 'rb') as f:
        data = f.read()

    padded = pad(data, AES.block_size)

    with open(out_path, 'wb') as f:
        f.write(iv + cipher.encrypt(padded))

    os.remove(filepath)
    return out_path


def aes_decrypt_file(filepath, password):
    key = derive_key(password)

    with open(filepath, 'rb') as f:
        iv = f.read(16)
        encrypted = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted)

    try:
        decrypted = unpad(decrypted_padded, AES.block_size)
    except ValueError:
        raise ValueError("Incorrect password or corrupted file.")

    out_path = filepath.replace('.enc', '')
    with open(out_path, 'wb') as f:
        f.write(decrypted)

    return out_path


def run_palm_registration(hand):
    script = REGISTER_LEFT_SCRIPT if hand == 'left' else REGISTER_RIGHT_SCRIPT
    subprocess.Popen([sys.executable, script])

# === Main App ===

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('Gesture-based Unlocking System')
        self.geometry('700x600')
        self.minsize(700, 600)
        self.center_window()

        self.log_panel = LogPanel(self)
        self.log_panel.pack(side='bottom', fill='x', padx=10, pady=5)
        self.current_frame = None
        self.show_welcome()

    def center_window(self):
        self.update_idletasks()
        w = 700
        h = 600
        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2) - 40  # offset from taskbar
        self.geometry(f'{w}x{h}+{x}+{max(y, 20)}')


    def show_welcome(self):
        self.clear_frame()
        self.current_frame = WelcomeFrame(self, self.show_main)

    def show_main(self):
        self.clear_frame()
        self.current_frame = MainFrame(self, self.log_panel, self.handle_action, self.handle_palm_registration, self.show_settings)

    def show_settings(self):
        self.clear_frame()
        self.current_frame = SettingsFrame(self, self.show_main, self.change_theme)

    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()

    def change_theme(self, theme):
        ctk.set_appearance_mode(theme)
        self.log_panel.log(f"Theme changed to {theme}.", 'info')

    def handle_action(self, action, files):
        if action == 'encrypt':
            self.ask_password_and_encrypt(files)
        elif action == 'decrypt':
            self.palm_decrypt(files)

    def ask_password_and_encrypt(self, files):
        pw_win = ctk.CTkInputDialog(text='Enter password for encryption:', title='Password')
        pw_win.lift()
        pw_win.focus_force()
        password = pw_win.get_input()
        if not password:
            self.log_panel.log('Encryption cancelled (no password).', 'error')
            return
        original_sizes = {f: os.path.getsize(f) for f in files}
        popup = ProgressPopup(self, 'Encrypting...', max_value=sum(original_sizes.values()))
        def encrypt_thread():
            total = 0
            for f in files:
                self.log_panel.log(f"Encrypting {f}...", 'info')
                def prog_cb(val):
                    nonlocal total
                    popup.update_progress(total + val, f"Encrypting {os.path.basename(f)}...")
                try:
                    aes_encrypt_file(f, password, progress_cb=prog_cb)
                    self.log_panel.log(f"Encrypted {f}.", 'success')
                except Exception as e:
                    self.log_panel.log(f"Encryption failed for {f}: {e}", 'error')
                total += original_sizes[f]
            popup.close()
        threading.Thread(target=encrypt_thread, daemon=True).start()

    def palm_decrypt(self, files):
        def start_decrypt(palm_type):
            popup = ProgressPopup(self, 'Decrypting...', max_value=len(files))
            def decrypt_thread():
                subprocess.run([sys.executable, PALM_DECRYPT_SCRIPT, palm_type] + files)
                popup.close()
            threading.Thread(target=decrypt_thread, daemon=True).start()
        dialog = ctk.CTkToplevel(self)
        dialog.title("Select Palm")
        dialog.geometry("300x150")
        dialog.lift()
        dialog.focus_force()
        ctk.CTkLabel(dialog, text="Choose which palm to use", font=("Segoe UI", 16)).pack(pady=20)
        btn_frame = ctk.CTkFrame(dialog)
        btn_frame.pack()
        ctk.CTkButton(btn_frame, text="Right", command=lambda: (dialog.destroy(), start_decrypt('right')), width=100).pack(side='left', padx=10)
        ctk.CTkButton(btn_frame, text="Left", command=lambda: (dialog.destroy(), start_decrypt('left')), width=100).pack(side='left', padx=10)

    def handle_palm_registration(self, hand):
        run_palm_registration(hand)

if __name__ == '__main__':
    ctk.set_appearance_mode('System')
    app = App()
    app.mainloop()