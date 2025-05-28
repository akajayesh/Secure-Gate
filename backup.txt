import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import sys
import subprocess
import time
import queue
from functools import partial


# --- AES ENCRYPTION/DECRYPTION ---
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import hashlib

# --- PALM/DECRYPTION SCRIPTS ---
# These are called as subprocesses when needed
REGISTER_LEFT_SCRIPT = 'register_left.py'
REGISTER_RIGHT_SCRIPT = 'register_right.py'
PALM_DECRYPT_SCRIPT = 'new_sol.py'  # Use this for palm-based decryption
FALLBACK_DECRYPT_SCRIPT = 'simple.py'  # Fallback only if palm fails

SALT = b'\x00\x01\x02\x03\x04\x05\x06\x07'  # Use a securely generated salt in production

# --- GUI CLASSES ---
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
        self.progress = ctk.CTkProgressBar(self, width=350)
        self.progress.pack(pady=30)
        self.progress.set(0)
        self.label = ctk.CTkLabel(self, text='Starting...')
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
        pass  # Prevent closing
    def close(self):
        self.destroy()

class WelcomeFrame(ctk.CTkFrame):
    def __init__(self, master, on_continue):
        super().__init__(master)
        self.pack(expand=True, fill='both')
        ctk.CTkLabel(self, text='Welcome to Gesture-based Unlocking System', font=('Arial', 24, 'bold')).pack(pady=40)
        ctk.CTkLabel(self, text='Secure your files with palm gestures and AES encryption.', font=('Arial', 16)).pack(pady=10)
        ctk.CTkButton(self, text='Continue', command=on_continue, width=180).pack(pady=40)

class SettingsFrame(ctk.CTkFrame):
    def __init__(self, master, on_back, theme_callback):
        super().__init__(master)
        self.pack(expand=True, fill='both')
        ctk.CTkLabel(self, text='Settings', font=('Arial', 22, 'bold')).pack(pady=20)
        ctk.CTkLabel(self, text='Theme:', font=('Arial', 16)).pack(pady=10)
        self.theme_var = ctk.StringVar(value=ctk.get_appearance_mode())
        theme_menu = ctk.CTkOptionMenu(self, variable=self.theme_var, values=['Light', 'Dark', 'System'], command=theme_callback)
        theme_menu.pack(pady=10)
        ctk.CTkButton(self, text='Back', command=on_back, width=120).pack(pady=30)

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
        ctk.CTkLabel(self, text='Select Folder for Encryption/Decryption', font=('Arial', 18, 'bold')).pack(pady=10)
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(pady=5)
        ctk.CTkButton(btn_frame, text='Browse Folder', command=self.browse_folder, width=120).pack(side='left', padx=5)
        ctk.CTkButton(btn_frame, text='Clear Selection', command=self.clear_selection, width=120).pack(side='left', padx=5)
        self.file_listbox = tk.Listbox(self, selectmode='extended', width=60, height=8)
        self.file_listbox.pack(pady=10)
        action_frame = ctk.CTkFrame(self)
        action_frame.pack(pady=10)
        ctk.CTkButton(action_frame, text='Encrypt Folder', command=self.encrypt_selected, width=140).pack(side='left', padx=10)
        ctk.CTkButton(action_frame, text='Decrypt Folder', command=self.decrypt_selected, width=140).pack(side='left', padx=10)
        ctk.CTkButton(action_frame, text='Settings', command=self.settings_callback, width=120).pack(side='left', padx=10)
        palm_frame = ctk.CTkFrame(self)
        palm_frame.pack(pady=10)
        ctk.CTkButton(palm_frame, text='Register Left Palm', command=partial(self.palm_reg_callback, 'left'), width=140).pack(side='left', padx=10)
        ctk.CTkButton(palm_frame, text='Register Right Palm', command=partial(self.palm_reg_callback, 'right'), width=140).pack(side='left', padx=10)
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


class PalmTypeDialog(ctk.CTkToplevel):
    def __init__(self, master, callback):
        super().__init__(master)
        self.title('Select Palm Type')
        self.geometry('300x150')
        self.resizable(False, False)
        self.callback = callback
        ctk.CTkLabel(self, text='Which palm do you want to use?', font=('Arial', 16)).pack(pady=20)
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text='Right Palm', command=lambda: self.select('right'), width=100).pack(side='left', padx=10)
        ctk.CTkButton(btn_frame, text='Left Palm', command=lambda: self.select('left'), width=100).pack(side='left', padx=10)
    def select(self, palm_type):
        self.callback(palm_type)
        self.destroy()

# --- ENCRYPTION/DECRYPTION LOGIC ---
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]
def derive_key(password):
    return PBKDF2(password, SALT, dkLen=32, count=100_000)
# --- ENCRYPTION/DECRYPTION LOGIC ---
def aes_encrypt_file(filepath, password, progress_cb=None):
    key = derive_key(password)
    out_path = filepath + '.enc'
    cipher = AES.new(key, AES.MODE_CBC)
    filesize = os.path.getsize(filepath)

    with open(filepath, 'rb') as f_in, open(out_path, 'wb') as f_out:
        f_out.write(cipher.iv)
        total = 0
        while True:
            chunk = f_in.read(4096)
            if not chunk:
                break
            if len(chunk) % 16 != 0:
                chunk = pad(chunk)
            enc_chunk = cipher.encrypt(chunk)
            f_out.write(enc_chunk)
            total += len(chunk)
            if progress_cb:
                progress_cb(total)

    os.remove(filepath)  # Remove original file
    return out_path

def aes_decrypt_file(filepath, password, progress_cb=None):
    key = derive_key(password)
    out_path = filepath.replace('.enc', '.dec')
    with open(filepath, 'rb') as f_in:
        iv = f_in.read(16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        filesize = os.path.getsize(filepath) - 16
        with open(out_path, 'wb') as f_out:
            total = 0
            while True:
                chunk = f_in.read(4096)
                if not chunk:
                    break
                dec_chunk = cipher.decrypt(chunk)
                if f_in.tell() == os.path.getsize(filepath):
                    dec_chunk = unpad(dec_chunk)
                f_out.write(dec_chunk)
                total += len(chunk)
                if progress_cb:
                    progress_cb(total)
    # Overwrite original file with decrypted file
    os.replace(out_path, filepath.replace('.enc', ''))
    return filepath.replace('.enc', '')

# --- PALM DECRYPTION LOGIC ---
# --- PALM REGISTRATION/DECRYPTION ---
def run_palm_registration(hand):
    script = REGISTER_LEFT_SCRIPT if hand == 'left' else REGISTER_RIGHT_SCRIPT
    subprocess.Popen([sys.executable, script])
    

def run_palm_decryption(files, log_panel, progress_popup, palm_type):
    try:
        # Attempt to decrypt all files in one go if the script supports it
        log_panel.log("Attempting palm-based decryption for all files...", 'info')
        result = subprocess.run([sys.executable, PALM_DECRYPT_SCRIPT, palm_type] + files, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            log_panel.log("Palm-based decryption succeeded for all files.", 'success')
        else:
            log_panel.log("Palm-based decryption failed for some files. Fallback to password.", 'error')
            run_fallback_decryption(files, log_panel, progress_popup)
        progress_popup.update_progress(len(files), "Processed all files")
    except Exception as e:
        log_panel.log(f"Palm-based decryption error: {e}", 'error')
        run_fallback_decryption(files, log_panel, progress_popup)


def run_fallback_decryption(files, log_panel, progress_popup):
    # Fallback to password-based decryption
    for f in files:
        log_panel.log(f"Fallback: password-based decryption for {f}...", 'info')
        try:
            result = subprocess.run([sys.executable, FALLBACK_DECRYPT_SCRIPT, f], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                log_panel.log(f"Fallback decryption succeeded for {f}.", 'success')
            else:
                log_panel.log(f"Fallback decryption failed for {f}.", 'error')
                messagebox.showerror('Decryption Failed', f"Failed to decrypt {os.path.basename(f)}.")
        except Exception as e:
            log_panel.log(f"Error during fallback decryption for {f}: {e}", 'error')
            messagebox.showerror('Decryption Error', f"An error occurred: {e}")

# --- MAIN APP ---
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
        w = self.winfo_width()
        h = self.winfo_height()
        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2)
        self.geometry(f'+{x}+{y}')
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
                run_palm_decryption(files, self.log_panel, popup, palm_type)
                popup.close()
            threading.Thread(target=decrypt_thread, daemon=True).start()
        PalmTypeDialog(self, start_decrypt)
    def handle_palm_registration(self, hand):
        run_palm_registration(hand)

if __name__ == '__main__':
    ctk.set_appearance_mode('System')
    app = App()
    app.mainloop()