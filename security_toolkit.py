"""
Security Toolkit - A Beautiful Tkinter Application for Cryptographic Algorithms
Integrates RSA, DES Key Generation, and S-DES Encryption/Decryption
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
import struct
import math


def is_prime(n):
    """Check if a number is prime"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    # Check odd divisors up to sqrt(n)
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


class SecurityToolkit:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Security Toolkit")
        self.root.geometry("900x700")
        self.root.configure(bg="#0a0e27")
        
        # Generate RSA keys at startup
        self.rsa_n, self.rsa_e, self.rsa_d = self.generate_rsa_keys(bit_length=10)
        
        # Configure custom style
        self.setup_styles()
        
        # Create header
        self.create_header()
        
        # Create notebook (tabbed interface)
        self.create_notebook()
        
        # Create status bar
        self.create_status_bar()
        
    def setup_styles(self):
        """Configure custom ttk styles for security theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure notebook
        style.configure('TNotebook', background='#0a0e27', borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background='#16213e', 
                       foreground='#00d4ff',
                       padding=[20, 10],
                       font=('Consolas', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', '#1a1a2e')],
                 foreground=[('selected', '#0f0')])
        
        # Configure frames
        style.configure('Dark.TFrame', background='#0a0e27')
        style.configure('Card.TFrame', background='#16213e', relief='raised')
        
        # Configure labels
        style.configure('Title.TLabel', 
                       background='#0a0e27',
                       foreground='#0f0',
                       font=('Consolas', 16, 'bold'))
        style.configure('Header.TLabel',
                       background='#16213e',
                       foreground='#00d4ff',
                       font=('Consolas', 11, 'bold'))
        style.configure('Info.TLabel',
                       background='#16213e',
                       foreground='#e0e0e0',
                       font=('Consolas', 9))
        
        # Configure buttons
        style.configure('Action.TButton',
                       background='#0f0',
                       foreground='#000',
                       font=('Consolas', 10, 'bold'),
                       padding=[10, 5])
        style.map('Action.TButton',
                 background=[('active', '#00ff00'), ('pressed', '#00cc00')])
        
        style.configure('Secondary.TButton',
                       background='#00d4ff',
                       foreground='#000',
                       font=('Consolas', 9),
                       padding=[8, 4])
        style.map('Secondary.TButton',
                 background=[('active', '#00e5ff'), ('pressed', '#00b0cc')])
    
    def create_header(self):
        """Create application header"""
        header_frame = ttk.Frame(self.root, style='Dark.TFrame', height=80)
        header_frame.pack(fill='x', padx=10, pady=10)
        header_frame.pack_propagate(False)
        
        title = ttk.Label(header_frame, 
                         text="🔐 SECURITY TOOLKIT",
                         style='Title.TLabel')
        title.pack(pady=15)
        
        subtitle = tk.Label(header_frame,
                           text="RSA • DES • S-DES Cryptographic Algorithms",
                           bg='#0a0e27',
                           fg='#888',
                           font=('Consolas', 9))
        subtitle.pack()
    
    def create_notebook(self):
        """Create tabbed interface"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Create tabs
        self.create_rsa_tab()
        self.create_des_tab()
        self.create_sdes_tab()
        self.create_md5_tab()
        self.create_sha1_tab()
        self.create_full_md5_tab()
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root,
                             textvariable=self.status_var,
                             bg='#16213e',
                             fg='#0f0',
                             font=('Consolas', 9),
                             anchor='w',
                             padx=10,
                             pady=5)
        status_bar.pack(side='bottom', fill='x')
    
    def set_status(self, message):
        """Update status bar message"""
        self.status_var.set(f"⚡ {message}")
        self.root.after(3000, lambda: self.status_var.set("Ready"))
    
    # ==================== RSA TAB ====================
    
    def create_rsa_tab(self):
        """Create RSA encryption/decryption tab"""
        rsa_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(rsa_frame, text='🔑 RSA')
        
        # Key information frame
        key_frame = ttk.Frame(rsa_frame, style='Card.TFrame')
        key_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(key_frame, text="RSA Key Information", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        self.rsa_key_info = tk.Text(key_frame, height=3, width=60, 
                                    bg='#0a0e27', fg='#00d4ff',
                                    font=('Consolas', 9),
                                    relief='flat', padx=10, pady=5)
        self.rsa_key_info.pack(padx=10, pady=(0, 5))
        self.update_rsa_key_display()
        
        btn_frame = ttk.Frame(key_frame, style='Card.TFrame')
        btn_frame.pack(pady=(0, 10))
        
        ttk.Button(btn_frame, text="🔄 Regenerate Keys", 
                  style='Secondary.TButton',
                  command=self.regenerate_rsa_keys).pack(side='left', padx=5)
        
        # Message input
        input_frame = ttk.Frame(rsa_frame, style='Card.TFrame')
        input_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(input_frame, text="Plaintext Message", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        self.rsa_plaintext = scrolledtext.ScrolledText(input_frame, height=4, width=60,
                                                       bg='#0a0e27', fg='#0f0',
                                                       font=('Consolas', 10),
                                                       relief='flat', padx=10, pady=5,
                                                       insertbackground='#0f0')
        self.rsa_plaintext.pack(padx=10, pady=(0, 10))
        
        # Encrypted output
        ttk.Label(input_frame, text="Encrypted Ciphertext", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        cipher_container = ttk.Frame(input_frame, style='Card.TFrame')
        cipher_container.pack(fill='x', padx=10)
        
        self.rsa_ciphertext = scrolledtext.ScrolledText(cipher_container, height=4, width=50,
                                                        bg='#0a0e27', fg='#ff6b6b',
                                                        font=('Consolas', 9),
                                                        relief='flat', padx=10, pady=5,
                                                        state='disabled')
        self.rsa_ciphertext.pack(side='left', fill='both', expand=True)
        
        ttk.Button(cipher_container, text="📋", 
                  style='Secondary.TButton',
                  command=lambda: self.copy_to_clipboard(self.rsa_ciphertext)).pack(side='left', padx=(5, 0))
        
        # Decrypted output
        ttk.Label(input_frame, text="Decrypted Message", style='Header.TLabel').pack(anchor='w', padx=10, pady=(15, 5))
        
        decrypt_container = ttk.Frame(input_frame, style='Card.TFrame')
        decrypt_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.rsa_decrypted = scrolledtext.ScrolledText(decrypt_container, height=4, width=50,
                                                       bg='#0a0e27', fg='#0f0',
                                                       font=('Consolas', 10),
                                                       relief='flat', padx=10, pady=5,
                                                       state='disabled')
        self.rsa_decrypted.pack(side='left', fill='both', expand=True)
        
        ttk.Button(decrypt_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_to_clipboard(self.rsa_decrypted)).pack(side='left', padx=(5, 0))
        
        # Action buttons
        action_frame = ttk.Frame(input_frame, style='Card.TFrame')
        action_frame.pack(pady=(5, 10))
        
        ttk.Button(action_frame, text="🔒 ENCRYPT", 
                  style='Action.TButton',
                  command=self.rsa_encrypt).pack(side='left', padx=5)
        
        ttk.Button(action_frame, text="🔓 DECRYPT",
                  style='Action.TButton',
                  command=self.rsa_decrypt).pack(side='left', padx=5)
    
    # RSA Algorithm Functions
    def generate_prime(self, bits):
        """Generate a prime number with given bit length"""
        while True:
            num = random.getrandbits(bits)
            if is_prime(num):
                return num
    
    def gcd(self, a, b):
        """Calculate greatest common divisor"""
        while b:
            a, b = b, a % b
        return a
    
    def generate_rsa_keys(self, bit_length=10):
        """Generate RSA key pair"""
        p = self.generate_prime(bit_length)
        q = self.generate_prime(bit_length)
        n = p * q
        euler = (p - 1) * (q - 1)
        
        e = random.randrange(2, euler)
        while self.gcd(e, euler) != 1:
            e = random.randrange(2, euler)
        
        for i in range(1, euler):
            if (i * e) % euler == 1:
                d = i
                break
        
        return n, e, d
    
    def update_rsa_key_display(self):
        """Update RSA key information display"""
        self.rsa_key_info.config(state='normal')
        self.rsa_key_info.delete('1.0', 'end')
        self.rsa_key_info.insert('1.0', 
            f"Public Key (n, e):  n = {self.rsa_n}, e = {self.rsa_e}\n"
            f"Private Key (d):    d = {self.rsa_d}\n"
            f"Key Strength:       {self.rsa_n.bit_length()} bits")
        self.rsa_key_info.config(state='disabled')
    
    def regenerate_rsa_keys(self):
        """Regenerate RSA keys"""
        self.rsa_n, self.rsa_e, self.rsa_d = self.generate_rsa_keys(bit_length=10)
        self.update_rsa_key_display()
        self.set_status("New RSA keys generated successfully")
    
    def rsa_encrypt(self):
        """Encrypt message using RSA"""
        message = self.rsa_plaintext.get('1.0', 'end-1c')
        
        if not message:
            messagebox.showwarning("Input Error", "Please enter a message to encrypt!")
            return
        
        try:
            # Convert message to ASCII numbers
            message_ascii = [ord(ch) for ch in message]
            
            # Encrypt each character
            cipher = [(m ** self.rsa_e) % self.rsa_n for m in message_ascii]
            
            # Display encrypted message
            self.rsa_ciphertext.config(state='normal')
            self.rsa_ciphertext.delete('1.0', 'end')
            self.rsa_ciphertext.insert('1.0', str(cipher))
            self.rsa_ciphertext.config(state='disabled')
            
            # Clear decrypted text
            self.rsa_decrypted.config(state='normal')
            self.rsa_decrypted.delete('1.0', 'end')
            self.rsa_decrypted.config(state='disabled')
            
            self.set_status("Message encrypted successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Encryption failed: {str(ex)}")
    
    def rsa_decrypt(self):
        """Decrypt message using RSA"""
        cipher_text = self.rsa_ciphertext.get('1.0', 'end-1c').strip()
        
        if not cipher_text:
            messagebox.showwarning("Input Error", "No encrypted message to decrypt!")
            return
        
        try:
            # Convert string representation of list back to list
            cipher = eval(cipher_text)
            
            # Decrypt each character
            decrypted = [(c ** self.rsa_d) % self.rsa_n for c in cipher]
            decrypted_text = ''.join(chr(num) for num in decrypted)
            
            # Display decrypted message
            self.rsa_decrypted.config(state='normal')
            self.rsa_decrypted.delete('1.0', 'end')
            self.rsa_decrypted.insert('1.0', decrypted_text)
            self.rsa_decrypted.config(state='disabled')
            
            self.set_status("Message decrypted successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Decryption failed: {str(ex)}")
    
    # ==================== DES TAB ====================
    
    def create_des_tab(self):
        """Create DES 16-round key generation tab"""
        des_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(des_frame, text='🔐 DES')
        
        # Input frame
        input_frame = ttk.Frame(des_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="DES Key Generator (16 Rounds)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        ttk.Label(input_frame, text="Enter 16-character hexadecimal key (0-9, A-F):", 
                 style='Info.TLabel').pack(anchor='w', padx=10, pady=(5, 5))
        
        key_input_frame = ttk.Frame(input_frame, style='Card.TFrame')
        key_input_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        self.des_key_entry = tk.Entry(key_input_frame, 
                                      bg='#0a0e27', fg='#0f0',
                                      font=('Consolas', 12, 'bold'),
                                      insertbackground='#0f0',
                                      relief='flat',
                                      width=40)
        self.des_key_entry.pack(side='left', padx=(0, 10), pady=5, ipady=5)
        self.des_key_entry.insert(0, "133457799BBCDFF1")
        
        ttk.Button(key_input_frame, text="🔑 Generate Keys",
                  style='Action.TButton',
                  command=self.generate_des_keys).pack(side='left')
        
        # Output frame
        output_frame = ttk.Frame(des_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(output_frame, text="Generated Round Keys", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        self.des_output = scrolledtext.ScrolledText(output_frame, 
                                                    bg='#0a0e27', fg='#00d4ff',
                                                    font=('Consolas', 9),
                                                    relief='flat', padx=15, pady=10,
                                                    state='disabled')
        self.des_output.pack(fill='both', expand=True, padx=10, pady=(0, 10))
    
    # DES Algorithm Functions
    def left_shift(self, bits, n):
        """Perform circular left shift"""
        return bits[n:] + bits[:n]
    
    def generate_des_keys(self):
        """Generate 16 round keys for DES"""
        hex_key = self.des_key_entry.get().strip()
        
        # Validate input
        if len(hex_key) != 16 or any(c not in "0123456789abcdefABCDEF" for c in hex_key):
            messagebox.showerror("Invalid Input", 
                               "Please enter exactly 16 hexadecimal characters (0-9, A-F)!")
            return
        
        try:
            # Convert hex to binary (64-bit)
            bin_key = bin(int(hex_key, 16))[2:].zfill(64)
            
            # PC-1 Table
            PC1 = [
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
            ]
            
            # PC-2 Table
            PC2 = [
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
            ]
            
            # Apply PC-1
            perm_key = "".join([bin_key[i - 1] for i in PC1])
            
            # Split into halves
            L = perm_key[:28]
            R = perm_key[28:]
            
            # Number of left shifts per round
            ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
            
            # Generate output text
            output_text = f"Hexadecimal Key: {hex_key}\n"
            output_text += f"Binary Key (64-bit):\n{bin_key}\n\n"
            output_text += f"After PC-1 (56-bit):\n{perm_key}\n\n"
            output_text += f"Initial L0: {L}\n"
            output_text += f"Initial R0: {R}\n\n"
            output_text += "=" * 70 + "\n"
            output_text += "16 ROUND KEYS\n"
            output_text += "=" * 70 + "\n\n"
            
            # Generate 16 subkeys
            for i in range(16):
                L = self.left_shift(L, ROTATIONS[i])
                R = self.left_shift(R, ROTATIONS[i])
                combined = L + R
                subkey = "".join([combined[j - 1] for j in PC2])
                output_text += f"Round {i+1:2d} Key: {subkey}\n"
            
            # Display output
            self.des_output.config(state='normal')
            self.des_output.delete('1.0', 'end')
            self.des_output.insert('1.0', output_text)
            self.des_output.config(state='disabled')
            
            self.set_status("DES round keys generated successfully")
            
        except Exception as ex:
            messagebox.showerror("Error", f"Key generation failed: {str(ex)}")
    
    # ==================== S-DES TAB ====================
    
    def create_sdes_tab(self):
        """Create S-DES encryption/decryption tab"""
        sdes_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(sdes_frame, text='🔒 S-DES')
        
        # Input frame
        input_frame = ttk.Frame(sdes_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="Simplified DES (S-DES)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        # Key input
        ttk.Label(input_frame, text="10-bit Key:", style='Info.TLabel').pack(anchor='w', padx=10, pady=(10, 2))
        self.sdes_key_entry = tk.Entry(input_frame,
                                       bg='#0a0e27', fg='#0f0',
                                       font=('Consolas', 11),
                                       insertbackground='#0f0',
                                       relief='flat', width=30)
        self.sdes_key_entry.pack(anchor='w', padx=10, pady=(0, 5), ipady=3)
        self.sdes_key_entry.insert(0, "1010000010")
        
        # Plaintext input
        ttk.Label(input_frame, text="8-bit Plaintext:", style='Info.TLabel').pack(anchor='w', padx=10, pady=(10, 2))
        self.sdes_plain_entry = tk.Entry(input_frame,
                                         bg='#0a0e27', fg='#0f0',
                                         font=('Consolas', 11),
                                         insertbackground='#0f0',
                                         relief='flat', width=30)
        self.sdes_plain_entry.pack(anchor='w', padx=10, pady=(0, 10), ipady=3)
        self.sdes_plain_entry.insert(0, "10100010")
        
        # Generated keys display
        ttk.Label(input_frame, text="Generated Subkeys:", style='Info.TLabel').pack(anchor='w', padx=10, pady=(5, 2))
        self.sdes_subkeys = tk.Text(input_frame, height=2, width=40,
                                    bg='#0a0e27', fg='#00d4ff',
                                    font=('Consolas', 9),
                                    relief='flat', padx=5, pady=5,
                                    state='disabled')
        self.sdes_subkeys.pack(anchor='w', padx=10, pady=(0, 10))
        
        ttk.Button(input_frame, text="🔑 Generate Subkeys",
                  style='Secondary.TButton',
                  command=self.sdes_generate_keys).pack(anchor='w', padx=10, pady=(0, 10))
        
        # Output frame
        output_frame = ttk.Frame(sdes_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(output_frame, text="Results", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        # Ciphertext
        result_container = ttk.Frame(output_frame, style='Card.TFrame')
        result_container.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(result_container, text="Ciphertext:", style='Info.TLabel').pack(side='left', padx=(0, 10))
        self.sdes_cipher_label = tk.Label(result_container,
                                         bg='#0a0e27', fg='#ff6b6b',
                                         font=('Consolas', 12, 'bold'),
                                         width=15, anchor='w',
                                         padx=10, pady=5)
        self.sdes_cipher_label.pack(side='left', fill='x', expand=True)
        
        ttk.Button(result_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_text(self.sdes_cipher_label.cget('text'))).pack(side='left', padx=5)
        
        # Decrypted text
        decrypt_container = ttk.Frame(output_frame, style='Card.TFrame')
        decrypt_container.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(decrypt_container, text="Decrypted:", style='Info.TLabel').pack(side='left', padx=(0, 10))
        self.sdes_decrypt_label = tk.Label(decrypt_container,
                                          bg='#0a0e27', fg='#0f0',
                                          font=('Consolas', 12, 'bold'),
                                          width=15, anchor='w',
                                          padx=10, pady=5)
        self.sdes_decrypt_label.pack(side='left', fill='x', expand=True)
        
        ttk.Button(decrypt_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_text(self.sdes_decrypt_label.cget('text'))).pack(side='left', padx=5)
        
        # Action buttons
        action_frame = ttk.Frame(output_frame, style='Card.TFrame')
        action_frame.pack(pady=15)
        
        ttk.Button(action_frame, text="🔒 ENCRYPT",
                  style='Action.TButton',
                  command=self.sdes_encrypt).pack(side='left', padx=5)
        
        ttk.Button(action_frame, text="🔓 DECRYPT",
                  style='Action.TButton',
                  command=self.sdes_decrypt).pack(side='left', padx=5)
    
    # S-DES Algorithm Functions
    def sdes_permute(self, bits, pattern):
        """Rearrange bits according to a pattern"""
        return ''.join(bits[i - 1] for i in pattern)
    
    def sdes_key_generation(self, key):
        """Generate K1 and K2 for S-DES"""
        P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        P8 = [6, 3, 7, 4, 8, 5, 10, 9]
        
        key = self.sdes_permute(key, P10)
        left, right = key[:5], key[5:]
        
        # Left shift by 1
        left = self.left_shift(left, 1)
        right = self.left_shift(right, 1)
        K1 = self.sdes_permute(left + right, P8)
        
        # Left shift by 2 more
        left = self.left_shift(left, 2)
        right = self.left_shift(right, 2)
        K2 = self.sdes_permute(left + right, P8)
        
        return K1, K2
    
    def sdes_fk(self, bits, key):
        """S-DES fk function"""
        EP = [4, 1, 2, 3, 2, 3, 4, 1]
        S0 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 3, 2]
        ]
        S1 = [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ]
        
        left, right = bits[:4], bits[4:]
        
        # Expand and permute
        right_expanded = self.sdes_permute(right, EP)
        
        # XOR with key
        xor_result = ''.join(str(int(a) ^ int(b)) for a, b in zip(right_expanded, key))
        
        # Split for S-boxes
        left_xor, right_xor = xor_result[:4], xor_result[4:]
        
        # S-box lookup
        def sbox_lookup(bits, sbox):
            row = int(bits[0] + bits[3], 2)
            col = int(bits[1] + bits[2], 2)
            return format(sbox[row][col], '02b')
        
        sbox_output = sbox_lookup(left_xor, S0) + sbox_lookup(right_xor, S1)
        
        # XOR with left half and right half
        left_result = ''.join(str(int(a) ^ int(b) ^ int(c)) for a, b, c in zip(left, sbox_output, right))
        
        return left_result + right
    
    def sdes_encrypt_text(self, plaintext, key):
        """Encrypt using S-DES"""
        IP = [2, 6, 3, 1, 4, 8, 5, 7]
        IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
        
        K1, K2 = self.sdes_key_generation(key)
        
        bits = self.sdes_permute(plaintext, IP)
        bits = self.sdes_fk(bits, K1)
        bits = bits[4:] + bits[:4]  # Swap halves
        bits = self.sdes_fk(bits, K2)
        ciphertext = self.sdes_permute(bits, IP_inv)
        
        return ciphertext
    
    def sdes_decrypt_text(self, ciphertext, key):
        """Decrypt using S-DES"""
        IP = [2, 6, 3, 1, 4, 8, 5, 7]
        IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
        
        K1, K2 = self.sdes_key_generation(key)
        
        bits = self.sdes_permute(ciphertext, IP)
        bits = self.sdes_fk(bits, K2)
        bits = bits[4:] + bits[:4]  # Swap halves
        bits = self.sdes_fk(bits, K1)
        plaintext = self.sdes_permute(bits, IP_inv)
        
        return plaintext
    
    def sdes_generate_keys(self):
        """Generate and display S-DES subkeys"""
        key = self.sdes_key_entry.get().strip()
        
        if len(key) != 10 or any(c not in '01' for c in key):
            messagebox.showerror("Invalid Input", "Please enter exactly 10 binary digits (0 or 1)!")
            return
        
        try:
            K1, K2 = self.sdes_key_generation(key)
            
            self.sdes_subkeys.config(state='normal')
            self.sdes_subkeys.delete('1.0', 'end')
            self.sdes_subkeys.insert('1.0', f"K1: {K1}\nK2: {K2}")
            self.sdes_subkeys.config(state='disabled')
            
            self.set_status("S-DES subkeys generated")
        except Exception as ex:
            messagebox.showerror("Error", f"Key generation failed: {str(ex)}")
    
    def sdes_encrypt(self):
        """Encrypt plaintext using S-DES"""
        key = self.sdes_key_entry.get().strip()
        plaintext = self.sdes_plain_entry.get().strip()
        
        if len(key) != 10 or any(c not in '01' for c in key):
            messagebox.showerror("Invalid Input", "Key must be 10 binary digits!")
            return
        
        if len(plaintext) != 8 or any(c not in '01' for c in plaintext):
            messagebox.showerror("Invalid Input", "Plaintext must be 8 binary digits!")
            return
        
        try:
            ciphertext = self.sdes_encrypt_text(plaintext, key)
            self.sdes_cipher_label.config(text=ciphertext)
            self.sdes_decrypt_label.config(text="")
            self.set_status("S-DES encryption successful")
        except Exception as ex:
            messagebox.showerror("Error", f"Encryption failed: {str(ex)}")
    
    def sdes_decrypt(self):
        """Decrypt ciphertext using S-DES"""
        key = self.sdes_key_entry.get().strip()
        ciphertext = self.sdes_cipher_label.cget('text').strip()
        
        if not ciphertext:
            messagebox.showwarning("No Ciphertext", "Please encrypt a message first!")
            return
        
        if len(key) != 10 or any(c not in '01' for c in key):
            messagebox.showerror("Invalid Input", "Key must be 10 binary digits!")
            return
        
        try:
            plaintext = self.sdes_decrypt_text(ciphertext, key)
            self.sdes_decrypt_label.config(text=plaintext)
            self.set_status("S-DES decryption successful")
        except Exception as ex:
            messagebox.showerror("Error", f"Decryption failed: {str(ex)}")
    
    # ==================== MD5 FIRST ROUND TAB ====================
    
    def create_md5_tab(self):
        """Create MD5 First Round visualization tab"""
        md5_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(md5_frame, text='🛡️ MD5')
        
        # Input frame
        input_frame = ttk.Frame(md5_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="MD5 First Round Visualization", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        ttk.Label(input_frame, text="Enter Text to Hash:", style='Info.TLabel').pack(anchor='w', padx=10, pady=(5, 5))
        
        input_container = ttk.Frame(input_frame, style='Card.TFrame')
        input_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.md5_entry = tk.Entry(input_container, 
                                bg='#0a0e27', fg='#0f0',
                                font=('Consolas', 11),
                                insertbackground='#0f0',
                                relief='flat', width=40)
        self.md5_entry.pack(side='left', padx=(0, 10), pady=5, ipady=5, fill='x', expand=True)
        self.md5_entry.insert(0, "security")
        
        ttk.Button(input_container, text="⚡ Run Round 1",
                  style='Action.TButton',
                  command=self.run_md5_round1).pack(side='left')

        # Info Frame
        self.md5_info_label = tk.Label(input_frame, text="", 
                                     bg='#16213e', fg='#00d4ff',
                                     font=('Consolas', 9), justify='left')
        self.md5_info_label.pack(anchor='w', padx=10, pady=(0, 10))
        
        # Log Output frame
        output_frame = ttk.Frame(md5_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(output_frame, text="Round 1 Steps Log (16 Operations)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        self.md5_log = scrolledtext.ScrolledText(output_frame, 
                                                bg='#0a0e27', fg='#0f0',
                                                font=('Consolas', 9),
                                                relief='flat', padx=15, pady=10,
                                                state='disabled')
        self.md5_log.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
    def run_md5_round1(self):
        """Execute MD5 First Round logic"""
        text = self.md5_entry.get()
        if not text:
            messagebox.showwarning("Input Error", "Please enter text to hash!")
            return
            
        try:
            # 1. Padding Logic (from provided code)
            msg_bytes = bytearray(text.encode('utf-8'))
            msg_len_bits = len(msg_bytes) * 8
            import math
            blocks = math.floor(msg_len_bits / 512)
            len_block = msg_len_bits - (blocks * 512)
            if len_block < 448:
                pad_len = 512 - (len_block + 64)
            else:
                pad_len = (512 - (len_block + 64)) + 512
            
            total_len_bits = msg_len_bits + pad_len + 64
            
            info_text = (f"Original Length: {len(text)} chars ({msg_len_bits} bits)\n"
                         f"Padding Added:   {pad_len} bits\n"
                         f"Total Length:    {total_len_bits} bits (Multiple of 512)")
            self.md5_info_label.config(text=info_text)
            
            # 2. Initialize State
            a = 0x67452301
            b = 0xefcdab89
            c = 0x98badcfe
            d = 0x10325476
            
            # Constants
            s1 = [7, 12, 17, 22]
            t = [
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
            ]
            
            log_text = f"Initial State:\n  A: {a:08x}\n  B: {b:08x}\n  C: {c:08x}\n  D: {d:08x}\n\n"
            log_text += "=" * 60 + "\n"
            
            # 3. Simulate Round 1 (16 operations)
            # In a real MD5, we'd process 512-bit blocks. Here we simulate the first block's first round.
            # We need 'M' (message block). For demo, strictly padding isn't fully constructed in the user code, 
            # so we'll mock the M[0]...M[15] as part of the visualizer or just use 0 if not enough data, 
            # but to be accurate we should construct the block.
            
            # Construct the padded block (simplified for demonstration of Round 1 on the first block)
            # Append '1' bit (0x80 byte)
            msg_bytes.append(0x80)
            while (len(msg_bytes) * 8) % 512 != 448:
                msg_bytes.append(0)
            
            # Append length (64 bits, little endian)
            msg_bytes += (msg_len_bits).to_bytes(8, byteorder='little')
            
            # Extract first 16 words (32-bit blocks)
            M = []
            for i in range(16):
                val = int.from_bytes(msg_bytes[i*4:(i+1)*4], byteorder='little')
                M.append(val)
                
            # Round 1 Loop
            for i in range(16):
                # Save old state for display (optional, but we show result after)
                
                # F function
                f = (b & c) | (~b & d)
                
                # Operation: a = b + ((a + F(b,c,d) + M[k] + T[i]) <<< s)
                temp = (a + f + M[i] + t[i]) & 0xFFFFFFFF
                shift = s1[i % 4]
                rotated = ((temp << shift) | (temp >> (32 - shift))) & 0xFFFFFFFF
                new_b = (b + rotated) & 0xFFFFFFFF
                
                # Rotate variables
                a, b, c, d = d, new_b, b, c
                
                log_text += f"Step {i+1:02d}:\n"
                log_text += f"  Function F result: {f:08x}\n"
                log_text += f"  M[{i}]:            {M[i]:08x}\n"
                log_text += f"  Shift:            {shift}\n"
                log_text += f"  New State -> A:{a:08x} B:{b:08x} C:{c:08x} D:{d:08x}\n"
                log_text += "-" * 40 + "\n"
                
            self.md5_log.config(state='normal')
            self.md5_log.delete('1.0', 'end')
            self.md5_log.insert('1.0', log_text)
            self.md5_log.config(state='disabled')
            
            self.set_status("MD5 Round 1 simulated successfully")

        except Exception as ex:
            messagebox.showerror("Error", f"MD5 execution failed: {str(ex)}")

    # ==================== SHA-1 TAB ====================
    
    def create_sha1_tab(self):
        """Create SHA-1 Hash tab"""
        sha1_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(sha1_frame, text='🛡️ SHA-1')
        
        # Input frame
        input_frame = ttk.Frame(sha1_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="SHA-1 Secure Hash Algorithm", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        ttk.Label(input_frame, text="Enter Text to Hash:", style='Info.TLabel').pack(anchor='w', padx=10, pady=(5, 5))
        
        input_container = ttk.Frame(input_frame, style='Card.TFrame')
        input_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.sha1_entry = tk.Entry(input_container, 
                                 bg='#0a0e27', fg='#0f0',
                                 font=('Consolas', 11),
                                 insertbackground='#0f0',
                                 relief='flat', width=40)
        self.sha1_entry.pack(side='left', padx=(0, 10), pady=5, ipady=5, fill='x', expand=True)
        
        ttk.Button(input_container, text="⚡ Calculate Hash",
                  style='Action.TButton',
                  command=self.run_sha1).pack(side='left')

        # Output frame
        output_frame = ttk.Frame(sha1_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(output_frame, text="SHA-1 Digest (160-bit)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        result_container = ttk.Frame(output_frame, style='Card.TFrame')
        result_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.sha1_result = tk.Label(result_container,
                                  bg='#0a0e27', fg='#00d4ff',
                                  font=('Consolas', 12, 'bold'),
                                  anchor='w', padx=10, pady=10)
        self.sha1_result.pack(side='left', fill='x', expand=True)
        
        ttk.Button(result_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_text(self.sha1_result.cget('text'))).pack(side='left', padx=5)

    def left_rotate(self, n, b):
        """Left rotate n by b bits."""
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    def sha1_hash(self, message):
        """Implementation of SHA-1 algorithm"""
        # Step 1: Convert message to bytes
        if isinstance(message, str):
            data = bytearray(message, 'utf-8')
        else:
            data = bytearray(message)
        
        orig_len_bits = len(data) * 8
        
        # Step 2: Append padding
        data.append(0x80)
        while (len(data) * 8) % 512 != 448:
            data.append(0x00)
        
        # Step 3: Append original length (64 bits, big-endian)
        data += struct.pack('>Q', orig_len_bits)
        
        # Step 4: Initialize buffers
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0
        
        # Step 5: Process each 512-bit block
        for i in range(0, len(data), 64):
            chunk = data[i:i+64]
            words = list(struct.unpack('>16I', chunk))
            
            for j in range(16, 80):
                word = (words[j-3] ^ words[j-8] ^ words[j-14] ^ words[j-16])
                words.append(self.left_rotate(word, 1))
            
            a, b, c, d, e = h0, h1, h2, h3, h4
            
            for j in range(80):
                if 0 <= j <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= j <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= j <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                
                temp = (self.left_rotate(a, 5) + f + e + k + words[j]) & 0xffffffff
                e = d
                d = c
                c = self.left_rotate(b, 30)
                b = a
                a = temp
            
            h0 = (h0 + a) & 0xffffffff
            h1 = (h1 + b) & 0xffffffff
            h2 = (h2 + c) & 0xffffffff
            h3 = (h3 + d) & 0xffffffff
            h4 = (h4 + e) & 0xffffffff
        
        return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

    def run_sha1(self):
        """Execute SHA-1 hashing"""
        text = self.sha1_entry.get()
        if not text:
            messagebox.showwarning("Input Error", "Please enter text to hash!")
            return
        try:
            hashed = self.sha1_hash(text)
            self.sha1_result.config(text=hashed)
            self.set_status("SHA-1 Hash calculated successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"SHA-1 execution failed: {str(ex)}")

    # ==================== FULL MD5 TAB ====================

    def create_full_md5_tab(self):
        """Create Full MD5 Hash tab"""
        md5_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(md5_frame, text='🛡️ Full MD5')
        
        # Input frame
        input_frame = ttk.Frame(md5_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="MD5 Message Digest Algorithm (Full)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        ttk.Label(input_frame, text="Enter Text to Hash:", style='Info.TLabel').pack(anchor='w', padx=10, pady=(5, 5))
        
        input_container = ttk.Frame(input_frame, style='Card.TFrame')
        input_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.full_md5_entry = tk.Entry(input_container, 
                                     bg='#0a0e27', fg='#0f0',
                                     font=('Consolas', 11),
                                     insertbackground='#0f0',
                                     relief='flat', width=40)
        self.full_md5_entry.pack(side='left', padx=(0, 10), pady=5, ipady=5, fill='x', expand=True)
        
        ttk.Button(input_container, text="⚡ Calculate Hash",
                  style='Action.TButton',
                  command=self.run_full_md5).pack(side='left')

        # Output frame
        output_frame = ttk.Frame(md5_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(output_frame, text="MD5 Digest (128-bit)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        result_container = ttk.Frame(output_frame, style='Card.TFrame')
        result_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.full_md5_result = tk.Label(result_container,
                                      bg='#0a0e27', fg='#00d4ff',
                                      font=('Consolas', 12, 'bold'),
                                      anchor='w', padx=10, pady=10)
        self.full_md5_result.pack(side='left', fill='x', expand=True)
        
        ttk.Button(result_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_text(self.full_md5_result.cget('text'))).pack(side='left', padx=5)

    def full_md5_hash(self, message):
        """Implementation of Full MD5 algorithm"""
        msg_bytes = bytearray(message.encode('utf-8'))
        orig_len_bits = len(msg_bytes) * 8
        msg_bytes.append(0x80)
        while (len(msg_bytes) * 8) % 512 != 448:
            msg_bytes.append(0x00)
        
        msg_bytes += struct.pack('<Q', orig_len_bits)
        
        a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
        
        s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
        
        K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
             0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
             0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
             0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
             0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
             0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
             0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
             0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]
        
        for i in range(0, len(msg_bytes), 64):
            block = msg_bytes[i:i+64]
            M = list(struct.unpack('<16I', block))
            A, B, C, D = a0, b0, c0, d0
            
            for j in range(64):
                if 0 <= j <= 15:
                    F = (B & C) | ((~B) & D)
                    g = j
                elif 16 <= j <= 31:
                    F = (D & B) | ((~D) & C)
                    g = (5*j + 1) % 16
                elif 32 <= j <= 47:
                    F = B ^ C ^ D
                    g = (3*j + 5) % 16
                else:
                    F = C ^ (B | (~D))
                    g = (7*j) % 16
                
                F = (F + A + K[j] + M[g]) & 0xFFFFFFFF
                A, D, C, B = D, C, B, (B + self.left_rotate(F, s[j])) & 0xFFFFFFFF
            
            a0 = (a0 + A) & 0xFFFFFFFF
            b0 = (b0 + B) & 0xFFFFFFFF
            c0 = (c0 + C) & 0xFFFFFFFF
            d0 = (d0 + D) & 0xFFFFFFFF
            
        digest = struct.pack('<4I', a0, b0, c0, d0)
        return digest.hex()

    def run_full_md5(self):
        """Execute Full MD5 hashing"""
        text = self.full_md5_entry.get()
        if not text:
            messagebox.showwarning("Input Error", "Please enter text to hash!")
            return
        try:
            hashed = self.full_md5_hash(text)
            self.full_md5_result.config(text=hashed)
            self.set_status("Full MD5 Hash calculated successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Full MD5 execution failed: {str(ex)}")

    # ==================== UTILITY FUNCTIONS ====================
    
    def copy_to_clipboard(self, text_widget):
        """Copy text from a text widget to clipboard"""
        try:
            content = text_widget.get('1.0', 'end-1c')
            if content:
                self.root.clipboard_clear()
                self.root.clipboard_append(content)
                self.set_status("Copied to clipboard")
            else:
                messagebox.showinfo("No Content", "Nothing to copy!")
        except Exception as ex:
            messagebox.showerror("Error", f"Copy failed: {str(ex)}")
    
    def copy_text(self, text):
        """Copy plain text to clipboard"""
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.set_status("Copied to clipboard")
        else:
            messagebox.showinfo("No Content", "Nothing to copy!")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityToolkit(root)
    root.mainloop()
