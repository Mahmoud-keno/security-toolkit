"""
Security Toolkit - A Beautiful Tkinter Application for Cryptographic Algorithms
Integrates RSA, DES Key Generation, and S-DES Encryption/Decryption
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random


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
