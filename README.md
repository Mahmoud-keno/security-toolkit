# 🔐 Security Toolkit

A professional, comprehensive GUI application for demonstrating and performing various cryptographic operations. Built with Python and Tkinter, featuring a modern dark-themed interface.

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![Tkinter](https://img.shields.io/badge/GUI-Tkinter-green.svg) ![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📖 Overview

**Security Toolkit** is an all-in-one cryptographic suite designed for educational purposes and practical use. It enables users to visualize and execute complex algorithms involved in encryption, decryption, hashing, and key exchange. The application features a clean, tabbed interface with a "Hacker/Cyberpunk" aesthetic (Dark Blue/Green) for an immersive experience.

## ✨ Features

### 🔑 Public Key Cryptography
*   **RSA Encryption System**:
    *   Automated Prime & Key Generation (Public/Private keys).
    *   Encrypt and Decrypt text messages.
    *   Support for file input and output.
*   **Diffie-Hellman Key Exchange**:
    *   Simulate secure key exchange between two parties (Alice & Bob).
    *   Visualize the generation of public keys and the shared secret.
*   **DSS (Digital Signature Standard)**:
    *   Algorithm parameter visualization (p, q, g).
    *   Sign messages to create digital signatures.
    *   Verify signatures to ensure authenticity.

### 🔒 Symmetric Key Cryptography
*   **DES (Data Encryption Standard)**:
    *   **Key Generator**: Visualizes the generation of 16 round keys from a 64-bit hexadecimal master key.
    *   Detailed breakdown of shifts and permutations (PC-1, PC-2).
*   **S-DES (Simplified DES)**:
    *   Educational 8-bit block cipher implementation.
    *   10-bit Key input with automatic subkey generation (K1, K2).
    *   Full encryption and decryption pipeline.

### 🛡️ Hashing Algorithms
*   **MD5 (Message Digest Algorithm 5)**:
    *   **Round 1 Visualizer**: Step-by-step log of the first 16 operations of the MD5 first round.
    *   **Full MD5**: Calculate 128-bit hash digests for any text or file.
*   **SHA-1 (Secure Hash Algorithm 1)**:
    *   Generate standard 160-bit hash digests.
    *   Secure and fast implementation.

### ⚙️ Utility Features
*   **File Operations**: Load text files (`.txt`) directly into input fields and save results to files.
*   **Clipboard Integration**: One-click buttons to copy results.
*   **Responsive GUI**: Modern, dark-themed interface built with `ttk` styling.

---

## 🚀 Getting Started

### Prerequisites

*   **Python 3.6+**: Ensure Python is installed on your system.
    *   [Download Python](https://www.python.org/downloads/)
*   **Tkinter**: Usually comes pre-installed with Python.
    *   *Linux users might need:* `sudo apt-get install python3-tk`

### Installation

1.  **Clone the repository** (or download the source code):
    ```bash
    git clone https://github.com/Mahmoud-keno/security-toolkit.git
    cd security-toolkit
    ```

2.  **No external dependencies required**: The project uses only standard Python libraries (`tkinter`, `random`, `struct`, `math`).

### 🏃 How to Run

1.  Open your terminal or command prompt.
2.  Navigate to the project directory.
3.  Run the application using Python:

    ```bash
    python security_toolkit.py
    ```

4.  The GUI window should appear immediately.

---

## 🖥️ Usage Guide

1.  **Navigation**: Use the tabs at the top (RSA, DES, S-DES, etc.) to switch between algorithms.
2.  **Input**:
    *   **Text**: Type directly into the input fields.
    *   **Files**: Click the **📂 Load File** button to read text from a local `.txt` file.
3.  **Action**: Click the main action buttons (e.g., **Key Generation**, **Encrypt**, **Run Round 1**) to execute the algorithm.
4.  **Output**:
    *   Results are shown in the output text areas or logs.
    *   **Copy**: Click the **📋** button to copy to clipboard.
    *   **Save**: Click the **💾** button to save the result to a text file.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1.  Fork the project
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
