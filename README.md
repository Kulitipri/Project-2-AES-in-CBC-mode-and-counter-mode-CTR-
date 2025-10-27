# Programming Assignment 2 Report: AES Decryption (CBC & CTR)

This report describes the Python program written to decrypt the ciphertexts provided in the programming assignment, using two AES modes of operation: **CBC** and **CTR**.

## 1\. Environment & How to Run

### Environment

  * **Language:** Python
  * **Operating System:** Windows, macOS, Linux,...

### Library Installation

This program requires the `pycryptodome` library. You can install it using `pip`:

```bash
pip install pycryptodome
```

### How to Run

1.  Save the decryption code (e.g., the code for both CBC and CTR) into a Python file (e.g., `decrypt.py`).
2.  Open your terminal or command prompt.
3.  Navigate to the directory containing your code file.
4.  Run the following command:

<!-- end list -->

```bash
python decrypt.py
```

The program will execute, decrypt all 4 ciphertexts, and print the resulting plaintexts to the console.

## 2\. Libraries Used

This program utilizes the following modules from the `pycryptodome` library:

  * **`Crypto.Cipher.AES`:** Provides the core AES block cipher function (encrypt/decrypt a single 16-byte block). We use `AES.MODE_ECB` as a way to access this raw block cipher function without any other mode logic interfering.
  * **`Crypto.Util.number`:** Provides the `bytes_to_long` and `long_to_bytes` helper functions. These are used to convert between byte strings and integers, which is useful for performing XOR operations and incrementing the counter.

## 3\. How the Decryption Works

The program manually implements the logic for both CBC and CTR modes, as requested by the assignment.

### CBC (Cipher Block Chaining) Mode

The CBC decryption logic follows the formula: $P_i = \text{Decrypt}(K, C_i) \oplus C_{i-1}$

1.  **Preparation:** Convert the hex **Key** and hex **Ciphertext** into raw `bytes`.
2.  **Extract IV:** The first 16 bytes of the ciphertext bytestring are extracted as the **IV** (Initialization Vector). The remainder is the actual ciphertext blocks $C_1, C_2, ...$
3.  **Initialization:** Create an AES cipher object using the `key` and `AES.MODE_ECB` (to access the raw block decryption function).
4.  **Iterative Decryption:**
      * Set `previous_block = IV`.
      * Loop through each 16-byte ciphertext block $C_i$:
        a.  Decrypt the block $C_i$ with the key: `decrypted_block = cipher.decrypt(C_i)`.
        b.  XOR the result with the *previous* ciphertext block: `plaintext_block = decrypted_block XOR previous_block`.
        c.  Append the resulting `plaintext_block` to the final plaintext.
        d.  Update `previous_block = C_i` (the raw ciphertext block) for the next iteration.
5.  **Unpadding:** After decryption, the full plaintext has **PKCS5 padding**. The code reads the final byte (value $N$) and removes the last $N$ bytes to recover the original message.

### CTR (Counter) Mode

CTR decryption logic (which is identical to encryption) turns AES into a stream cipher following the formula: $P_i = C_i \oplus \text{Keystream}_i$.

1.  **Preparation:** Convert the hex **Key** and **Ciphertext** into raw `bytes`.
2.  **Extract Nonce:** The first 16 bytes are extracted as the **Nonce** (which serves as the IV). This value is used as the *starting value* for the counter.
3.  **Initialization:** Create an AES cipher object using the `key` and `AES.MODE_ECB` (to access the raw block *encryption* function).
4.  **Prepare Counter:** Convert the 16-byte `Nonce` into a single large integer (`counter_int`).
5.  **Iterative Decryption:**
      * Loop through each ciphertext block $C_i$ (the last block may be shorter than 16 bytes):
        a.  Convert the current `counter_int` back into 16 bytes (`counter_bytes`).
        b.  **Generate Keystream:** *Encrypt* the `counter_bytes` with the key: `keystream_block = cipher.encrypt(counter_bytes)`.
        c.  **XOR:** Perform an XOR operation between the ciphertext block $C_i$ and the `keystream_block`: `plaintext_block = C_i XOR keystream_block`.
        d.  Append the resulting `plaintext_block` to the final plaintext.
        e.  **Increment Counter:** Increment the `counter_int` by 1 (`counter_int += 1`) for the next iteration.
6.  **Finalize:** CTR mode does not use padding, so the result after the final XOR is the complete message.

## 4\. All Recovered Plaintexts

Below are the plaintexts recovered from the four provided ciphertexts:

-----

**Question 1 (CBC):**

```
Basic CBC mode encryption needs padding.
```

-----

**Question 2 (CBC):**

```
Our implementation uses rand. IV
```

-----

**Question 3 (CTR):**

```
CTR mode lets you build a stream cipher from a block cipher.
```

-----

**Question 4 (CTR):**

```
Always avoid the two time pad!
```
