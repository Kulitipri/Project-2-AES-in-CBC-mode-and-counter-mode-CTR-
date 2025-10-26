from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Kích thước khối AES (luôn là 16 bytes)
BLOCK_SIZE = 16

def xor_bytes_flexible(a: bytes, b: bytes) -> bytes:
    """
    Thực hiện phép XOR trên hai chuỗi bytes.
    Hàm này có thể xử lý các chuỗi có độ dài khác nhau,
    nó sẽ XOR cho đến hết độ dài của chuỗi ngắn hơn.
    """
    length = min(len(a), len(b))
    return bytes([a[i] ^ b[i] for i in range(length)])

def decrypt_ctr(key_hex: str, ciphertext_hex: str) -> str:
    """
    Giải mã một ciphertext AES-CTR theo logic tự triển khai.
   
    """
    try:
        # 1. Chuyển đổi key và ciphertext từ hex sang bytes
        key = bytes.fromhex(key_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # 2. Tách IV (nonce) (16 bytes đầu tiên) ra khỏi ciphertext
        #    Trong CTR, đây là giá trị khởi tạo cho bộ đếm (counter).
        iv_nonce = ciphertext[:BLOCK_SIZE]
        ciphertext_data = ciphertext[BLOCK_SIZE:]
        
        # 3. Khởi tạo AES cipher ở chế độ ECB.
        #    Chúng ta dùng ECB để truy cập hàm *MÃ HÓA* (encrypt) 16-byte.
        cipher = AES.new(key, AES.MODE_ECB)
        
        plaintext_bytes = b""
        
        # Chuyển IV/Nonce thành một số nguyên để dễ dàng cộng
        counter_int = bytes_to_long(iv_nonce)
        
        # 4. Lặp qua từng khối ciphertext
        for i in range(0, len(ciphertext_data), BLOCK_SIZE):
            # Lấy khối ciphertext (có thể ngắn hơn 16 bytes ở cuối)
            ct_block = ciphertext_data[i : i + BLOCK_SIZE]
            
            # a. Chuyển giá trị counter hiện tại sang bytes
            counter_bytes = long_to_bytes(counter_int, BLOCK_SIZE)
            
            # b. Tạo keystream bằng cách *MÃ HÓA* (ENCRYPT) counter
            #    Công thức: Keystream = Encrypt(Key, Counter)
            keystream_block = cipher.encrypt(counter_bytes)
            
            # c. XOR keystream với ciphertext để lấy plaintext
            #    Công thức: Plaintext = Ciphertext XOR Keystream
            plaintext_block = xor_bytes_flexible(ct_block, keystream_block)
            
            # d. Thêm vào kết quả
            plaintext_bytes += plaintext_block
            
            # e. Tăng counter lên 1 cho khối tiếp theo
            counter_int += 1
            
        # 5. Chế độ CTR không dùng padding,
        #    chỉ cần chuyển kết quả bytes sang string.
        return plaintext_bytes.decode('utf-8')
        
    except ValueError as e:
        return f"Lỗi: {e}. Có thể key hoặc ciphertext bị sai."
    except Exception as e:
        return f"Đã xảy ra lỗi: {e}"

# === THỰC THI ===
if __name__ == "__main__":
    
    # Dữ liệu cho Câu 3 & 4
    key_ctr = "36f18357be4dbd77f050515c73fcf9f2" # [cite: 21, 25]
    
    # Ciphertext đầy đủ cho Câu 3 (từ nguồn bên ngoài)
    ct3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    
    # Ciphertext đầy đủ cho Câu 4 (từ nguồn bên ngoài)
    ct4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

    print("--- Giải mã AES-CTR ---")
    
    # Giải mã câu 3
    plaintext3 = decrypt_ctr(key_ctr, ct3)
    print(f"[Câu 3] Plaintext:\n{plaintext3}\n")
    
    # Giải mã câu 4
    plaintext4 = decrypt_ctr(key_ctr, ct4)
    print(f"[Câu 4] Plaintext:\n{plaintext4}\n")