from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Kích thước khối AES (luôn là 16 bytes)
BLOCK_SIZE = 16

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Thực hiện phép XOR trên hai chuỗi bytes."""
    # Chuyển bytes sang số nguyên, XOR, rồi chuyển ngược lại
    int_a = bytes_to_long(a)
    int_b = bytes_to_long(b)
    xor_val = int_a ^ int_b
    
    # Đảm bảo kết quả trả về có cùng độ dài (16 bytes)
    return long_to_bytes(xor_val, BLOCK_SIZE)

def pkcs5_unpad(data: bytes) -> bytes:
    """
    Loại bỏ phần đệm PKCS5 (hoặc PKCS7) khỏi dữ liệu đã giải mã.
    
    """
    if not data:
        raise ValueError("Dữ liệu rỗng, không thể unpad")

    # Lấy byte cuối cùng, đó chính là số lượng byte đệm
    padding_len = data[-1]
    
    # Kiểm tra xem byte đệm có hợp lệ không
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Giá trị padding không hợp lệ")
        
    # Kiểm tra xem tất cả các byte đệm có đúng giá trị không
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Padding bị lỗi")
        
    # Trả về dữ liệu không có phần đệm
    return data[:-padding_len]

def decrypt_cbc(key_hex: str, ciphertext_hex: str) -> str:
    """
    Giải mã một ciphertext AES-CBC theo logic tự triển khai.
    
    """
    try:
        # 1. Chuyển đổi key và ciphertext từ hex sang bytes
        key = bytes.fromhex(key_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # 2. Tách IV (16 bytes đầu tiên) ra khỏi ciphertext
        iv = ciphertext[:BLOCK_SIZE]
        ciphertext_blocks = ciphertext[BLOCK_SIZE:]
        
        # 3. Khởi tạo AES cipher ở chế độ ECB.
        #    Chúng ta dùng ECB chỉ để truy cập hàm giải mã khối 16-byte cơ bản.
        #   
        cipher = AES.new(key, AES.MODE_ECB)
        
        plaintext_bytes = b""
        previous_cipher_block = iv
        
        # 4. Lặp qua từng khối ciphertext
        for i in range(0, len(ciphertext_blocks), BLOCK_SIZE):
            current_block = ciphertext_blocks[i : i + BLOCK_SIZE]
            
            # Công thức giải mã CBC: P[i] = Decrypt(K, C[i]) XOR C[i-1]
            
            # a. Giải mã khối hiện tại
            decrypted_block = cipher.decrypt(current_block)
            
            # b. XOR với khối ciphertext *trước đó* (khối đầu tiên XOR với IV)
            plaintext_block = xor_bytes(decrypted_block, previous_cipher_block)
            
            # c. Thêm vào kết quả
            plaintext_bytes += plaintext_block
            
            # d. Cập nhật khối "trước đó" cho vòng lặp tiếp theo
            previous_cipher_block = current_block
            
        # 5. Loại bỏ padding PKCS5 sau khi giải mã xong
        unpadded_plaintext = pkcs5_unpad(plaintext_bytes)
        
        # 6. Chuyển kết quả bytes sang chuỗi string (dùng utf-8)
        return unpadded_plaintext.decode('utf-8')
        
    except ValueError as e:
        return f"Lỗi: {e}. Có thể key hoặc ciphertext bị sai."
    except Exception as e:
        return f"Đã xảy ra lỗi: {e}"

# === THỰC THI ===
if __name__ == "__main__":
    
    # Dữ liệu cho Câu 1
    key_cbc = "140b41b22a29beb4061bda66b6747e14"
    
    # Ciphertext đầy đủ cho Câu 1 (lấy từ nguồn bên ngoài, vì PDF bị cắt)
    ct1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    
    # Dữ liệu cho Câu 2
    # Ciphertext đầy đủ cho Câu 2 (lấy từ nguồn bên ngoài)
    ct2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

    print("--- Giải mã AES-CBC ---")
    
    # Giải mã câu 1
    plaintext1 = decrypt_cbc(key_cbc, ct1)
    print(f"[Câu 1] Plaintext:\n{plaintext1}\n")
    
    # Giải mã câu 2
    plaintext2 = decrypt_cbc(key_cbc, ct2)
    print(f"[Câu 2] Plaintext:\n{plaintext2}\n")