import hashlib
from tkinter import *
from tkinter import filedialog

root = Tk()
root.title("Hashing Uygulaması")
root.geometry("600x400")

# Dosya seçme kısmı
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, "rb") as f:
            bytes = f.read()
            md5_hash = hashlib.md5(bytes).hexdigest()
            sha1_hash = hashlib.sha1(bytes).hexdigest()
            sha256_hash = hashlib.sha256(bytes).hexdigest()
            hash_text.delete("1.0", END)
            hash_text.insert(END, f"MD5: {md5_hash},\nSHA1: {sha1_hash},\nSHA256: {sha256_hash}")

# Dosya hash karşılaştırma kısmı
def compare_hash():
    file_hash = hash_text.get("1.0", END).strip()
    input_hash = hash_input.get().strip()
    file_hashar = file_hash.replace("\n", "").replace("MD5: ", "").replace("SHA1: ", "").replace("SHA256: ", "").split(",")
    print(file_hashar[0])
    print("2."+input_hash)
    if file_hash and input_hash:
        if file_hashar[0] == input_hash or file_hashar[1] == input_hash or file_hashar[2] == input_hash:
            status_text.config(text="Doğrulandı", fg="green")
        else:
            status_text.config(text="Doğrulanamadı", fg="red")
    else:
        status_text.config(text="Lütfen dosya hash'ini hesaplayın ve yapıştırın", fg="black")

# Dosya seçme butonu
select_button = Button(root, text="Dosya Seç", command=select_file)
select_button.pack(pady=10)

# Hesaplanan hash text alanı
hash_text = Text(root, height=8, width=40, font=("Helvetica", 10))
hash_text.pack()

# Yapıştırılacak hash input alanı
hash_input = Entry(root, width=40, font=("Helvetica", 10))
hash_input.pack(pady=10)

# Hash karşılaştırma butonu
compare_button = Button(root, text="Karşılaştır", command=compare_hash)
compare_button.pack()

# Doğrulama durumu text alanı
status_text = Label(root, text="", font=("Helvetica", 12))
status_text.pack(pady=10)

root.mainloop()