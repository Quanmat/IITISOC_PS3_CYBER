import sqlite3
import bcrypt
from tkinter import * 
from tkinter import messagebox,filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# DATABASE SETUP / OUTLINE

def set_db() :
     conn = sqlite3.connect('key_management.db')
     c = conn.cursor()

     c.execute('''
            CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
 
     c.execute('''
            CREATE TABLE IF NOT EXISTS skeys (
            username TEXT,
            public_rkeys TEXT,
            private_rkeys TEXT,
            FOREIGN KEY(username) REFERENCES users(username)
        )
    ''')
     conn.commit()
     conn.close()

set_db()

# PASSWORD HASHING

def hash_password(password):
    salt = bcrypt.gensalt(rounds=15)
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def check_password(hashed_password, user_password):
    result = bcrypt.checkpw(user_password.encode(), hashed_password)

    return result

# ALGORITHM IMPLEMENTATION

def generate_rpair(username):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    conn = sqlite3.connect('key_management.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO skeys (username, public_rkeys, private_rkeys) VALUES (?, ?, ?)''', (username, public_key, private_key))
    conn.commit()

def get_rkeys_Public(username):
        conn = sqlite3.connect('key_management.db')
        c = conn.cursor()
        c.execute('SELECT public_rkeys FROM skeys WHERE username = ?', (username,))
        keys = c.fetchone()
        if keys:
            public_key = RSA.import_key(keys[0])
            return public_key
        else:
            return None
    
def get_rkeys_Private(username):
        conn = sqlite3.connect('key_management.db')
        c = conn.cursor()
        c.execute('SELECT private_rkeys FROM skeys WHERE username = ?', (username,))
        keys = c.fetchone()
        if keys:
            private_key = RSA.import_key(keys[0])
            return private_key
        else:
            return None

def encrypt_symtc_key(symtc_key, public_key):
    RSA_cipher_object = PKCS1_OAEP.new(public_key)
    encrypted_symtc_key = RSA_cipher_object.encrypt(symtc_key)
    return encrypted_symtc_key

def decrypt_symtc_key(encrypted_symtc_key, private_key):
    RSA_cipher_object = PKCS1_OAEP.new(private_key)
    symtc_key = RSA_cipher_object.decrypt(encrypted_symtc_key)
    return symtc_key

# IMAGE ENCRYPTION AND DECRYPTION

def encrypt_imageF(image_path, symtc_key):
    AES_cipher_object = AES.new(symtc_key, AES.MODE_EAX)

    f =  open(image_path, 'rb') 
    data = f.read()
    f.close

    ciphertext, tag = AES_cipher_object.encrypt_and_digest(data)
    
    f2 = open(image_path + ".enc", "wb")
    for x in (AES_cipher_object.nonce, tag, ciphertext):
        f2.write(x)
    f2.close()

def decrypt_imageF(image_path, symtc_key, pathF):
    f = open(image_path, 'rb')
    nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
    f.close

    AES_cipher_object = AES.new(symtc_key, AES.MODE_EAX, nonce=nonce)
    data = AES_cipher_object.decrypt_and_verify(ciphertext, tag)

    f2 = open(pathF, 'wb')
    f2.write(data)
    f2.close()

def encrypt_aes(image_path, username):
    symtc_key = get_random_bytes(16)
    public_key = get_rkeys_Public(username)
    encrypted_symtc_key = encrypt_symtc_key(symtc_key, public_key)

    encrypt_imageF(image_path, symtc_key)

    f = open(image_path + ".key", 'wb')
    f.write(encrypted_symtc_key)
    f.close()

def decrypt_aes(image_path, key_path, username, pathF):
    private_key = get_rkeys_Private(username)

    f = open(key_path, 'rb')
    encrypted_symtc_key = f.read()
    f.close

    symtc_key = decrypt_symtc_key(encrypted_symtc_key, private_key)
    decrypt_imageF(image_path, symtc_key, pathF)

# USER REGISTRATION, LOGIN AND AUTHENTICATION 

def register_user(username, password):
    hashed_password = hash_password(password)
    conn = sqlite3.connect('key_management.db')
    c = conn.cursor()
    c.execute('SELECT 1 FROM users WHERE username = ?', (username,))
    if c.fetchone():
       return False 
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    conn.close()
    return True

def login_user(username, password):
    conn = sqlite3.connect('key_management.db')
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    if result and check_password(result[0], password):
        return True
    return False

def registration():
    rgt_window = Toplevel(root)
    rgt_window.title("Register")
    rgt_window.iconbitmap('registercon.ico')

    Label(rgt_window, text="Username").pack()

    e_rgt_u = Entry(rgt_window)
    e_rgt_u.pack()

    Label(rgt_window, text="Password").pack()
  
    e_rgt_pw = Entry(rgt_window, show='*')
    e_rgt_pw.pack()

    def registerF():
        username = e_rgt_u.get()
        password = e_rgt_pw.get()
        e_rgt_u.delete(0, END)
        e_rgt_pw.delete(0, END)
        rgt_success = register_user(username, password)

        if not username or not password:
            messagebox.showwarning("Warning!", "Username and password cannot be empty.")
            rgt_window.destroy()
            return
        
        if rgt_success:
            messagebox.showinfo("Success", f"Registration successful.\nYour username is: {username}")
            rgt_window.destroy()
        else:
            messagebox.showerror("Error", "Username already exists.")
            rgt_window.destroy()

    btn_rgt = Button(rgt_window, text="Register", command=registerF)
    btn_rgt.pack()

def activate_buttons():
    btn_encrypt_image.config(state="normal", bg = "green")
    btn_generate_keys.config(state="normal", bg = "yellow")
    btn_decrypt_image.config(state="normal", bg = "red")

def logging_in():
    login_window = Toplevel(root)
    login_window.title("Login")
    login_window.iconbitmap('logincon.ico')

    Label(login_window, text="Username").pack()
    
    e_login_u = Entry(login_window)
    e_login_u.pack()

    Label(login_window, text="Password").pack()
    
    e_login_pw = Entry(login_window, show='*')
    e_login_pw.pack()

    def loginF():
        username = e_login_u.get()
        password = e_login_pw.get()
        e_login_u.delete(0, END)
        e_login_pw.delete(0, END)
        login_success = login_user(username, password)

        if not username or not password:
            messagebox.showwarning("Warning!", "Username and password cannot be empty.")
            login_window.destroy()
            return 
        
        if login_success:
            global user_loggedin
            user_loggedin = username
            messagebox.showinfo("Success", "Login successful.")
            login_window.destroy()
            #e_wel.insert(0, " Welcome " + username)                        #
            lbl_cl = Label(root, bg = "yellow", padx = 173, pady = 1)
            lbl_cl.grid(row=3, column=0, columnspan=3)
            lbl_Wl = Label(root, text= "Welcome " + username)
            lbl_Wl.grid(row=4, column=0, columnspan=3)

            activate_buttons()
        else:
            messagebox.showerror("Error", "Invalid username or password.")
            login_window.destroy()

    btn_login = Button(login_window, text="Login", command=loginF)
    btn_login.pack()


# FUNCTIONS CALLED DIRECTLY AFTER BUTTON CLICK 
    
def generate_keysF():
    if user_loggedin:
        generate_rpair(user_loggedin)
        messagebox.showinfo("Success", "Key pair generated successfully.")
    else:
        messagebox.showerror("Error", "Log in to access key generation.")

def encrypt_image():
    if user_loggedin:
       E_path = filedialog.askopenfilename(title="Select Image To Be Encrypted", filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
       if E_path:
              encrypt_aes(E_path, user_loggedin)
              messagebox.showinfo("Success", "Image encrypted successfully.")
    else:
        messagebox.showerror("Error", "Log in to access image encryption.")

def decrypt_image():
    if user_loggedin:
       D_path = filedialog.askopenfilename(title="Select The Encrypted Image", filetypes=[("Encrypted files", "*.enc")])

       if D_path:
          k_path = filedialog.askopenfilename(title="Select The Key File", filetypes=[("Key files", "*.key")])
               
          if k_path:
             pathF = filedialog.asksaveasfilename(title="Save Decrypted Image As", filetypes=[("Image files", "*.jpg;*.jpeg;*.png")], defaultextension=".jpg")    
             
             if pathF:
                decrypt_aes(D_path, k_path, user_loggedin, pathF)
                messagebox.showinfo("Success", "Image decrypted successfully.")
             else:
               messagebox.showerror("Error", "No location saved, action cancelled.")
          else:
            messagebox.showerror("Error", "No key file selected, action cancelled.")
       else:
         messagebox.showerror("Error", "No encrypted image selected, action cancelled.")
    else:
      messagebox.showerror("Error", "Log in to access image decryption.")


# GUI INTERFACE
      
root = Tk()

root.title("Secure Image Encryption")
root.iconbitmap('iiticon.ico')

user_loggedin = None

btn_register = Button(root, text="Register", padx=150, pady=80, bg = 'yellow', command=registration)  
btn_register.grid(row=0, column=0, columnspan=3)   
btn_login = Button(root, text="Login", padx=156, pady=80,bg = 'blue', command=logging_in)                            
btn_login.grid(row=1, column=0, columnspan=3)      

btn_encrypt_image = Button(root, text="Encrypt Image", command=encrypt_image, state="disabled")   #
btn_encrypt_image.grid(row=2, column=0, padx=22)

btn_generate_keys = Button(root, text="Generate Keys",command=generate_keysF, state="disabled")   #
btn_generate_keys.grid(row=2, column=1, padx=22)

btn_decrypt_image = Button(root, text="Decrypt Image",command=decrypt_image, state="disabled")   #
btn_decrypt_image.grid(row=2, column=2, padx=22)

# e_wel = Entry(root, width=58, borderwidth=2)                              #
# e_wel.grid(row=3, column=0, columnspan=3, padx=10, pady=10)               #

root.mainloop()
    

 

  
    