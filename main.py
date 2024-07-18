import sys
import os
from time import sleep
from cryptography.fernet import Fernet,InvalidToken
import psutil
from InquirerPy import inquirer

desktop_path=os.path.normpath(os.path.expanduser("~/Desktop"))

# Generate a key and save it into a file
def write_key(path):
    key = Fernet.generate_key()
    with open(path, "wb") as key_file:
        key_file.write(key)
    os.chmod(path,0o400)

# Load the previously generated key
def load_key(path):
    return open(path, "rb").read()

# Encrypt a file
def encrypt_file(file_name,key_path):
    key = load_key(key_path)
    f = Fernet(key)

    with open(file_name, "rb") as file:
        file_data = file.read()

    encrypted_data = f.encrypt(file_data)

    with open(file_name, "wb") as file:
        file.write(encrypted_data)

# Decrypt a file
def decrypt_file(file_name,key_path):
    key = load_key(key_path)
    f = Fernet(key)

    with open(file_name, "rb") as file:
        encrypted_data = file.read()
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except InvalidToken as e:
        print("Decryption failed: Invalid key or corrupted data")
        sys.exit(1)
        
    with open(file_name, "wb") as file:
        file.write(decrypted_data)

def select(msg,choices,default=None):
    action = inquirer.select(
        message=msg,
        choices=choices,
        default=default
    ).execute()
    return action

def new():
    key_path = inquirer.filepath("New key location: ", only_directories=True, default=desktop_path if not os.path.exists("D:\\") else "D:\\").execute()
    key_path = os.path.join(key_path, inquirer.text("New key name: ",default="key",
                                    validate=lambda x: not os.path.exists(os.path.join(key_path,x+".key")), invalid_message="File already exists.").execute()+".key")
    file_path = inquirer.filepath("File to encrypt",default=desktop_path,
                                  validate=lambda x: os.path.exists(x)).execute()
    
    write_key(key_path)
    encrypt_file(file_path,key_path)
    sys.exit(0)
    
    
# ---------------- Main ----------------

# find .key file in an external drive
key_paths=[]
if os.path.exists("D:\\"):
    key_paths=[os.path.join(root, file) for root, dirs, files in os.walk("D:\\") for file in files if file.endswith(".key")]

a = select("Select a key file",key_paths+["Pick manually","New","Exit"])
if a=="New":
    new()
elif a=="Exit":
    sys.exit(0)
elif a=="Pick manually":
    key_path = inquirer.filepath(message="Key path: ",default=desktop_path,
                                    validate=lambda x: x.endswith(".key")).execute()
else:
    key_path = a
    
enORde = select("Encrypt or decrypt?",["Encrypt","Decrypt & Encrypt","Decrypt","Exit"],default="Decrypt & Encrypt")
if enORde=="Exit":
    sys.exit(0)
if len(sys.argv)!=2:
    file_path=inquirer.filepath("File to "+enORde.lower(),default=desktop_path).execute()
else:
    file_path = sys.argv[1]
    
if enORde=="Encrypt":
    encrypt_file(file_path,key_path)
    sys.exit(0)
elif enORde=="Decrypt":
    decrypt_file(file_path,key_path)
    sys.exit(0)
else:
    decrypt_file(file_path,key_path) 
    print("File decrypted. Close the Notepad to encrypt the file.")
    os.startfile(file_path)
    if file_path.endswith(".txt"):
        sleep(3)
        while True:
            sleep(0.7)
            for process in psutil.process_iter(['pid', 'name']):
                if process.info['name'].lower() == 'notepad.exe':
                    notepad_process = process
                    break
            if not notepad_process.is_running():
                break
    else:
        input("Press Enter to encrypt the file.")
    encrypt_file(file_path,key_path)
    print("File encrypted.")
if inquirer.confirm("Open file?").execute():
    os.startfile(file_path)