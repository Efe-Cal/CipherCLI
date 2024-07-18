import sys
import os
from time import sleep
from cryptography.fernet import Fernet,InvalidToken
import psutil
from InquirerPy import inquirer

desktop_path=os.path.normpath(os.path.expanduser("~/Desktop"))

class Cryptographer:
    def __init__(self,key_path,file_path):
        self.key_path = key_path
        self.file_path = file_path
        if os.path.exists(self.key_path):
            self.key = self.load_key()
        else:
            self.write_key()
    # Generate a key and save it into a file
    def write_key(self):
        self.key = Fernet.generate_key()
        with open(self.key_path, "wb") as key_file:
            key_file.write(self.key)
        os.chmod(self.key_path,0o400)

    # Load the previously generated key
    def load_key(self):
        return open(self.key_path, "rb").read()

    # Encrypt a file
    def encrypt_file(self):
        f = Fernet(self.key)

        with open(self.file_path, "rb") as file:
            file_data = file.read()

        encrypted_data = f.encrypt(file_data)

        with open(self.file_path, "wb") as file:
            file.write(encrypted_data)

    # Decrypt a file
    def decrypt_file(self):
        f = Fernet(self.key)

        with open(self.file_path, "rb") as file:
            encrypted_data = file.read()
        try:
            decrypted_data = f.decrypt(encrypted_data)
        except InvalidToken as e:
            print("Decryption failed: Invalid key or corrupted data")
            sys.exit(1)
            
        with open(self.file_path, "wb") as file:
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
    
    crypt = Cryptographer(key_path,file_path)
    crypt.encrypt_file()
    sys.exit(0)
    
    
# ---------------- Main ----------------

# find .key file in an external drive
key_paths=[]
if os.path.exists("D:\\"):
    key_paths=[os.path.join(root, file) for root, dirs, files in os.walk("D:\\") for file in files if file.endswith(".key")]

a = select("Select a key file",key_paths+["Pick manually","New Key","Exit"])
if a=="New Key":
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

crypt= Cryptographer(key_path,file_path)

if enORde=="Encrypt":
    crypt.encrypt_file()
    sys.exit(0)
elif enORde=="Decrypt":
    crypt.decrypt_file()
    sys.exit(0)
else:
    crypt.decrypt_file() 
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
    crypt.encrypt_file()
    print("File encrypted.")
if inquirer.confirm("Open file?").execute():
    os.startfile(file_path)