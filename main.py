import sys
import os
from time import sleep
from cryptography.fernet import Fernet,InvalidToken
import psutil
from InquirerPy import inquirer

desktop_path=os.path.normpath(os.path.expanduser("~/Desktop"))

class Cryptographer:
    def __init__(self,key_path:str,file_paths):
        self.key_path = key_path
        self.file_paths = file_paths
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
    def encrypt_file(self,fn_encrypt="No"):
        f = Fernet(self.key)
        for file_path in self.file_paths:
            with open(file_path, "rb") as file:
                file_data = file.read()

            encrypted_data = f.encrypt(file_data)

            with open(file_path, "wb") as file:
                file.write(encrypted_data)
            if fn_encrypt=="Yes":
                new_file_path = os.path.join(os.path.split(file_path)[0], f.encrypt(os.path.basename(file_path).encode()).decode())
                os.rename(file_path,new_file_path)


    # Decrypt a file
    def decrypt_file(self,fn_encrypt="No"):
        f = Fernet(self.key)
        for file_path in self.file_paths:
            with open(file_path, "rb") as file:
                encrypted_data = file.read()
            try:
                decrypted_data = f.decrypt(encrypted_data)
            except InvalidToken as e:
                print("Decryption failed: Invalid key or corrupted data")
                sys.exit(1)
                
            with open(file_path, "wb") as file:
                file.write(decrypted_data)
            if fn_encrypt=="Yes":
                new_file_path = os.path.join(os.path.split(file_path)[0], f.decrypt(os.path.basename(file_path).encode()).decode())
                os.rename(file_path,new_file_path)
    
    @staticmethod
    def decrypt_filenames(keypath,file_paths):
        f = Fernet(open(keypath, "rb").read())
        filenames=[]
        for file_path in file_paths:
            try:
                filenames.append(f.decrypt(os.path.basename(file_path).encode()).decode()+" (Encrypted file)")
            except InvalidToken:
                filenames.append(os.path.basename(file_path))
        return filenames

def select(msg,choices,default=None,multiselect=False):
    action = inquirer.select(
        message=msg,
        choices=choices,
        default=default,
        multiselect=multiselect
    ).execute()
    return action

def new():
    key_path = inquirer.filepath("New key location: ", only_directories=True, default=desktop_path if not os.path.exists("D:\\") else "D:\\").execute()
    key_path = os.path.join(key_path, inquirer.text("New key name: ",default="key",
                                    validate=lambda x: not os.path.exists(os.path.join(key_path,x+".key")), invalid_message="File already exists.").execute()+".key")
    return key_path
# ---------------- Main ----------------

# find .key file in an external drive
key_paths=[]
if os.path.exists("D:\\"):
    key_paths=[os.path.join(root, file) for root, dirs, files in os.walk("D:\\") for file in files if file.endswith(".key")]

a = select("Select a key file",key_paths+["Pick manually","New Key","Exit"])
if a=="New Key":
    key_path=new()
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
if len(sys.argv)<2:
    file_paths=[inquirer.filepath("File to "+enORde.lower(),default=desktop_path).execute()]
else:
    if os.path.isdir(sys.argv[1]):
        file_paths = [os.path.join(root, file) for root, dirs, files in os.walk(sys.argv[1]) for file in files]
    else:
        file_paths = sys.argv[1:]


if len(file_paths)>1:
    filenames=Cryptographer.decrypt_filenames(key_path,file_paths)
    selected_files = select("Select files to "+enORde.lower(),filenames+["All"],default="All",multiselect=True)
    if selected_files==["All"]:
        pass
    else:
        file_paths=[file_paths[filenames.index(i)] for i in selected_files]


crypt= Cryptographer(key_path,file_paths)

if enORde=="Encrypt":
    fn_encrypt = select("Do you want to encrypt the filename(s)?",["Yes","No"],default="Yes")
    print("Encrypting...")
    crypt.encrypt_file(fn_encrypt)
    sys.exit(0)
elif enORde=="Decrypt":
    fn_encrypted = select("Do you want to decrypt filename(s)?",["Yes","No"],default="Yes")
    print("Decrypting...")
    crypt.decrypt_file(fn_encrypted)
    sys.exit(0)
else:
    crypt.decrypt_file() 
    print("File decrypted. Close the Notepad to encrypt the file.")
    os.startfile(file_paths)
    if file_paths.endswith(".txt"):
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
    os.startfile(file_paths)