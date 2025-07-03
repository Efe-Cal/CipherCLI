import sys
import os
from time import sleep
from cryptography.fernet import Fernet, InvalidToken
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
        try:
            with open(self.key_path, "wb") as key_file:
                key_file.write(self.key)
            os.chmod(self.key_path,0o400)
        except Exception as e:
            print(f"Error writing key file: {e}")
            raise

    # Load the previously generated key
    def load_key(self):
        try:
            with open(self.key_path, "rb") as f:
                return f.read()
        except Exception as e:
            print(f"Error reading key file: {e}")
            raise

    # Encrypt a file
    def encrypt_file(self, fn_encrypt="No"):
        f = Fernet(self.key)
        for file_path in self.file_paths:
            try:
                with open(file_path, "rb") as file:
                    file_data = file.read()
            except Exception as e:
                print(f"Error reading file '{file_path}': {e}")
                continue

            try:
                encrypted_data = f.encrypt(file_data)
            except Exception as e:
                print(f"Error encrypting file '{file_path}': {e}")
                continue

            try:
                with open(file_path, "wb") as file:
                    file.write(encrypted_data)
            except Exception as e:
                print(f"Error writing encrypted file '{file_path}': {e}")
                continue
            # Rename 
            if fn_encrypt=="Yes":
                try:
                    new_file_path = os.path.join(os.path.split(file_path)[0], f.encrypt(os.path.basename(file_path).encode()).decode())
                    os.rename(file_path,new_file_path)
                except Exception as e:
                    print(f"Error renaming encrypted file '{file_path}': {e}")
                    continue

    # Decrypt a file
    def decrypt_file(self,fn_encrypt="No"):
        f = Fernet(self.key)
        for file_path in self.file_paths:
            try:
                with open(file_path, "rb") as file:
                    encrypted_data = file.read()
            except Exception as e:
                print(f"Error reading file '{file_path}': {e}")
                continue
            try:
                decrypted_data = f.decrypt(encrypted_data)
            except InvalidToken as e:
                print("Decryption failed: Invalid key or corrupted data")
                sys.exit(1)
            except Exception as e:
                print(f"Error decrypting file '{file_path}': {e}")
                continue
            try:
                with open(file_path, "wb") as file:
                    file.write(decrypted_data)
            except Exception as e:
                print(f"Error writing decrypted file '{file_path}': {e}")
                continue
            if fn_encrypt=="Yes":
                try:
                    new_file_path = os.path.join(os.path.split(file_path)[0], f.decrypt(os.path.basename(file_path).encode()).decode())
                    os.rename(file_path,new_file_path)
                except Exception as e:
                    print(f"Error renaming decrypted file '{file_path}': {e}")
                    continue
    
    @staticmethod
    def decrypt_filenames(keypath,file_paths):
        try:
            with open(keypath, "rb") as key_file:
                key = key_file.read()
            f = Fernet(key)
        except Exception as e:
            print(f"Error loading key for filename decryption: {e}")
            return [os.path.basename(fp) for fp in file_paths]
        filenames=[]
        for file_path in file_paths:
            try:
                filenames.append(f.decrypt(os.path.basename(file_path).encode()).decode()+" (Encrypted file)")
            except InvalidToken:
                filenames.append(os.path.basename(file_path))
            except Exception as e:
                print(f"Error decrypting filename '{file_path}': {e}")
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
key_paths = []
partitions = []
for p in psutil.disk_partitions(all=False):
    try:
        if os.name == 'nt':
            # On Windows, removable drives often have 'removable' in opts
            if 'removable' in p.opts.lower():
                partitions.append(p.device)
        else:
            # On Unix, skip system partitions and check for mountpoint accessibility
            if p.fstype and os.access(p.mountpoint, os.R_OK):
                partitions.append(p.device)
    except Exception as e:
        continue

print("Searching for key files in partitions: " + ", ".join(partitions))
for partition in partitions:
    try:
        for root, dirs, files in os.walk(partition):
            for file in files:
                if file.endswith(".key"):
                    key_paths.append(os.path.join(root, file))
    except Exception as e:
        print(f"Error searching for key files in {partition}: {e}")

selected_key_option = select("Select a key file",key_paths+["Pick manually","New Key","Exit"])
if selected_key_option=="New Key":
    key_path=new()
elif selected_key_option=="Exit":
    sys.exit(0)
elif selected_key_option=="Pick manually":
    key_path = inquirer.filepath(message="Key path: ",default=desktop_path,
                                    validate=lambda x: x.endswith(".key")).execute()
else:
    key_path = selected_key_option

cryptoOperationChoice = select("Encrypt or decrypt?",["Encrypt","Decrypt & Encrypt","Decrypt","Exit"],default="Decrypt & Encrypt")

if cryptoOperationChoice=="Exit":
    sys.exit(0)

if len(sys.argv)<2:
    try:
        file_paths=[inquirer.filepath("File(s) to "+cryptoOperationChoice.lower(),default=desktop_path).execute()]
    except Exception as e:
        print(f"Error selecting file: {e}")
        sys.exit(1)

elif len(sys.argv)==2:
    if os.path.isdir(sys.argv[1]):
        try:
            file_paths = [os.path.join(root, file) for root, dirs, files in os.walk(sys.argv[1]) for file in files]
        except Exception as e:
            print(f"Error reading directory '{sys.argv[1]}': {e}")
            sys.exit(1)
    else:
        file_paths = sys.argv[1:]
elif len(sys.argv)>2:
    file_paths = sys.argv[1:]
else:
    print("No files provided. Exiting.")
    sys.exit(1)

if len(file_paths)>1:
    filenames=Cryptographer.decrypt_filenames(key_path,file_paths)
    selected_files = select("Select files to "+cryptoOperationChoice.lower(),filenames+["All"],default="All",multiselect=True)
    if selected_files==["All"]:
        pass
    else:
        file_paths=[file_paths[filenames.index(i)] for i in selected_files]

crypto = Cryptographer(key_path, file_paths)

if cryptoOperationChoice=="Encrypt":
    should_encrypt_filenames = select("Do you want to encrypt the filename(s)?",["Yes","No"],default="Yes")
    print("Encrypting...")
    crypto.encrypt_file(should_encrypt_filenames)
    sys.exit(0)
elif cryptoOperationChoice=="Decrypt":
    fn_encrypted = select("Do you want to decrypt filename(s)?",["Yes","No"],default="Yes")
    print("Decrypting...")
    crypto.decrypt_file(fn_encrypted)
    sys.exit(0)
else:
    crypto.decrypt_file() 
    print("File decrypted. Close the Notepad to encrypt the file.")
    try:
        os.startfile(file_paths)
    except Exception as e:
        print(f"Error opening file: {e}")
        sys.exit(1)
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
    crypto.encrypt_file()
    print("File encrypted.")
if inquirer.confirm("Open file?").execute():
    try:
        os.startfile(file_paths)
    except Exception as e:
        print(f"Error opening file: {e}")