import os
import sys
import time

def ensure_optimized_mode():
    if not sys.flags.optimize:
        print("You forgot the -O flag. Shad0wCrack is now restarting your Script with the -O flag")
        time.sleep(2)  # Wait for 2 seconds to display the message
        os.execv(sys.executable, [sys.executable, "-O"] + sys.argv)

ensure_optimized_mode()

import pikepdf
from tqdm import tqdm
import argparse
from colorama import Fore, Style, init
import psutil
import subprocess
import hashlib
import tempfile 

# Initialize colorama
init(autoreset=True)

def display_message():
    print(Fore.RED + Style.BRIGHT + """
      ______  _               _  ___           
     / / ___|| |__   __ _  __| |/ _ \__      __
    / /\___ \| '_ \ / _ |/ _ | | | \ \ /\ / /
 _ / /  ___) | | | | (_| | (_| | |_| |\ V  V / 
(_)_/  |____/|_| |_|\__,_|\__,_|\___/  \_/\_/  
                                                    
"The Shad0ws betray you, because they belong to me"
                Developed by ./Shad0w
    """ + Style.RESET_ALL)

def check_pdf_password(pdf_path: str, password: str) -> bool:
   
    try:
        with pikepdf.open(pdf_path, password=password):
            return True
    except pikepdf.PasswordError:
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


def brute_force_pdf(pdf_path: str, wordlist: str, output_file: str = None, auto_open: bool = False) -> str:
   
    start_time = time.time()
    process = psutil.Process(os.getpid())

    if not os.path.isfile(wordlist) or os.path.getsize(wordlist) == 0:
        print(Fore.RED + "[!] Wordlist file is missing or empty.")
        return ""

    progress_file = f"{os.path.basename(pdf_path)}.progress"
    start_line = 0
    if os.path.exists(progress_file):
        with open(progress_file, 'r') as f:
            start_line = int(f.read().strip())
        print(Fore.YELLOW + f"[+] Resuming from line {start_line + 1} in the wordlist.")

    with open(wordlist, 'r') as words:
        total_words = sum(1 for _ in words)
        words.seek(0)
        
        for _ in range(start_line):
            words.readline()

        save_interval = min(1000, total_words // 10)

        for index, password in enumerate(tqdm(words, total=total_words, initial=start_line, unit="word", ncols=100, colour="green")):
            password = password.strip('\n\r')
            if check_pdf_password(pdf_path, password):
                end_time = time.time()
                total_attempts = index + 1 + start_line
                report_content = generate_report(pdf_path, wordlist, True, password, start_time, end_time, total_attempts, process)
                
                print(Fore.GREEN + Style.BRIGHT + f"[+] Password found: {password}")
                print_report(report_content)

                if output_file:
                    save_report_to_file(report_content, output_file)
                
                if auto_open:
                    open_pdf(pdf_path, password)

                if os.path.exists(progress_file):
                    os.remove(progress_file)
                return password

            if (index + start_line) % save_interval == 0:
                with open(progress_file, 'w') as f:
                    f.write(str(index + start_line))

    end_time = time.time()
    total_attempts = total_words
    report_content = generate_report(pdf_path, wordlist, False, None, start_time, end_time, total_attempts, process)
    
    print(Fore.RED + "[!] Password not found.")
    print_report(report_content)
    
    if output_file:
        save_report_to_file(report_content, output_file)
    
    return ""

def open_pdf(pdf_path: str, password: str):

    try:
        # Bypass PDF-Viewer Security by creating a TempFile ;)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp_pdf:
            temp_pdf_path = temp_pdf.name

            # Removing the PW by creating a new PDF without one.
            with pikepdf.open(pdf_path, password=password) as pdf:
                pdf.save(temp_pdf_path)

        # Open the bypassed PDF on any Sys
        if sys.platform == "win32":
            subprocess.run(["start", "", temp_pdf_path], shell=True)
        elif sys.platform == "darwin":
            subprocess.run(["open", temp_pdf_path])
        else:  # Assume Linux or other Unix-like OS
            subprocess.run(["xdg-open", temp_pdf_path])

        # (optional) delete or save tmp file
        time.sleep(2)  
        os.remove(temp_pdf_path)

    except Exception as e:
        print(Fore.RED + f"Failed to open the PDF file: {e}" + Style.RESET_ALL)

def generate_report(pdf_path, wordlist, success, password, start_time, end_time, total_attempts, process):
   
    time_taken = end_time - start_time
    words_per_second = total_attempts / time_taken
    memory_info = process.memory_info()

    report_content = f"""
./Shad0wCrack Report
===================
PDF File: {pdf_path}
Wordlist: {wordlist}
Total Attempts: {total_attempts}
Time Taken: {time.strftime('%H:%M:%S', time.gmtime(time_taken))}
Attempts per Second: {words_per_second:.2f}
Peak Memory Usage: {memory_info.rss / (1024 * 1024):.2f} MB

Result
------
Password Found: {success}
"""
    if success:
        report_content += f"Password: {password}\n"
    else:
        report_content += "Password: Not Found\n"

    return report_content

def print_report(report_content):
   
    print(Fore.CYAN + report_content)

def save_report_to_file(report_content, output_file):
   
    with open(output_file, 'w') as report_file:
        report_file.write(report_content)
    print(Fore.CYAN + f"\n[+] Report saved to file: {output_file}")

def show_help():
    help_text = f"""
Usage: python {os.path.basename(__file__)} -f <path_to_pdf> -p <path_to_wordlist> [-O <output_file>]

Options:
  -f, --file           Path to the PDF file.
  -p, --password-list  Path to the wordlist file.
  -O, --output         (Optional) Save the report to the specified file.
  --hash="hash here"   Hash Cracking Module

Example:
  python script_name.py -f protected.pdf -p wordlist.txt
  python script_name.py -f protected.pdf -p wordlist.txt -O output.txt
  python script_name.py --hash="" -p wordlist.txt -O output.txt
"""
    print(Fore.YELLOW + help_text + Style.RESET_ALL)

import hashlib

def crack_hash(hash_str: str, wordlist: str, output_file: str = None) -> str:
    hash_type = determine_hash_type(hash_str)
    if not hash_type:
        print(Fore.RED + "[!] Unsupported or unrecognized hash type.")
        return ""

    start_time = time.time()    
    
    with open(wordlist, 'r') as words:
        for password in tqdm(words, unit="word", ncols=100, colour="green", leave=False):
            password = password.strip()
            hashed_password = getattr(hashlib, hash_type)(password.encode()).hexdigest()
            if hashed_password == hash_str:
                end_time = time.time()
                time_taken = end_time - start_time 
                sys.stdout.flush()  # flushout progress bar for clarity
                print(Fore.GREEN + Style.BRIGHT + f"\n[+] Hash cracked! Password: {password}")
                print(Fore.CYAN + f"Hash: {hash_str}")
                print(Fore.CYAN + f"Hash Type: {hash_type}")
                print(Fore.CYAN + f"Password: {password}" + Style.RESET_ALL)
                print(Fore.CYAN + f"Time Taken: {time_taken:.2f} seconds")

                if output_file:
                    with open(output_file, 'w') as report_file:
                        report_file.write(f"Hash: {hash_str}\n")
                        report_file.write(f"Password: {password}\n")
                        report_file.write(f"Hash Type: {hash_type}\n")
                        report_file.write(f"Time Taken: {time_taken:.2f} seconds\n")
                return password

    print(Fore.RED + "[!] Failed to crack the hash.")
    return ""


def determine_hash_type(hash_str: str) -> str:
    """
    Determine the hash type based on the length of the hash string.
    """
    hash_length_to_type = {
        32: 'md5',                             # 32 characters
        40: 'sha1',                            # 40 characters
        56: 'sha224',                          # 56 characters
        64: 'sha256',                          # 64 characters
        96: 'sha384',                          # 96 characters
        128: 'sha512',                         # 128 characters
        80: 'ripemd320',                       # 80 characters
        48: 'tiger192,3',                      # 48 characters
        8: 'crc8',                             # 8 characters
    }
    return hash_length_to_type.get(len(hash_str), None)

if __name__ == "__main__":
    display_message()  # Display the custom message

    # Setup command-line argument parsing
    parser = argparse.ArgumentParser(description="Brute-force a password-protected PDF file.")
    parser.add_argument("-f", "--file", type=str, required=False, help="Path to the PDF file.")
    parser.add_argument("-p", "--password-list", type=str, required=False, help="Path to the wordlist file.")
    parser.add_argument("-O", "--output", type=str, help="Save the report to the specified file.")
    parser.add_argument("--hash", type=str, help="Hash to be cracked.")
    parser.add_argument("-a", "--auto-open", action="store_true", help="Automatically open the PDF if the password is found.")

    if len(sys.argv) == 1:
        show_help()
        sys.exit(1)

    args = parser.parse_args()

    # Use the command-line arguments for the file paths
    pdf_path = args.file
    wordlist = args.password_list
    output_file = args.output
    auto_open = args.auto_open

    if args.hash:
        crack_hash(args.hash, wordlist, output_file)
    elif pdf_path and wordlist:
        brute_force_pdf(pdf_path, wordlist, output_file, auto_open)
    else:
        show_help()