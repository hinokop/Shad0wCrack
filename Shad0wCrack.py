import os
import sys
import time
import pikepdf
from tqdm import tqdm
import argparse
from colorama import Fore, Style, init
import psutil
import subprocess
import hashlib
import tempfile
import gzip
from multiprocessing import Pool, Manager, cpu_count

# Initialize colorama
init(autoreset=True)

def ensure_optimized_mode():
    if not sys.flags.optimize:
        print("You forgot the -O flag. Shad0wCrack is now restarting your Script with the -O flag")
        time.sleep(1)
        os.execv(sys.executable, [sys.executable, "-O"] + sys.argv)

ensure_optimized_mode()

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

def open_wordlist(wordlist: str):
    return gzip.open(wordlist, 'rt', encoding='utf-8', errors='ignore') if wordlist.endswith('.gz') else open(wordlist, 'r', encoding='utf-8', errors='ignore')

def generate_passwords(wordlist_lines, pdf_path):
    """Generates password attempts."""
    for password in wordlist_lines:
        yield (pdf_path, password)

def check_pdf_password_worker(args):
    """Check PDF password. This function is run by the main process to avoid issues with shared state."""
    pdf_path, password = args
    try:
        with pikepdf.open(pdf_path, password=password):
            return password
    except pikepdf.PasswordError:
        return None
    except pikepdf._qpdf.PasswordError:
        return None
    except Exception as e:
        return None

def brute_force_pdf(pdf_path: str, wordlist: str, output_file: str = None, auto_open: bool = False) -> str:
    start_time = time.time()
    process = psutil.Process(os.getpid())

    with open_wordlist(wordlist) as words:
        if sum(1 for _ in words) == 0:
            print(Fore.RED + "[!] Wordlist file is missing or empty.")
            return ""

        words.seek(0)
        wordlist_lines = [line.strip() for line in words]  # Convert wordlist to a list to avoid exhausting the iterator

        progress_file = f"{os.path.basename(pdf_path)}.progress"
        start_line = load_progress(progress_file)

        if start_line > 0:
            print(Fore.YELLOW + f"[+] Resuming from line {start_line + 1} in the wordlist.")

        wordlist_lines = wordlist_lines[start_line:]  # Skip lines based on progress

        total_words = len(wordlist_lines)

        with Manager() as manager:
            found_password = manager.Value('found_password', None)

            pool = Pool(processes=cpu_count())
            try:
                for index, password in enumerate(tqdm(wordlist_lines, total=total_words, unit="word", ncols=100, colour="green", leave=False, mininterval=0.5)):
                    result = check_pdf_password_worker((pdf_path, password))  # Move password checking to the main process

                    if result:
                        found_password.value = result
                        break

                    if index % 1000 == 0:
                        save_progress(progress_file, index + start_line)

                pool.close()
                pool.join()
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                print(Fore.RED + "\n[!] Process interrupted by user.")
                return ""

            if found_password.value:
                handle_success(pdf_path, wordlist, found_password.value, output_file, auto_open, start_time, time.time(), index + 1 + start_line, process)
                remove_progress(progress_file)
                return found_password.value

    handle_failure(pdf_path, wordlist, output_file, start_time, time.time(), total_words, process)
    return ""

def skip_words(word_file, count: int):
    for _ in range(count):
        word_file.readline()

def load_progress(progress_file: str) -> int:
    if os.path.exists(progress_file):
        with open(progress_file, 'r') as f:
            return int(f.read().strip())
    return 0

def save_progress(progress_file: str, current_line: int):
    with open(progress_file, 'w') as f:
        f.write(str(current_line))

def remove_progress(progress_file: str):
    if os.path.exists(progress_file):
        os.remove(progress_file)

def handle_success(pdf_path: str, wordlist: str, password: str, output_file: str, auto_open: bool, start_time: float, end_time: float, total_attempts: int, process):
    report_content = generate_report(pdf_path, wordlist, True, password, start_time, end_time, total_attempts, process)
    print(Fore.GREEN + Style.BRIGHT + f"[+] Password found: {password}")
    print_report(report_content)

    if output_file:
        save_report_to_file(report_content, output_file)

    if auto_open:
        open_pdf(pdf_path, password)

def handle_failure(pdf_path: str, wordlist: str, output_file: str, start_time: float, end_time: float, total_attempts: int, process):
    report_content = generate_report(pdf_path, wordlist, False, None, start_time, end_time, total_attempts, process)
    print(Fore.RED + "[!] Password not found.")
    print_report(report_content)

    if output_file:
        save_report_to_file(report_content, output_file)

def open_pdf(pdf_path: str, password: str):
    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp_pdf:
            temp_pdf_path = temp_pdf.name
            with pikepdf.open(pdf_path, password=password) as pdf:
                pdf.save(temp_pdf_path)

        open_file(temp_pdf_path)

        time.sleep(2)
        os.remove(temp_pdf_path)
    except Exception as e:
        print(Fore.RED + f"Failed to open the PDF file: {e}" + Style.RESET_ALL)

def open_file(file_path: str):
    if sys.platform == "win32":
        subprocess.run(["start", "", file_path], shell=True)
    elif sys.platform == "darwin":
        subprocess.run(["open", file_path])
    else:
        subprocess.run(["xdg-open", file_path])

def generate_report(pdf_path: str, wordlist: str, success: bool, password: str, start_time: float, end_time: float, total_attempts: int, process) -> str:
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

def print_report(report_content: str):
    print(Fore.CYAN + report_content)

def save_report_to_file(report_content: str, output_file: str):
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
  python {os.path.basename(__file__)} -f protected.pdf -p wordlist.txt
  python {os.path.basename(__file__)} -f protected.pdf -p wordlist.txt -O output.txt
  python {os.path.basename(__file__)} --hash="" -p wordlist.txt -O output.txt
"""
    print(Fore.YELLOW + help_text + Style.RESET_ALL)

def crack_hash(hash_str: str, wordlist: str, output_file: str = None) -> str:
    hash_type = determine_hash_type(hash_str)
    if not hash_type:
        print(Fore.RED + "[!] Unsupported or unrecognized hash type.")
        return ""

    start_time = time.time()

    with open_wordlist(wordlist) as words:
        for password in tqdm(words, unit="word", ncols=100, colour="green", leave=False, mininterval=0.5):
            password = password.strip()
            hashed_password = getattr(hashlib, hash_type)(password.encode()).hexdigest()
            if hashed_password == hash_str:
                end_time = time.time()
                time_taken = end_time - start_time
                sys.stdout.flush()
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
    hash_length_to_type = {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512',
        80: 'ripemd320',
        48: 'tiger192,3',
        8: 'crc8',
    }
    return hash_length_to_type.get(len(hash_str), None)

if __name__ == "__main__":
    display_message()

    parser = argparse.ArgumentParser(description="Brute-force a password-protected PDF file.")
    parser.add_argument("-f", "--file", type=str, required=False, help="Path to the PDF file.")
    parser.add_argument("-p", "--password-list", type=str, required=False, help="Path to the wordlist file.")  # Fixed the argument definition
    parser.add_argument("-O", "--output", type=str, help="Save the report to the specified file.")
    parser.add_argument("--hash", type=str, help="Hash to be cracked.")
    parser.add_argument("-a", "--auto-open", action="store_true", help="Automatically open the PDF if the password is found.")

    if len(sys.argv) == 1:
        show_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.hash:
        crack_hash(args.hash, args.password_list, args.output)
    elif args.file and args.password_list:  # Updated to match the corrected argument
        brute_force_pdf(args.file, args.password_list, args.output, args.auto_open)
    else:
        show_help()
