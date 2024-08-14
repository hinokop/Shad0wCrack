import os
import sys
import time
import pikepdf
import zipfile
import rarfile
from tqdm import tqdm
import argparse
from colorama import Fore, Style, init
import psutil
import subprocess
import hashlib
import tempfile
import gzip
import smtplib
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama
init(autoreset=True)

class Shad0wCrack:
    def __init__(self, pdf_path=None, zip_path=None, rar_path=None, wordlist=None, output_file=None, auto_open=False, hash_str=None, notify_email=None, email_password=None):
        self.pdf_path = pdf_path
        self.zip_path = zip_path
        self.rar_path = rar_path
        self.wordlist = wordlist
        self.output_file = output_file
        self.auto_open = auto_open
        self.hash_str = hash_str
        self.notify_email = notify_email
        self.email_password = email_password
        self.process = psutil.Process(os.getpid())
        self.progress_file = self.get_progress_file()

    def get_progress_file(self):
        if self.pdf_path:
            return f"{os.path.basename(self.pdf_path)}.progress"
        elif self.zip_path:
            return f"{os.path.basename(self.zip_path)}.progress"
        elif self.rar_path:
            return f"{os.path.basename(self.rar_path)}.progress"
        else:
            return None

    @staticmethod
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

    @staticmethod
    def open_wordlist(wordlist):
        return gzip.open(wordlist, 'rt', encoding='utf-8', errors='ignore') if wordlist.endswith('.gz') else open(wordlist, 'r', encoding='utf-8', errors='ignore')

    def check_pdf_password(self, password):
        try:
            with open(os.devnull, 'w') as devnull:
                with pikepdf.open(self.pdf_path, password=password):
                    return True
        except pikepdf.PasswordError:
            return False
        except Exception:
            return False

    def check_zip_password(self, password):
        try:
            with open(os.devnull, 'w') as devnull:
                with zipfile.ZipFile(self.zip_path) as zf:
                    zf.extractall(pwd=bytes(password, 'utf-8'))
                    return True
        except (RuntimeError, zipfile.BadZipFile):
            return False
        except Exception:
            return False

    def check_rar_password(self, password):
        try:
            with open(os.devnull, 'w') as devnull:
                with rarfile.RarFile(self.rar_path) as rf:
                    rf.extractall(pwd=bytes(password, 'utf-8'))
                    return True
        except rarfile.RarWrongPassword:
            return False
        except Exception:
            return False

    def brute_force(self):
        start_time = time.time()

        if not self.wordlist:
            print(Fore.RED + "[!] Wordlist file is missing.")
            return ""

        with self.open_wordlist(self.wordlist) as words:
            total_words = sum(1 for _ in words)
            if total_words == 0:
                print(Fore.RED + "[!] Wordlist file is empty.")
                return ""

            words.seek(0)
            start_line = self.load_progress()

            if start_line > 0:
                print(Fore.YELLOW + f"[+] Resuming from line {start_line + 1} in the wordlist.")

            self.skip_words(words, start_line)

            for index, password in enumerate(tqdm(words, total=total_words, initial=start_line, unit="word", ncols=100, colour="green", leave=False, mininterval=0.5)):
                password = password.strip()
                if (self.pdf_path and self.check_pdf_password(password)) or \
                   (self.zip_path and self.check_zip_password(password)) or \
                   (self.rar_path and self.check_rar_password(password)):
                    self.handle_success(password, start_time, time.time(), index + 1 + start_line)
                    self.remove_progress()
                    return password

                if (index + start_line) % 1000 == 0:
                    self.save_progress(index + start_line)

        self.handle_failure(start_time, time.time(), total_words)
        return ""

    def skip_words(self, word_file, count):
        for _ in range(count):
            word_file.readline()

    def load_progress(self):
        if self.progress_file and os.path.exists(self.progress_file):
            with open(self.progress_file, 'r') as f:
                return int(f.read().strip())
        return 0

    def save_progress(self, current_line):
        if self.progress_file:
            with open(self.progress_file, 'w') as f:
                f.write(str(current_line))

    def remove_progress(self):
        if self.progress_file and os.path.exists(self.progress_file):
            os.remove(self.progress_file)

    def handle_success(self, password, start_time, end_time, total_attempts):
        report_content = self.generate_report(True, password, start_time, end_time, total_attempts)
        print(Fore.GREEN + Style.BRIGHT + f"[+] Password found: {password}")
        self.print_report(report_content)

        if self.output_file:
            self.save_report_to_file(report_content)

        if self.auto_open:
            self.open_file(password)

        if self.notify_email:
            self.send_email_notification(True, password)

    def handle_failure(self, start_time, end_time, total_attempts):
        report_content = self.generate_report(False, None, start_time, end_time, total_attempts)
        print(Fore.RED + "[!] Password not found.")
        self.print_report(report_content)

        if self.output_file:
            self.save_report_to_file(report_content)

        if self.notify_email:
            self.send_email_notification(False)

    def open_file(self, password):
        if self.pdf_path:
            self.open_pdf(password)
        elif self.zip_path:
            self.open_zip(password)
        elif self.rar_path:
            self.open_rar(password)

    def open_pdf(self, password):
        try:
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp_pdf:
                temp_pdf_path = temp_pdf.name
                with pikepdf.open(self.pdf_path, password=password) as pdf:
                    pdf.save(temp_pdf_path)

            self._open_file(temp_pdf_path)

            time.sleep(2)
            os.remove(temp_pdf_path)
        except Exception as e:
            print(Fore.RED + f"Failed to open the PDF file: {e}" + Style.RESET_ALL)

    def open_zip(self, password):
        try:
            with zipfile.ZipFile(self.zip_path) as zf:
                zf.extractall(pwd=bytes(password, 'utf-8'))
            print(Fore.GREEN + "[+] ZIP file extracted successfully.")
        except Exception as e:
            print(Fore.RED + f"Failed to open the ZIP file: {e}" + Style.RESET_ALL)

    def open_rar(self, password):
        try:
            with rarfile.RarFile(self.rar_path) as rf:
                rf.extractall(pwd=bytes(password, 'utf-8'))
            print(Fore.GREEN + "[+] RAR file extracted successfully.")
        except Exception as e:
            print(Fore.RED + f"Failed to open the RAR file: {e}" + Style.RESET_ALL)

    @staticmethod
    def _open_file(file_path):
        if sys.platform == "win32":
            subprocess.run(["start", "", file_path], shell=True)
        elif sys.platform == "darwin":
            subprocess.run(["open", file_path])
        else:
            subprocess.run(["xdg-open", file_path])

    def generate_report(self, success, password, start_time, end_time, total_attempts):
        time_taken = end_time - start_time
        words_per_second = total_attempts / time_taken
        memory_info = self.process.memory_info()

        report_content = f"""
        ./Shad0wCrack Report
        ===================
        File: {self.pdf_path or self.zip_path or self.rar_path}
        Wordlist: {self.wordlist}
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

    @staticmethod
    def print_report(report_content):
        print(Fore.CYAN + report_content)

    def save_report_to_file(self, report_content):
        with open(self.output_file, 'w') as report_file:
            report_file.write(report_content)
        print(Fore.CYAN + f"\n[+] Report saved to file: {self.output_file}")

    def send_email_notification(self, success, password=None):
        msg_body = f"The password {'was' if success else 'was not'} found."
        if success:
            msg_body += f" The password is: {password}"

        msg = MIMEText(msg_body)
        msg['Subject'] = 'Shad0wCrack Task Completion'
        msg['From'] = self.notify_email
        msg['To'] = self.notify_email

        try:
            with smtplib.SMTP('smtp.example.com') as server:
                server.login(self.notify_email, self.email_password)
                server.sendmail(self.notify_email, self.notify_email, msg.as_string())
            print(Fore.GREEN + "[+] Email notification sent successfully.")
        except Exception as e:
            print(Fore.RED + f"Failed to send email notification: {e}" + Style.RESET_ALL)

    def crack_hash(self):
        hash_type = self.determine_hash_type()
        if not hash_type:
            print(Fore.RED + "[!] Unsupported or unrecognized hash type.")
            return ""

        start_time = time.time()

        with self.open_wordlist(self.wordlist) as words:
            for password in tqdm(words, unit="word", ncols=100, colour="green", leave=False, mininterval=0.5):
                password = password.strip()
                hashed_password = getattr(hashlib, hash_type)(password.encode()).hexdigest()
                if hashed_password == self.hash_str:
                    end_time = time.time()
                    time_taken = end_time - start_time
                    sys.stdout.flush()
                    print(Fore.GREEN + Style.BRIGHT + f"\n[+] Hash cracked! Password: {password}")
                    print(Fore.CYAN + f"Hash: {self.hash_str}")
                    print(Fore.CYAN + f"Hash Type: {hash_type}")
                    print(Fore.CYAN + f"Password: {password}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"Time Taken: {time_taken:.2f} seconds")

                    if self.output_file:
                        with open(self.output_file, 'w') as report_file:
                            report_file.write(f"Hash: {self.hash_str}\n")
                            report_file.write(f"Password: {password}\n")
                            report_file.write(f"Hash Type: {hash_type}\n")
                            report_file.write(f"Time Taken: {time_taken:.2f} seconds\n")
                    return password

        print(Fore.RED + "[!] Failed to crack the hash.")
        return ""

    def determine_hash_type(self):
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
        return hash_length_to_type.get(len(self.hash_str), None)

    def generate_wordlist(self, pattern, min_length, max_length):
        # This is a placeholder for a custom wordlist generator logic based on the pattern
        # Example: pattern could be a date range, character set, etc.
        # For simplicity, we'll generate words with letters and numbers
        import itertools
        from string import ascii_lowercase, digits

        characters = ascii_lowercase + digits
        with open(self.output_file or "custom_wordlist.txt", "w") as f:
            for length in range(min_length, max_length + 1):
                for word in itertools.product(characters, repeat=length):
                    f.write("".join(word) + "\n")
        print(Fore.GREEN + f"[+] Custom wordlist generated with pattern '{pattern}'.")

if __name__ == "__main__":
    Shad0wCrack.display_message()

    parser = argparse.ArgumentParser(description="Brute-force a password-protected PDF, ZIP, or RAR file.")
    parser.add_argument("-f", "--file", type=str, required=False, help="Path to the PDF file.")
    parser.add_argument("-z", "--zip", type=str, required=False, help="Path to the ZIP file.")
    parser.add_argument("-r", "--rar", type=str, required=False, help="Path to the RAR file.")
    parser.add_argument("-p", "--password-list", type=str, required=False, help="Path to the wordlist file.")
    parser.add_argument("-O", "--output", type=str, help="Save the report to the specified file.")
    parser.add_argument("--hash", type=str, help="Hash to be cracked.")
    parser.add_argument("-a", "--auto-open", action="store_true", help="Automatically open the file if the password is found.")
    parser.add_argument("-e", "--email", type=str, help="Email to notify upon completion.")
    parser.add_argument("--email-password", type=str, help="Password for the email account.")
    parser.add_argument("--generate-wordlist", action="store_true", help="Generate a custom wordlist.")
    parser.add_argument("--pattern", type=str, help="Pattern for wordlist generation.")
    parser.add_argument("--min-length", type=int, help="Minimum length for wordlist generation.", default=1)
    parser.add_argument("--max-length", type=int, help="Maximum length for wordlist generation.", default=6)

    args = parser.parse_args()

    # Validate email and password only if the email option is provided
    if args.email and not args.email_password:
        print(Fore.RED + "[!] Email specified but email password not provided.")
        sys.exit(1)

    shad0w_crack = Shad0wCrack(
        pdf_path=args.file,
        zip_path=args.zip,
        rar_path=args.rar,
        wordlist=args.password_list,
        output_file=args.output,
        auto_open=args.auto_open,
        hash_str=args.hash,
        notify_email=args.email,
        email_password=args.email_password
    )

    if args.generate_wordlist and args.pattern:
        shad0w_crack.generate_wordlist(args.pattern, args.min_length, args.max_length)
    elif args.hash:
        shad0w_crack.crack_hash()
    elif args.file or args.zip or args.rar:
        shad0w_crack.brute_force()
    else:
        Shad0wCrack.show_help()
