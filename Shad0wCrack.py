import pikepdf
from tqdm import tqdm
import argparse
from colorama import Fore, Style, init
import os
import sys
import time
import psutil

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
    """
    Attempt to open a PDF file with the provided password using pikepdf.
    Returns True if the password is correct, False otherwise.
    """
    try:
        with pikepdf.open(pdf_path, password=password):
            return True
    except pikepdf.PasswordError:
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def brute_force_pdf(pdf_path: str, wordlist: str, output_file: str = None) -> str:
    """
    Brute-force the password of a PDF file using a wordlist.
    Returns the correct password if found, otherwise returns an empty string.
    Saves progress to resume later if interrupted.
    Generates an advanced report after completion.
    Optionally writes the report to a specified file.
    """
    # Initialize start time and process
    start_time = time.time()
    process = psutil.Process(os.getpid())

    # Check if wordlist file exists and is not empty
    if not os.path.isfile(wordlist) or os.path.getsize(wordlist) == 0:
        print(Fore.RED + "[!] Wordlist file is missing or empty.")
        return ""

    # Determine the progress file name based on the PDF file name
    progress_file = f"{os.path.basename(pdf_path)}.progress"

    # Check if there is a saved progress file to resume from
    start_line = 0
    if os.path.exists(progress_file):
        with open(progress_file, 'r') as f:
            start_line = int(f.read().strip())
        print(Fore.YELLOW + f"[+] Resuming from line {start_line + 1} in the wordlist.")

    with open(wordlist, 'r') as words:
        total_words = len(words.readlines())
        words.seek(0)
        
        # Skip to the last attempted password if resuming
        for _ in range(start_line):
            words.readline()

        for index, password in enumerate(tqdm(words, total=total_words, initial=start_line, unit="word", ncols=100, colour="green")):
            password = password.strip()
            if check_pdf_password(pdf_path, password):
                end_time = time.time()
                total_attempts = index + 1 + start_line
                report_content = generate_report(pdf_path, wordlist, True, password, start_time, end_time, total_attempts, process)
                
                print(Fore.GREEN + Style.BRIGHT + f"[+] Password found: {password}")
                print_report(report_content)

                if output_file:
                    save_report_to_file(report_content, output_file)
                
                # Remove progress file upon success
                if os.path.exists(progress_file):
                    os.remove(progress_file)
                return password

            # Save progress every 1000 attempts to reduce I/O overhead
            if (index + start_line) % 1000 == 0:
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

def generate_report(pdf_path, wordlist, success, password, start_time, end_time, total_attempts, process):
    """
    Generates a report summarizing the brute-force attempt.
    """
    time_taken = end_time - start_time
    words_per_second = total_attempts / time_taken
    memory_info = process.memory_info()

    report_content = f"""
Brute-force Report
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
    """
    Prints the report content to the terminal.
    """
    print(Fore.CYAN + report_content)

def save_report_to_file(report_content, output_file):
    """
    Saves the report content to the specified file.
    """
    with open(output_file, 'w') as report_file:
        report_file.write(report_content)
    print(Fore.CYAN + f"\n[+] Report saved to file: {output_file}")

def show_help():
    help_text = """
Usage: python script_name.py -f <path_to_pdf> -p <path_to_wordlist> [-O <output_file>]

Options:
  -f, --file           Path to the PDF file.
  -p, --password-list  Path to the wordlist file.
  -O, --output         (Optional) Save the report to the specified file.

Example:
  python script_name.py -f protected.pdf -p wordlist.txt
  python script_name.py -f protected.pdf -p wordlist.txt -O output.txt
"""
    print(Fore.YELLOW + help_text + Style.RESET_ALL)

if __name__ == "__main__":
    display_message()  # Display the custom message

    # Setup command-line argument parsing
    parser = argparse.ArgumentParser(description="Brute-force a password-protected PDF file.")
    parser.add_argument("-f", "--file", type=str, required=False, help="Path to the PDF file.")
    parser.add_argument("-p", "--password-list", type=str, required=False, help="Path to the wordlist file.")
    parser.add_argument("-O", "--output", type=str, help="Save the report to the specified file.")

    if len(sys.argv) == 1:
        show_help()
        sys.exit(1)

    args = parser.parse_args()

    # Use the command-line arguments for the file paths
    pdf_path = args.file
    wordlist = args.password_list
    output_file = args.output

    if pdf_path and wordlist:
        brute_force_pdf(pdf_path, wordlist, output_file)
    else:
        show_help()
