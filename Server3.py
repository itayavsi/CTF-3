import os
import json
import sys
import textwrap
import base64



PROGRESS_FILE = "progress.json"

LEVEL_FLAGS = {
    1: "FLAG{level1_hidden_in_dotfile}",
    2: "FLAG{level2_udp_ping}",
    3: "FLAG{level3_every_7th_char}",
    4: "FLAG{level4_port_auth}",
    5: "FLAG{level5_eval_escape}",
    6: "FLAG{level6_hidden_route}",
    7: "FLAG{level7_reverse_protocol}",
    8: "FLAG{level8_injection_demo}",
    9: "FLAG{level9_proxy_log}",
    10: "FLAG{level10_cipher_puzzle}",
    11: "FLAG{level11_checksum_exploit}",
    15: "FLAG{level15_unpickle_trick}",
}

def save_progress(current_level, solved_levels):
    data = {"current_level": current_level, "solved": solved_levels}
    with open(PROGRESS_FILE, "w") as f:
        json.dump(data, f)

def load_progress():
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, "r") as f:
                data = json.load(f)
                return data.get("current_level", 1), set(data.get("solved", []))
        except Exception:
            pass
    return 1, set()

def input_prompt(prompt="> "):
    try:
        return input(prompt).strip()
    except EOFError:
        print("\nGoodbye.")
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nGoodbye.")
        sys.exit(0)

def require_flag(level, solved_levels):
    print("\nEnter the flag to mark level solved (or type 'back' to return):")
    while True:
        ans = input_prompt()
        if ans.lower() == "back":
            return False
        if ans == LEVEL_FLAGS[level]:
            print("Correct! Level solved.")
            solved_levels.add(level)
            return True
        else:
            print("Not correct. Try again or type 'back'.")

#############################################
# Level implementations (interactive minis) #
#############################################

def level1_interactive(solved_levels):
    print("\n=== Level 1: Hello, Root (file-discovery) ===")
    print("Goal: find the hidden dot-file containing the flag.\n")
    print("You are dropped into a directory. Try commands: ls, ls -a, cat <filename>, help, flag\n")
    files = {"readme.txt": "Welcome to Level 1.\nFind the hidden file.\n"}
    hidden = {".secret_hidden": LEVEL_FLAGS[1] + "\n"}
    while True:
        cmd = input_prompt()
        if cmd == "help":
            print("ls         - list visible files\nls -a      - list all files (including hidden)\ncat <file> - display file contents\nflag       - submit flag\nexit       - quit level")
        elif cmd == "ls":
            print("\n".join(sorted(files.keys())))
        elif cmd == "ls -a":
            all_files = list(files.keys()) + list(hidden.keys())
            print("\n".join(sorted(all_files)))
        elif cmd.startswith("cat "):
            fname = cmd.split(" ",1)[1]
            if fname in files:
                print(files[fname])
            elif fname in hidden:
                print(hidden[fname])
            else:
                print("No such file")
        elif cmd == "flag":
            solved = require_flag(1, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'help'.")

def level2_interactive(solved_levels):
    print("\n=== Level 2: Ping of Destiny (simulated UDP exchange) ===")
    print("Goal: speak to the UDP service in the right order to receive the flag.")
    print("Commands: send <MSG>, state, hint, flag, exit")
    state = {"stage": 0}
    while True:
        cmd = input_prompt()
        if cmd == "help" or cmd == "hint":
            print("You must send HELLO first, then PINGME. Example: send HELLO")
        elif cmd.startswith("send "):
            msg = cmd.split(" ",1)[1].strip()
            if state["stage"] == 0 and msg == "HELLO":
                state["stage"] = 1
                print("ACK")
            elif state["stage"] == 1 and msg == "PINGME":
                print("Service:", LEVEL_FLAGS[2])
                # prompt to submit flag
            else:
                print("Service: NOPE")
        elif cmd == "state":
            print("Internal stage:", state["stage"])
        elif cmd == "flag":
            solved = require_flag(2, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for guidance.")

def level3_interactive(solved_levels):
    print("\n=== Level 3: Hidden in Plain Sight (steganography) ===")
    print("Goal: extract the hidden flag in the text by taking every Nth character.\nCommands: show, extract <n>, hint, flag, exit")
    # create a long text with flag every 7th character
    base = "This is a long innocuous-looking text used for level 3. " * 20
    n = 7
    slot = list(base)
    flag = LEVEL_FLAGS[3]
    for i, ch in enumerate(flag):
        pos = (i+1)*n - 1
        if pos < len(slot):
            slot[pos] = ch
        else:
            slot.extend([" "]*(pos-len(slot)+1))
            slot[pos] = ch
    text = "".join(slot)
    while True:
        cmd = input_prompt()
        if cmd == "show":
            print(textwrap.fill(text[:500], width=80) + ("\n..."))
        elif cmd.startswith("extract "):
            try:
                nn = int(cmd.split()[1])
                extracted = "".join([text[i] for i in range(nn-1, len(text), nn)])
                print("Extracted:", extracted[:200])
                print("(If you see the flag, use 'flag' to submit.)")
            except Exception:
                print("Usage: extract <n> e.g. extract 7")
        elif cmd == "hint":
            print("Try extracting every 7th character (use 'extract 7').")
        elif cmd == "flag":
            solved = require_flag(3, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for guidance.")

def level4_interactive(solved_levels):
    print("\n=== Level 4: Port Authority (TCP password) ===")
    print("Goal: connect and send the correct password. Commands: connect, send <text>, hint, flag, exit")
    connected = False
    PASSWORD = "OPEN SESAME"
    while True:
        cmd = input_prompt()
        if cmd == "connect":
            connected = True
            print("Connected to 127.0.0.1:9004. Server: Welcome. Send password:")
        elif cmd.startswith("send "):
            if not connected:
                print("You need to 'connect' first.")
                continue
            tosend = cmd.split(" ",1)[1]
            if tosend == PASSWORD:
                print("Server:", LEVEL_FLAGS[4])
            else:
                print("Server: Authentication failed")
        elif cmd == "hint":
            print("Try the phrase that sounds like a magic-password (two words).")
        elif cmd == "flag":
            solved = require_flag(4, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for guidance.")

def level5_interactive(solved_levels):
    print("\n=== Level 5: Hello World, Goodbye Security (eval simulation) ===")
    print("Goal: the service evaluates small expressions. How could an attacker leak the flag?\n")
    print("To keep this playground safe, type a specially crafted payload to 'leak' the flag.")
    print("Commands: eval <expression>, hint, flag, exit\n")
    # For safety we DO NOT eval user input. We simulate a vulnerable service that would accept a payload 'leak_flag()'.
    while True:
        cmd = input_prompt()
        if cmd.startswith("eval "):
            expr = cmd.split(" ",1)[1].strip()
            if "leak_flag" in expr or "get_flag" in expr or "globals()['FLAG']" in expr:
                print("Service output:", LEVEL_FLAGS[5])
            else:
                print("Service output: Expression evaluated result (simulated).")
        elif cmd == "hint":
            print("Think: unsafe eval allows access to names/objects. A payload like leak_flag() would return the flag in this simulation.")
        elif cmd == "flag":
            solved = require_flag(5, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for guidance.")

def level6_interactive(solved_levels):
    print("\n=== Level 6: 404 Not Found (hidden HTTP path) ===")
    print("Goal: find the path that returns the flag. Commands: get <path>, hint, flag, exit\n")
    SECRET = "/.very_hidden_path_42"
    while True:
        cmd = input_prompt()
        if cmd.startswith("get "):
            path = cmd.split(" ",1)[1].strip()
            if path == SECRET:
                print("HTTP/1.1 200 OK\n\n" + LEVEL_FLAGS[6])
            else:
                print("HTTP/1.1 404 Not Found\n\nNot Found")
        elif cmd == "hint":
            print("The hidden path starts with a dot and ends with an underscore and 42.")
        elif cmd == "flag":
            solved = require_flag(6, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for help.")

def level7_interactive(solved_levels):
    print("\n=== Level 7: Socket to Me (reverse protocol) ===")
    print("Goal: send the reversed token to get the flag.\nCommands: send <token>, hint, flag, exit\n")
    SECRET_TOKEN = "supersecret"
    while True:
        cmd = input_prompt()
        if cmd.startswith("send "):
            token = cmd.split(" ",1)[1].strip()
            if token == SECRET_TOKEN[::-1]:
                print("Server:", LEVEL_FLAGS[7])
            else:
                print("Server: Wrong")
        elif cmd == "hint":
            print("The server expects the token backwards. Reverse the word 'supersecret'.")
        elif cmd == "flag":
            solved = require_flag(7, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for help.")

def level8_interactive(solved_levels):
    print("\n=== Level 8: Shell We Dance? (command-injection simulation) ===")
    print("Goal: craft a 'name' parameter that injects a command to read the flag file. This is a simulation; we won't run shell commands.")
    print("Commands: request name=<value>, hint, flag, exit\n")
    while True:
        cmd = input_prompt()
        if cmd.startswith("request "):
            body = cmd.split(" ",1)[1]
            if "cat /flag" in body or "cat __flag_file__" in body or ";" in body:
                print("Server output:")
                print(LEVEL_FLAGS[8])
            else:
                print("Server output: Hello " + body.split("=",1)[1])
        elif cmd == "hint":
            print("Try injecting a command separator like ';' or include 'cat __flag_file__' in the name value. (simulation)")
        elif cmd == "flag":
            solved = require_flag(8, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for help.")

def level9_interactive(solved_levels):
    print("\n=== Level 9: Man in the Middle (proxy log) ===")
    print("Goal: inspect the proxy.log to find a proxied request that included the flag.")
    print("Commands: curl /path, viewlog, hint, flag, exit\n")
    # build proxy.log content
    proxy_log = b"GET /secret HTTP/1.1\r\nHost: backend\r\n\r\n" + LEVEL_FLAGS[9].encode() + b"\n---\n"
    while True:
        cmd = input_prompt()
        if cmd.startswith("curl "):
            path = cmd.split(" ",1)[1]
            if path == "/secret":
                print("HTTP/1.1 200 OK\n\n" + LEVEL_FLAGS[9])
            else:
                print("HTTP/1.1 200 OK\n\nOK")
        elif cmd == "viewlog":
            print("proxy.log content:\n")
            print(proxy_log.decode(errors="replace"))
        elif cmd == "hint":
            print("The proxy logs forwarded requests. View the log to find the /secret request.")
        elif cmd == "flag":
            solved = require_flag(9, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for guidance.")

def level10_interactive(solved_levels):
    print("\n=== Level 10: The Ciphered Truth (symmetric cipher puzzle) ===")
    print("Goal: derive the passphrase hinted and use it to decrypt the ciphertext. Commands: show, decrypt <passphrase>, hint, flag, exit\n")
    # We'll use simple XOR with key derived from passphrase (sha-like simple hash)
    def simple_key(p):
        # deterministic bytes from passphrase (not cryptographically secure - for teaching)
        b = p.encode('utf-8')
        key = bytearray(16)
        for i in range(len(b)):
            key[i % 16] ^= b[i]
        return bytes(key)
    def xor_decrypt(key, data):
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    flag = LEVEL_FLAGS[10].encode()
    passphrase = "gama-essentials-2025"
    key = simple_key(passphrase)
    ciphertext = base64.b64encode(xor_decrypt(key, flag)).decode()
    print("Ciphertext (base64):", ciphertext)
    while True:
        cmd = input_prompt()
        if cmd == "show":
            print("ciphertext (copied above).")
        elif cmd.startswith("decrypt "):
            guess = cmd.split(" ",1)[1]
            k = simple_key(guess)
            try:
                dec = xor_decrypt(k, base64.b64decode(ciphertext))
                if dec.decode().startswith("FLAG{"):
                    print("Decryption result:", dec.decode())
                else:
                    print("Decryption result (invalid):", dec)
            except Exception as e:
                print("Decryption failed:", e)
        elif cmd == "hint":
            print("Passphrase starts with 'gama' and ends with '2025'.")
        elif cmd == "flag":
            solved = require_flag(10, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for help.")

def level11_interactive(solved_levels):
    print("\n=== Level 11: Kernel Panic (checksum puzzle) ===")
    print("Goal: send a 4-byte integer whose byte-sum mod 256 equals 0x2A (42). Commands: send <hex4bytes>, hint, flag, exit\n")
    def checksum(n):
        s = 0
        for b in n.to_bytes(4, 'big'):
            s = (s + b) & 0xFF
        return s
    while True:
        cmd = input_prompt()
        if cmd.startswith("send "):
            hx = cmd.split(" ",1)[1].strip()
            try:
                if hx.startswith("0x"): hx = hx[2:]
                if len(hx) != 8:
                    print("Provide 4 bytes as 8 hex chars, e.g. 0x01020304 or 0x0000002A")
                    continue
                val = int(hx,16)
                if checksum(val) == 0x2A:
                    print("Server:", LEVEL_FLAGS[11])
                else:
                    print("Server: Try again (checksum mismatch).")
            except Exception as e:
                print("Bad input:", e)
        elif cmd == "hint":
            print("Find bytes b0+b1+b2+b3 = 42 (mod 256). For example 0x0000002A works.")
        elif cmd == "flag":
            solved = require_flag(11, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for help.")

def level15_interactive(solved_levels):
    print("\n=== Level 15: Command & Conquer (unsafe-deserialization simulation) ===")
    print("Goal: craft a serialization payload that would cause the server to read a flag file. This is a simulation - do not run unsafe deserialization in real life.")
    print("Commands: send <payload>, hint, flag, exit\n")
    # We'll accept a payload string that contains 'OPEN_FLAG_FILE' sequence.
    while True:
        cmd = input_prompt()
        if cmd.startswith("send "):
            payload = cmd.split(" ",1)[1]
            if "OPEN_FLAG_FILE" in payload or "read_flag" in payload or "os.system('cat __flag_file__')" in payload:
                print("Server: Deserialized object triggered file-read. Output:")
                print(LEVEL_FLAGS[15])
            else:
                print("Server: Deserialization OK. No interesting behavior.")
        elif cmd == "hint":
            print("In real CTFs you'd craft a pickle/gadget payload. Here include the marker OPEN_FLAG_FILE in your payload string.")
        elif cmd == "flag":
            solved = require_flag(15, solved_levels)
            return solved
        elif cmd == "exit":
            return False
        else:
            print("Unknown command. Type 'hint' for help.")


LEVEL_FUNCTIONS = {
    1: level1_interactive,
    2: level2_interactive,
    3: level3_interactive,
    4: level4_interactive,
    5: level5_interactive,
    6: level6_interactive,
    7: level7_interactive,
    8: level8_interactive,
    9: level9_interactive,
    10: level10_interactive,
    11: level11_interactive,
    15: level15_interactive,
}

def main():
    print("Welcome to the single-file CTF game (Levels 1-11, 15).")
    print("Progress will be saved in", PROGRESS_FILE)
    current_level, solved_levels = load_progress()
    # levels order: 1..11 then 15
    order = [1,2,3,4,5,6,7,8,9,10,11,15]
    # find starting index
    try:
        idx = order.index(current_level)
    except ValueError:
        idx = 0
        current_level = order[0]
    while idx < len(order):
        lvl = order[idx]
        print(f"\n=== AVAILABLE LEVEL: {lvl} === (Solved levels: {sorted(list(solved_levels))})")
        print("Type 'play' to start the level, 'skip' to skip (only for testing), 'quit' to exit, or 'reset' to restart progress.")
        cmd = input_prompt()
        if cmd == "play":
            solved = LEVEL_FUNCTIONS[lvl](solved_levels)
            if solved:
                # advance to next level
                idx += 1
                if idx < len(order):
                    current_level = order[idx]
                    save_progress(current_level, list(solved_levels))
                    print(f"Next level unlocked: {current_level}")
                else:
                    print("Congratulations! You completed all included levels.")
                    save_progress(order[-1], list(solved_levels))
                    break
            else:
                print("Returning to main menu. You can try the level again later.")
                save_progress(lvl, list(solved_levels))
        elif cmd == "skip":
            print("Skipping (test mode). Marking level solved.")
            solved_levels.add(lvl)
            idx += 1
            if idx < len(order):
                current_level = order[idx]
                save_progress(current_level, list(solved_levels))
        elif cmd == "reset":
            print("Resetting progress...")
            solved_levels.clear()
            idx = 0
            current_level = order[0]
            save_progress(current_level, list(solved_levels))
        elif cmd == "quit":
            print("Exiting. Progress saved.")
            save_progress(lvl, list(solved_levels))
            break
        else:
            print("Unknown command. Type 'play', 'skip', 'reset', or 'quit'.")

if __name__ == "__main__":
    main()
    

