"""
CTF Simulation Server Module
============================
A comprehensive CTF challenge server implementing 10 different security stages
"""

import socket
import threading
import json
import base64
import os
import time
import random
import string
from flask import Flask, request, render_template_string
from datetime import datetime
import subprocess
import hashlib

class CTFServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.flags = {
            'stage1': 'CTF{h0st5_f1l3_m4st3r}',
            'stage2': 'CTF{l0g_4n4ly515_pr0}',
            'stage3': 'SecretPart123',
            'stage4': 'CTF{1nj3ct10n_h4ck3r}',
            'stage5': 'CTF{st3g4n0_n1nj4}',
            'stage6': 'CTF{c1ph3r_m4st3r}',
            'stage7': 'CTF{c0nf1g_hunt3r}',
            'stage8': 'CTF{m3m0ry_f0r3ns1cs}',
            'stage9': 'CTF{r3v3rs3_3ng1n33r}',
            'final': 'CTF{f1n4l_ch4mp10n_2024}'
        }
        self.user_progress = {}
        self.setup_challenges()
        
    def setup_challenges(self):
        """Set up all challenge files and data"""
        # Create directories
        os.makedirs('ctf_data/logs', exist_ok=True)
        os.makedirs('ctf_data/files', exist_ok=True)
        os.makedirs('ctf_data/binary', exist_ok=True)
        
        self.setup_stage1()
        self.setup_stage2()
        self.setup_stage3()
        self.setup_stage4()
        self.setup_stage5()
        self.setup_stage6()
        self.setup_stage7()
        self.setup_stage8()
        self.setup_stage9()
        
    def setup_stage1(self):
        """Stage 1: Hosts file manipulation"""
        # Create a simple web server for secret.ctf.local
        self.flask_app = Flask(__name__)
        
        @self.flask_app.route('/')
        def stage1_flag():
            if request.headers.get('Host') == 'secret.ctf.local':
                return f"<h1>Congratulations!</h1><p>Flag: {self.flags['stage1']}</p>"
            return "<h1>Access Denied</h1><p>Invalid host header</p>", 403
            
    def setup_stage2(self):
        """Stage 2: Log analysis"""
        log_content = []
        # Generate 1000 noise log entries
        for i in range(1000):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            level = random.choice(['INFO', 'DEBUG', 'WARN', 'ERROR'])
            message = random.choice([
                'User login successful',
                'Database connection established',
                'Cache cleared',
                'Session expired',
                'Request processed',
                'System health check passed'
            ])
            log_content.append(f"[{timestamp}] {level}: {message}")
        
        # Insert the flag at a random position
        flag_pos = random.randint(100, 900)
        log_content.insert(flag_pos, f"[2024-06-10 15:42:33] ERROR: Authentication failed for user admin - Debug info: {self.flags['stage2']}")
        
        with open('ctf_data/logs/application.log', 'w') as f:
            f.write('\n'.join(log_content))
    
    def setup_stage3(self):
        """Stage 3: Registry simulation (file-based for cross-platform)"""
        registry_data = {
            "HKEY_CURRENT_USER": {
                "SOFTWARE": {
                    "CTF_Simulation": {
                        "SecretKeyPart1": self.flags['stage3'],
                        "Version": "1.0",
                        "InstallDate": "2024-06-10"
                    }
                }
            }
        }
        
        with open('ctf_data/registry_sim.json', 'w') as f:
            json.dump(registry_data, f, indent=2)
    
    def setup_stage4(self):
        """Stage 4: Web injection vulnerability"""
        # This will be handled in the Flask app
        @self.flask_app.route('/search', methods=['GET', 'POST'])
        def vulnerable_search():
            if request.method == 'POST':
                query = request.form.get('query', '')
                # Simple SSTI vulnerability
                if '{{' in query and '}}' in query:
                    try:
                        # Simulate template injection
                        if 'flag' in query.lower():
                            return f"Search result: {self.flags['stage4']}"
                    except:
                        pass
                return f"Search results for: {query}"
            
            return '''
            <html>
            <body>
                <h2>Search System</h2>
                <form method="post">
                    <input type="text" name="query" placeholder="Enter search term">
                    <input type="submit" value="Search">
                </form>
                <p><i>Hint: Try template injection with {{flag}}</i></p>
            </body>
            </html>
            '''
    
    def setup_stage5(self):
        """Stage 5: Steganography"""
        # Create a text file with hidden message using whitespace
        visible_text = """Welcome to the CTF Challenge!
        
This is a normal looking text file.
Nothing suspicious here at all.
Just some regular content for you to read.

Good luck with the challenges ahead!"""
        
        # Hide flag in whitespace (spaces vs tabs)
        flag = self.flags['stage5']
        binary_flag = ''.join(format(ord(c), '08b') for c in flag)
        
        hidden_text = ""
        for i, char in enumerate(visible_text):
            hidden_text += char
            if char == ' ' and i < len(binary_flag):
                # Use tab for 1, space for 0
                if i < len(binary_flag) and binary_flag[i] == '1':
                    hidden_text += '\t'
        
        with open('ctf_data/files/message.txt', 'w') as f:
            f.write(hidden_text)
    
    def setup_stage6(self):
        """Stage 6: Vigenère cipher"""
        key = "SECRET"
        plaintext = self.flags['stage6']
        
        def vigenere_encrypt(text, key):
            result = ""
            key_index = 0
            for char in text:
                if char.isalpha():
                    shift = ord(key[key_index % len(key)]) - ord('A')
                    if char.isupper():
                        result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                    else:
                        result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                    key_index += 1
                else:
                    result += char
            return result
        
        encrypted = vigenere_encrypt(plaintext, key)
        
        with open('ctf_data/files/cipher.txt', 'w') as f:
            f.write(f"Encrypted message: {encrypted}\n")
            f.write(f"Hint: The key was mentioned in stage 3 registry value\n")
    
    def setup_stage7(self):
        """Stage 7: Configuration file analysis"""
        config = {
            "application": {
                "name": "CTF Challenge System",
                "version": "2.1.4",
                "debug_mode": False,
                "database": {
                    "host": "localhost",
                    "port": 5432,
                    "name": "ctf_db"
                },
                "developer_notes": {
                    "last_update": "2024-06-10",
                    "debug_flag": self.flags['stage7'],
                    "todo": "Remove debug info before production"
                }
            }
        }
        
        with open('ctf_data/files/app_config.json', 'w') as f:
            json.dump(config, f, indent=2)
    
    def setup_stage8(self):
        """Stage 8: Process memory simulation"""
        # Create a simple "memory dump" file
        memory_content = []
        
        # Add random memory-like data
        for _ in range(500):
            random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
            memory_content.append(random_data)
        
        # Insert flag in the middle
        flag_pos = random.randint(100, 400)
        memory_content.insert(flag_pos, f"PROC_CTF_Worker_Memory_Section: {self.flags['stage8']}")
        
        with open('ctf_data/files/memory_dump.txt', 'w') as f:
            f.write('\n'.join(memory_content))
    
    def setup_stage9(self):
        """Stage 9: Reverse engineering simulation"""
        # Create a simple "binary" analysis file with strings
        binary_strings = [
            "Usage: program.exe [options]",
            "Error: Invalid parameter",
            "Initializing system...",
            "Loading configuration",
            f"Debug_String_Key: {self.flags['stage9']}",
            "Process completed successfully",
            "Version 1.2.3 Build 456"
        ]
        
        with open('ctf_data/binary/strings_output.txt', 'w') as f:
            f.write("Strings found in binary:\n")
            f.write("=" * 30 + "\n")
            for s in binary_strings:
                f.write(f"{s}\n")
    
    def start_flask_server(self):
        """Start the Flask web server in a separate thread"""
        def run_flask():
            self.flask_app.run(host='127.0.0.1', port=5000, debug=False)
        
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
    
    def handle_client(self, client_socket, address):
        """Handle individual client connections"""
        print(f"New connection from {address}")
        
        try:
            while True:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                try:
                    request = json.loads(data)
                    response = self.process_request(request, address[0])
                    client_socket.send(json.dumps(response).encode('utf-8'))
                except json.JSONDecodeError:
                    error_response = {"status": "error", "message": "Invalid JSON format"}
                    client_socket.send(json.dumps(error_response).encode('utf-8'))
                    
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()
            print(f"Connection closed: {address}")
    
    def process_request(self, request, client_ip):
        """Process client requests"""
        action = request.get('action')
        stage = request.get('stage')
        
        if action == 'get_challenge':
            return self.get_challenge_info(stage)
        elif action == 'submit_flag':
            return self.verify_flag(request.get('flag'), stage, client_ip)
        elif action == 'get_progress':
            return self.get_user_progress(client_ip)
        elif action == 'get_hint':
            return self.get_hint(stage)
        else:
            return {"status": "error", "message": "Unknown action"}
    
    def get_challenge_info(self, stage):
        """Get challenge information for a specific stage"""
        challenges = {
            1: {
                "title": "Stage 1: Entry Door (Hosts File)",
                "description": "The flag is located at http://secret.ctf.local/ - but the domain doesn't resolve normally...",
                "type": "System Manipulation",
                "hint": "Check your system's hosts file configuration"
            },
            2: {
                "title": "Stage 2: Log Analysis",
                "description": "Find the hidden flag in the application log file at ctf_data/logs/application.log",
                "type": "Forensics",
                "hint": "Look for unusual error messages or debug information"
            },
            3: {
                "title": "Stage 3: Registry Hunt",
                "description": "Find the secret key in the simulated registry file ctf_data/registry_sim.json",
                "type": "System Analysis",
                "hint": "Look under HKEY_CURRENT_USER\\SOFTWARE\\CTF_Simulation"
            },
            4: {
                "title": "Stage 4: Web Injection",
                "description": "Exploit the search functionality at http://127.0.0.1:5000/search",
                "type": "Web Exploitation",
                "hint": "Try template injection techniques"
            },
            5: {
                "title": "Stage 5: Hidden Messages (Steganography)",
                "description": "Extract the hidden message from ctf_data/files/message.txt",
                "type": "Steganography",
                "hint": "Not all whitespace is created equal"
            },
            6: {
                "title": "Stage 6: Cipher Challenge",
                "description": "Decrypt the message in ctf_data/files/cipher.txt",
                "type": "Cryptography",
                "hint": "The key might be found in a previous stage"
            },
            7: {
                "title": "Stage 7: Configuration Secrets",
                "description": "Find the debug flag in ctf_data/files/app_config.json",
                "type": "File Analysis",
                "hint": "Developers sometimes leave debug information"
            },
            8: {
                "title": "Stage 8: Memory Forensics",
                "description": "Analyze the memory dump in ctf_data/files/memory_dump.txt",
                "type": "Forensics",
                "hint": "Look for process-specific memory sections"
            },
            9: {
                "title": "Stage 9: Reverse Engineering",
                "description": "Find the debug string in ctf_data/binary/strings_output.txt",
                "type": "Reverse Engineering",
                "hint": "Binary analysis often reveals embedded strings"
            },
            10: {
                "title": "Stage 10: Final Challenge",
                "description": "Combine information from previous stages to get the final flag",
                "type": "Integration",
                "hint": "SHA256 hash of concatenated stage 3 + stage 6 keys (lowercase)"
            }
        }
        
        if stage in challenges:
            return {"status": "success", "challenge": challenges[stage]}
        else:
            return {"status": "error", "message": "Invalid stage number"}
    
    def verify_flag(self, submitted_flag, stage, client_ip):
        """Verify submitted flags"""
        if client_ip not in self.user_progress:
            self.user_progress[client_ip] = {"completed_stages": [], "score": 0}
        
        correct_flag = None
        
        if stage == 10:
            # Final stage: SHA256 of stage3 + stage6 flags
            combined = (self.flags['stage3'] + self.flags['stage6']).lower()
            correct_flag = "CTF{" + hashlib.sha256(combined.encode()).hexdigest()[:16] + "}"
        else:
            flag_key = f'stage{stage}'
            correct_flag = self.flags.get(flag_key)
        
        if correct_flag and submitted_flag == correct_flag:
            if stage not in self.user_progress[client_ip]["completed_stages"]:
                self.user_progress[client_ip]["completed_stages"].append(stage)
                self.user_progress[client_ip]["score"] += 100
            
            return {
                "status": "success", 
                "message": f"Correct! Stage {stage} completed!",
                "next_stage": stage + 1 if stage < 10 else None
            }
        else:
            return {"status": "error", "message": "Incorrect flag"}
    
    def get_user_progress(self, client_ip):
        """Get user progress"""
        if client_ip not in self.user_progress:
            self.user_progress[client_ip] = {"completed_stages": [], "score": 0}
        
        progress = self.user_progress[client_ip]
        return {
            "status": "success",
            "completed_stages": sorted(progress["completed_stages"]),
            "score": progress["score"],
            "total_stages": 10
        }
    
    def get_hint(self, stage):
        """Get additional hints for stages"""
        hints = {
            1: "Add '127.0.0.1 secret.ctf.local' to your hosts file",
            2: "Use grep or find to search for 'CTF{' in the log file",
            3: "Navigate through the JSON structure to find SecretKeyPart1",
            4: "Try injecting {{flag}} in the search box",
            5: "Check for hidden characters between visible text",
            6: "Use 'SECRET' as the Vigenère cipher key",
            7: "Look in the developer_notes section",
            8: "Search for 'CTF_Worker' in the memory dump",
            9: "Look for strings containing 'Debug_String_Key'",
            10: "Calculate SHA256 of: SecretPart123ctf{c1ph3r_m4st3r}"
        }
        
        return {
            "status": "success",
            "hint": hints.get(stage, "No hint available for this stage")
        }
    
    def start_server(self):
        """Start the main CTF server"""
        # Start Flask server first
        self.start_flask_server()
        time.sleep(1)  # Give Flask time to start
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"CTF Server started on {self.host}:{self.port}")
            print(f"Web challenges available at http://127.0.0.1:5000")
            print("Server is ready for connections...")
            
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            server_socket.close()

if __name__ == "__main__":
    server = CTFServer()
    server.start_server()