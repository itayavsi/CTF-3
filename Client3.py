"""
CTF Simulation Client Module
============================
Interactive client for participating in the CTF challenges
"""

import socket
import json
import requests
import os
import re
import hashlib
import base64
from datetime import datetime

class CTFClient:
    def __init__(self, server_host='localhost', server_port=8888):
        self.server_host = server_host
        self.server_port = server_port
        self.current_stage = 1
        self.completed_stages = []
        
    def connect_to_server(self):
        """Establish connection to CTF server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            return True
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            return False
    
    def send_request(self, request):
        """Send request to server and get response"""
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            response = self.socket.recv(4096).decode('utf-8')
            return json.loads(response)
        except Exception as e:
            print(f"Communication error: {e}")
            return {"status": "error", "message": str(e)}
    
    def get_challenge(self, stage):
        """Get challenge information for a specific stage"""
        request = {
            "action": "get_challenge",
            "stage": stage
        }
        return self.send_request(request)
    
    def submit_flag(self, flag, stage):
        """Submit a flag for verification"""
        request = {
            "action": "submit_flag",
            "flag": flag,
            "stage": stage
        }
        return self.send_request(request)
    
    def get_progress(self):
        """Get current progress"""
        request = {"action": "get_progress"}
        return self.send_request(request)
    
    def get_hint(self, stage):
        """Get hint for a specific stage"""
        request = {
            "action": "get_hint",
            "stage": stage
        }
        return self.send_request(request)
    
    def solve_stage1(self):
        """Automated solution for Stage 1 - Hosts file"""
        print("\\n=== Stage 1: Hosts File Challenge ===")
        print("This challenge requires manual intervention:")
        print("1. Add the following line to your hosts file:")
        print("   127.0.0.1    secret.ctf.local")
        print("2. Then visit: http://secret.ctf.local/")
        print("3. On Windows: C:\\Windows\\System32\\drivers\\etc\\hosts")
        print("4. On Linux/Mac: /etc/hosts")
        print()
        
        # Try to access the URL programmatically
        try:
            headers = {'Host': 'secret.ctf.local'}
            response = requests.get('http://127.0.0.1:5000/', headers=headers, timeout=5)
            if response.status_code == 200 and 'CTF{' in response.text:
                flag_match = re.search(r'CTF\{[^}]+\}', response.text)
                if flag_match:
                    flag = flag_match.group()
                    print(f"Found flag: {flag}")
                    return flag
        except requests.exceptions.RequestException:
            print("Could not automatically retrieve flag. Manual setup required.")
        
        return None
    
    def solve_stage2(self):
        """Automated solution for Stage 2 - Log analysis"""
        print("\\n=== Stage 2: Log Analysis ===")
        log_file = 'ctf_data/logs/application.log'
        
        if not os.path.exists(log_file):
            print(f"Log file not found: {log_file}")
            return None
        
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                
            # Search for CTF flag pattern
            flag_match = re.search(r'CTF\{[^}]+\}', content)
            if flag_match:
                flag = flag_match.group()
                print(f"Found flag in logs: {flag}")
                return flag
            else:
                print("No flag found in log file")
                
        except Exception as e:
            print(f"Error reading log file: {e}")
        
        return None
    
    def solve_stage3(self):
        """Automated solution for Stage 3 - Registry"""
        print("\\n=== Stage 3: Registry Analysis ===")
        registry_file = 'ctf_data/registry_sim.json'
        
        if not os.path.exists(registry_file):
            print(f"Registry file not found: {registry_file}")
            return None
        
        try:
            with open(registry_file, 'r') as f:
                registry_data = json.load(f)
            
            # Navigate to the secret key
            secret_key = registry_data['HKEY_CURRENT_USER']['SOFTWARE']['CTF_Simulation']['SecretKeyPart1']
            print(f"Found registry key: {secret_key}")
            return secret_key
            
        except Exception as e:
            print(f"Error reading registry file: {e}")
        
        return None
    
    def solve_stage4(self):
        """Automated solution for Stage 4 - Web injection"""
        print("\\n=== Stage 4: Web Injection ===")
        
        try:
            # Attempt SSTI injection
            payload = {'query': '{{flag}}'}
            response = requests.post('http://127.0.0.1:5000/search', data=payload, timeout=5)
            
            if response.status_code == 200 and 'CTF{' in response.text:
                flag_match = re.search(r'CTF\{[^}]+\}', response.text)
                if flag_match:
                    flag = flag_match.group()
                    print(f"Injection successful! Flag: {flag}")
                    return flag
            else:
                print("Injection attempt failed")
                
        except requests.exceptions.RequestException as e:
            print(f"Web request failed: {e}")
        
        return None
    
    def solve_stage5(self):
        """Automated solution for Stage 5 - Steganography"""
        print("\\n=== Stage 5: Steganography ===")
        message_file = 'ctf_data/files/message.txt'
        
        if not os.path.exists(message_file):
            print(f"Message file not found: {message_file}")
            return None
        
        try:
            with open(message_file, 'rb') as f:
                content = f.read()
            
            # Extract hidden binary data from whitespace
            binary_string = ""
            for byte in content:
                if byte == ord('\\t'):  # Tab represents 1
                    binary_string += '1'
                elif byte == ord(' '):  # Space represents 0
                    if len(binary_string) % 8 == 0 and binary_string:
                        break  # We have enough bits
                    binary_string += '0'
            
            # Convert binary to text
            if len(binary_string) >= 8:
                flag = ""
                for i in range(0, len(binary_string), 8):
                    if i + 8 <= len(binary_string):
                        byte_val = int(binary_string[i:i+8], 2)
                        if 32 <= byte_val <= 126:  # Printable ASCII
                            flag += chr(byte_val)
                        else:
                            break
                
                if 'CTF{' in flag:
                    print(f"Hidden message found: {flag}")
                    return flag
            
            # Alternative: search for CTF pattern in the visible text
            content_str = content.decode('utf-8', errors='ignore')
            flag_match = re.search(r'CTF\{[^}]+\}', content_str)
            if flag_match:
                flag = flag_match.group()
                print(f"Found flag in text: {flag}")
                return flag
                
        except Exception as e:
            print(f"Error analyzing steganography: {e}")
        
        return None
    
    def solve_stage6(self):
        """Automated solution for Stage 6 - Vigenère cipher"""
        print("\\n=== Stage 6: Vigenère Cipher ===")
        cipher_file = 'ctf_data/files/cipher.txt'
        
        if not os.path.exists(cipher_file):
            print(f"Cipher file not found: {cipher_file}")
            return None
        
        try:
            with open(cipher_file, 'r') as f:
                content = f.read()
            
            # Extract encrypted message
            encrypted_match = re.search(r'Encrypted message: (.+)', content)
            if not encrypted_match:
                print("No encrypted message found")
                return None
            
            encrypted = encrypted_match.group(1).strip()
            key = "SECRET"  # From hint
            
            # Vigenère decryption
            def vigenere_decrypt(text, key):
                result = ""
                key_index = 0
                for char in text:
                    if char.isalpha():
                        shift = ord(key[key_index % len(key)]) - ord('A')
                        if char.isupper():
                            result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                        else:
                            result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                        key_index += 1
                    else:
                        result += char
                return result
            
            decrypted = vigenere_decrypt(encrypted, key)
            print(f"Decrypted message: {decrypted}")
            
            if 'CTF{' in decrypted:
                return decrypted
                
        except Exception as e:
            print(f"Error decrypting cipher: {e}")
        
        return None
    
    def solve_stage7(self):
        """Automated solution for Stage 7 - Configuration file"""
        print("\\n=== Stage 7: Configuration Analysis ===")
        config_file = 'ctf_data/files/app_config.json'
        
        if not os.path.exists(config_file):
            print(f"Config file not found: {config_file}")
            return None
        
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            # Navigate to developer notes
            debug_flag = config_data['application']['developer_notes']['debug_flag']
            print(f"Found debug flag: {debug_flag}")
            return debug_flag
            
        except Exception as e:
            print(f"Error reading config file: {e}")
        
        return None
    
    def solve_stage8(self):
        """Automated solution for Stage 8 - Memory forensics"""
        print("\\n=== Stage 8: Memory Forensics ===")
        memory_file = 'ctf_data/files/memory_dump.txt'
        
        if not os.path.exists(memory_file):
            print(f"Memory dump not found: {memory_file}")
            return None
        
        try:
            with open(memory_file, 'r') as f:
                content = f.read()
            
            # Search for CTF_Worker process memory
            lines = content.split('\n')
            for line in lines:
                if 'CTF_Worker' in line and 'CTF{' in line:
                    flag_match = re.search(r'CTF\{[^}]+\}', line)
                    if flag_match:
                        flag = flag_match.group()
                        print(f"Found flag in memory dump: {flag}")
                        return flag
            
            print("No flag found in memory dump")
            
        except Exception as e:
            print(f"Error analyzing memory dump: {e}")
        
        return None
    
    def solve_stage9(self):
        """Automated solution for Stage 9 - Reverse engineering"""
        print("\\n=== Stage 9: Reverse Engineering ===")
        strings_file = 'ctf_data/binary/strings_output.txt'
        
        if not os.path.exists(strings_file):
            print(f"Strings file not found: {strings_file}")
            return None
        
        try:
            with open(strings_file, 'r') as f:
                content = f.read()
            
            # Search for debug string
            lines = content.split('\n')
            for line in lines:
                if 'Debug_String_Key' in line and 'CTF{' in line:
                    flag_match = re.search(r'CTF\{[^}]+\}', line)
                    if flag_match:
                        flag = flag_match.group()
                        print(f"Found flag in binary strings: {flag}")
                        return flag
            
            print("No flag found in binary strings")
            
        except Exception as e:
            print(f"Error analyzing binary strings: {e}")
        
        return None
    
    def solve_stage10(self, stage3_flag, stage6_flag):
        """Automated solution for Stage 10 - Final challenge"""
        print("\\n=== Stage 10: Final Challenge ===")
        
        if not stage3_flag or not stage6_flag:
            print("Missing flags from previous stages")
            return None
        
        try:
            # Combine flags and create hash
            combined = (stage3_flag + stage6_flag).lower()
            hash_value = hashlib.sha256(combined.encode()).hexdigest()[:16]
            final_flag = f"CTF{{{hash_value}}}"
            
            print(f"Combined string: {combined}")
            print(f"SHA256 hash (first 16 chars): {hash_value}")
            print(f"Final flag: {final_flag}")
            
            return final_flag
            
        except Exception as e:
            print(f"Error creating final flag: {e}")
        
        return None
    
    def auto_solve_all(self):
        """Automatically solve all stages"""
        print("=== CTF Auto-Solver Starting ===")
        
        if not self.connect_to_server():
            return
        
        flags = {}
        
        # Solve each stage
        solvers = {
            1: self.solve_stage1,
            2: self.solve_stage2,
            3: self.solve_stage3,
            4: self.solve_stage4,
            5: self.solve_stage5,
            6: self.solve_stage6,
            7: self.solve_stage7,
            8: self.solve_stage8,
            9: self.solve_stage9
        }
        
        for stage in range(1, 10):
            print(f"\\n{'='*50}")
            print(f"Attempting Stage {stage}")
            print('='*50)
            
            # Get challenge info
            challenge_info = self.get_challenge(stage)
            if challenge_info['status'] == 'success':
                challenge = challenge_info['challenge']
                print(f"Challenge: {challenge['title']}")
                print(f"Description: {challenge['description']}")
                print(f"Type: {challenge['type']}")
            
            # Attempt to solve
            if stage in solvers:
                flag = solvers[stage]()
                if flag:
                    flags[stage] = flag
                    # Submit flag
                    result = self.submit_flag(flag, stage)
                    if result['status'] == 'success':
                        print(f"✅ Stage {stage} completed successfully!")
                    else:
                        print(f"❌ Flag submission failed: {result['message']}")
                else:
                    print(f"❌ Could not solve stage {stage}")
            else:
                print(f"❌ No solver available for stage {stage}")
        
        # Solve final stage
        if 3 in flags and 6 in flags:
            print(f"\\n{'='*50}")
            print("Attempting Final Stage")
            print('='*50)
            
            final_flag = self.solve_stage10(flags[3], flags[6])
            if final_flag:
                result = self.submit_flag(final_flag, 10)
                if result['status'] == 'success':
                    print("🎉 Final stage completed! CTF conquered!")
                else:
                    print(f"❌ Final flag submission failed: {result['message']}")
        
        # Show final progress
        progress = self.get_progress()
        if progress['status'] == 'success':
            print(f"\\n{'='*50}")
            print("FINAL RESULTS")
            print('='*50)
            print(f"Completed stages: {progress['completed_stages']}")
            print(f"Total score: {progress['score']}")
            print(f"Stages completed: {len(progress['completed_stages'])}/{progress['total_stages']}")
        
        self.socket.close()
    
    def interactive_mode(self):
        """Interactive mode for manual solving"""
        if not self.connect_to_server():
            return
        
        print("=== CTF Interactive Mode ===")
        print("Commands:")
        print("  challenge <stage> - Get challenge info")
        print("  submit <stage> <flag> - Submit a flag")
        print("  hint <stage> - Get hint for stage")
        print("  progress - Show current progress")
        print("  solve <stage> - Auto-solve a specific stage")
        print("  auto - Auto-solve all stages")
        print("  quit - Exit")
        
        while True:
            try:
                command = input("\\nCTF> ").strip().split()
                
                if not command:
                    continue
                
                if command[0] == 'quit':
                    break
                
                elif command[0] == 'challenge' and len(command) == 2:
                    stage = int(command[1])
                    response = self.get_challenge(stage)
                    if response['status'] == 'success':
                        challenge = response['challenge']
                        print(f"\\n{challenge['title']}")
                        print(f"Description: {challenge['description']}")
                        print(f"Type: {challenge['type']}")
                        print(f"Hint: {challenge['hint']}")
                    else:
                        print(f"Error: {response['message']}")
                
                elif command[0] == 'submit' and len(command) >= 3:
                    stage = int(command[1])
                    flag = ' '.join(command[2:])
                    response = self.submit_flag(flag, stage)
                    print(f"Result: {response['message']}")
                
                elif command[0] == 'hint' and len(command) == 2:
                    stage = int(command[1])
                    response = self.get_hint(stage)
                    if response['status'] == 'success':
                        print(f"Hint: {response['hint']}")
                    else:
                        print(f"Error: {response['message']}")
                
                elif command[0] == 'progress':
                    response = self.get_progress()
                    if response['status'] == 'success':
                        print(f"Completed stages: {response['completed_stages']}")
                        print(f"Score: {response['score']}")
                        print(f"Progress: {len(response['completed_stages'])}/{response['total_stages']}")
                    else:
                        print(f"Error: {response['message']}")
                
                elif command[0] == 'solve' and len(command) == 2:
                    stage = int(command[1])
                    solvers = {
                        1: self.solve_stage1,
                        2: self.solve_stage2,
                        3: self.solve_stage3,
                        4: self.solve_stage4,
                        5: self.solve_stage5,
                        6: self.solve_stage6,
                        7: self.solve_stage7,
                        8: self.solve_stage8,
                        9: self.solve_stage9
                    }
                    
                    if stage in solvers:
                        flag = solvers[stage]()
                        if flag:
                            response = self.submit_flag(flag, stage)
                            print(f"Auto-solved and submitted: {response['message']}")
                        else:
                            print("Could not auto-solve this stage")
                    else:
                        print("No auto-solver available for this stage")
                
                elif command[0] == 'auto':
                    self.socket.close()
                    self.auto_solve_all()
                    return
                
                else:
                    print("Invalid command. Type 'quit' to exit.")
                    
            except KeyboardInterrupt:
                print("\\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")
        
        self.socket.close()
    
    def run(self, mode='interactive'):
        """Run the CTF client"""
        if mode == 'auto':
            self.auto_solve_all()
        else:
            self.interactive_mode()

def main():
    """Main function"""
    import sys
    
    client = CTFClient()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'auto':
        client.run('auto')
    else:
        client.run('interactive')

if __name__ == "__main__":
    main()