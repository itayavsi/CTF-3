"""
CTF Setup Script and Documentation
==================================
Setup script for the CTF simulation environment
"""

import os
import sys
import subprocess
import json

def check_dependencies():
    """Check if required dependencies are installed"""
    print("Checking dependencies...")
    
    required_packages = ['flask', 'requests']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} is installed")
        except ImportError:
            print(f"❌ {package} is missing")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\nInstalling missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing_packages)
            print("✅ All dependencies installed successfully")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies. Please install manually:")
            print(f"pip install {' '.join(missing_packages)}")
            return False
    
    return True

def create_directory_structure():
    """Create necessary directory structure"""
    print("Creating directory structure...")
    
    directories = [
        'ctf_data',
        'ctf_data/logs',
        'ctf_data/files',
        'ctf_data/binary'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def create_run_scripts():
    """Create convenient run scripts"""
    print("Creating run scripts...")
    
    # Server run script
    server_script = '''#!/usr/bin/env python3
"""
CTF Server Launcher
"""
from ctf_server import CTFServer

if __name__ == "__main__":
    print("Starting CTF Server...")
    server = CTFServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\\nServer stopped by user.")
'''
    
    # Client run script
    client_script = '''#!/usr/bin/env python3
"""
CTF Client Launcher
"""
from ctf_client import CTFClient
import sys

if __name__ == "__main__":
    print("Starting CTF Client...")
    client = CTFClient()
    
    mode = 'interactive'
    if len(sys.argv) > 1 and sys.argv[1] == 'auto':
        mode = 'auto'
    
    client.run(mode)
'''
    
    with open('run_server.py', 'w') as f:
        f.write(server_script)
    
    with open('run_client.py', 'w') as f:
        f.write(client_script)
    
    # Make scripts executable on Unix systems
    if os.name != 'nt':
        os.chmod('run_server.py', 0o755)
        os.chmod('run_client.py', 0o755)
    
    print("✅ Created run scripts")

def create_documentation():
    """Create comprehensive documentation"""
    print("Creating documentation...")
    
    readme_content = '''# CTF Simulation - Security Challenge Platform

## Overview
This CTF (Capture The Flag) simulation implements 10 different cybersecurity challenges covering various domains including system manipulation, forensics, web exploitation, cryptography, steganography, and reverse engineering.

## Features
- **10 Progressive Stages**: Each stage focuses on different security concepts
- **Auto-Solver**: Automated solutions for learning and verification
- **Interactive Mode**: Manual solving with hints and guidance
- **Web Components**: Real web vulnerabilities to exploit
- **Cross-Platform**: Works on Windows, Linux, and macOS

## Challenge Overview

### Stage 1: Entry Door (Hosts File)
- **Type**: System Manipulation
- **Skill**: Understanding DNS resolution and hosts file
- **Challenge**: Access a local domain that requires hosts file modification

### Stage 2: Log Analysis
- **Type**: Forensics
- **Skill**: Log file analysis and pattern recognition
- **Challenge**: Find hidden information in application logs

### Stage 3: Registry Hunt
- **Type**: System Analysis
- **Skill**: Windows registry navigation (simulated)
- **Challenge**: Extract secret keys from registry-like data

### Stage 4: Web Injection
- **Type**: Web Exploitation
- **Skill**: Template injection vulnerabilities
- **Challenge**: Exploit SSTI (Server-Side Template Injection)

### Stage 5: Hidden Messages
- **Type**: Steganography
- **Skill**: Hidden data extraction
- **Challenge**: Find data hidden in whitespace characters

### Stage 6: Cipher Challenge
- **Type**: Cryptography
- **Skill**: Classical cipher cryptanalysis
- **Challenge**: Decrypt Vigenère cipher with key from previous stage

### Stage 7: Configuration Secrets
- **Type**: File Analysis
- **Skill**: Configuration file analysis
- **Challenge**: Find debug information in JSON config files

### Stage 8: Memory Forensics
- **Type**: Forensics
- **Skill**: Memory dump analysis
- **Challenge**: Extract process-specific information from memory

### Stage 9: Reverse Engineering
- **Type**: Reverse Engineering
- **Skill**: Binary analysis and string extraction
- **Challenge**: Find embedded strings in binary files

### Stage 10: Final Challenge
- **Type**: Integration
- **Skill**: Combining multiple pieces of information
- **Challenge**: Create final flag using data from previous stages

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Setup
1. Extract all files to a directory
2. Run the setup script:
   ```bash
   python setup.py
   ```

### Manual Installation
If the setup script fails, install dependencies manually:
```bash
pip install flask requests
```

## Usage

### Starting the Server
```bash
python run_server.py
```
or
```bash
python ctf_server.py
```

The server will start on `localhost:8888` and create a web server on `localhost:5000`.

### Using the Client

#### Interactive Mode (Recommended for learning)
```bash
python run_client.py
```

Interactive commands:
- `challenge <stage>` - Get challenge information
- `submit <stage> <flag>` - Submit a flag
- `hint <stage>` - Get additional hints
- `progress` - Show current progress
- `solve <stage>` - Auto-solve specific stage
- `auto` - Auto-solve all stages
- `quit` - Exit

#### Auto-Solve Mode (For verification)
```bash
python run_client.py auto
```

## Challenge Solutions

### Stage 1: Hosts File
1. Add `127.0.0.1 secret.ctf.local` to your hosts file
2. Visit `http://secret.ctf.local/`
3. **Hosts file locations**:
   - Windows: `C:\\Windows\\System32\\drivers\\etc\\hosts`
   - Linux/Mac: `/etc/hosts`

### Stage 2: Log Analysis
```bash
grep "CTF{" ctf_data/logs/application.log
```

### Stage 3: Registry
Navigate through the JSON structure in `ctf_data/registry_sim.json`:
```json
HKEY_CURRENT_USER -> SOFTWARE -> CTF_Simulation -> SecretKeyPart1
```

### Stage 4: Web Injection
1. Visit `http://127.0.0.1:5000/search`
2. Enter `{{flag}}` in the search box
3. Submit the form

### Stage 5: Steganography
Analyze `ctf_data/files/message.txt` for hidden whitespace characters.

### Stage 6: Cryptography
1. Read `ctf_data/files/cipher.txt`
2. Use "SECRET" as the Vigenère cipher key
3. Decrypt the message

### Stage 7: Configuration
Check `ctf_data/files/app_config.json` under `developer_notes.debug_flag`

### Stage 8: Memory Forensics
Search for "CTF_Worker" in `ctf_data/files/memory_dump.txt`

### Stage 9: Reverse Engineering
Look for "Debug_String_Key" in `ctf_data/binary/strings_output.txt`

### Stage 10: Final Challenge
Combine flags from stages 3 and 6, then calculate SHA256 hash

## Security Learning Points

This CTF teaches:
- **System Administration**: Hosts file manipulation, registry analysis
- **Digital Forensics**: Log analysis, memory forensics
- **Web Security**: Template injection vulnerabilities
- **Cryptography**: Classical ciphers and cryptanalysis
- **Steganography**: Hidden data techniques
- **Reverse Engineering**: Binary analysis and string extraction
- **Integration Skills**: Combining multiple attack vectors

## Troubleshooting

### Common Issues

1. **Connection Refused**: Make sure the server is running first
2. **Permission Denied**: Run with administrator/sudo privileges for hosts file modification
3. **Module Not Found**: Install required dependencies with pip
4. **Port Already in Use**: Change ports in the server configuration

### File Permissions
On Unix systems, you may need to make scripts executable:
```bash
chmod +x run_server.py run_client.py
```

### Firewall Issues
If you have firewall restrictions, ensure ports 8888 and 5000 are accessible locally.

## Educational Use

This platform is designed for:
- **Cybersecurity Education**: Learning common attack vectors
- **Skill Development**: Hands-on practice with security tools
- **Team Training**: Collaborative problem-solving
- **Assessment**: Evaluating security knowledge

## Contributing

To add new challenges:
1. Implement the challenge logic in `ctf_server.py`
2. Add the corresponding solver in `ctf_client.py`
3. Update the documentation

## License

This CTF simulation is provided for educational purposes. Use responsibly and only in authorized environments.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Verify all dependencies are installed
3. Ensure proper file permissions
4. Check server logs for error messages

---
**Remember**: This is a simulation for learning purposes. Always practice ethical hacking and obtain proper authorization before testing security techniques on any system.
'''
    
    with open('README.md', 'w') as f:
        f.write(readme_content)
    
    print("✅ Created documentation")

def main():
    """Main setup function"""
    print("=" * 50)
    print("CTF Simulation Setup")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("❌ Setup failed due to missing dependencies")
        return False
    
    # Create directory structure
    create_directory_structure()
    
    # Create run scripts
    create_run_scripts()
    
    # Create documentation
    create_documentation()
    
    print("\n" + "=" * 50)
    print("Setup Complete!")
    print("=" * 50)
    print("Next steps:")
    print("1. Start the server: python run_server.py")
    print("2. In another terminal, start the client: python run_client.py")
    print("3. Follow the challenges in interactive mode")
    print("4. Use 'python run_client.py auto' for automated solving")
    print("\nFor detailed instructions, see README.md")
    
    return True

if __name__ == "__main__":
    main()