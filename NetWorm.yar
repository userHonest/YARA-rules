rule Python_SSH_BruteForce_Worm_Compiled
{
    meta:
        description = "Detects a Python script (compiled with PyInstaller) designed to spread across drives and brute force SSH servers"
        source = "https://github.com/pylyf/NetWorm/blob/master/worm.py"
        author = "u$3r_h0n3$t"
        date = "2023-06-25"
        version = "1.0"

    strings:
        // Python compiled magic bytes for Python 2.7 - Python 3.9
        $pyc_magic_27 = { d1 f2 0d 0a }
        $pyc_magic_33 = { 03 f3 0d 0a }
        $pyc_magic_34 = { 04 f3 0d 0a }
        $pyc_magic_35 = { 16 0d 0d 0a }
        $pyc_magic_36 = { 33 0d 0d 0a }
        $pyc_magic_37 = { 4b 0d 0d 0a }
        $pyc_magic_38 = { 55 0d 0d 0a }
        $pyc_magic_39 = { 5b 0d 0d 0a }
        
        // if python script is compiled wiht pyinstaller
        $pyinstaller_artifact1 = "PyInstaller" ascii
        
        // the rest are strings from the open source .py file,  if script is installed or runned in scheduled tasks
        $ssh_bruteforce_string = "bruteforce_ssh" ascii
        $drivespreading_string = "drivespreading" ascii
        $download_ssh_passwords_string = "download_ssh_passwords" ascii
        $url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt" ascii

    condition:
        (1 of ($pyc_magic_*) and $pyinstaller_artifact1) and 
        ($ssh_bruteforce_string or $drivespreading_string or $download_ssh_passwords_string or $url)
}

