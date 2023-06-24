rule Detect_Windows_Defender_Disable_Script_VBS {
    meta:
        description = "Detect VBScript that attempts to disable Windows Defender"
        source = "Based on the open source code provided from the github repository https://github.com/NYAN-x-CAT/Bypass-Windows-Defender-VBS/blob/master/script.vbs"
        author = "u$3r_h0n3$t"
        date = "2023-06-25"
        version = "1.0"

    strings:
    
        //This string looks for a regular expression pattern that matches 
        // a call to   the RegWrite method of a WshShell object, 
        // specifically where it's writing to a Windows Defender related 
        // registry key.
        
        $vb_regwrite = /WshShell\.RegWrite\s+"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender[^\n"]+"/ wide nocase
        
        // This string matches a piece of code where the script is 
        // being run with elevated permissions.
        
        $runas_elevate = "runas\", 1"
        
        // This string looks for a pattern where PowerShell is 
        // being used to set Windows Defender preferences.
        
        $powershell_pref = /powershell\s+Set-MpPreference/ wide nocase

    condition:
        $vb_regwrite and $runas_elevate and $powershell_pref and filename matches /.*\.vbs/
}

// ---------------- end of file ----------------------------- // 

