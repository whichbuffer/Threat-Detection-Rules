rule MAL_CRIME_Loader_WIN_PE_DarkGate_Jan9 {
    meta:
        description = "Detecting final payload of DarkGate loader on Windows Endpoints"
        author = "Arda Buyukkaya"
        md5 = "d25a5b444336b66cc5f36437701b896b"

    strings:
        // XOR Config Decryption Routine 1
        $XOR_Dec_1 = {
            8B 44 24 04
            8B D5
            E8 ?? ?? ?? ??
            8B C5
            E8 ?? ?? ?? ??
            8B F0
            85 F6
            7E 1E
            BB 01 00 00 00
            8B 44 24 04
            E8 ?? ?? ?? ??
            8B D7
            32 54 1D FF
            F6 D2
            88 54 18 FF
            43
            4E
            75 E7
        }
        
        // XOR Config Decryption Routine 2
        $XOR_Dec_2 = {C1 EB 04 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
        
        // XOR Config Decryption Routine 3
        $XOR_Dec_3 = {?? 80 E3 3F 02 CB 88 4C 10 FF FF 45}
        
        // Generic Base64 alphabet used in C2 config obfuscation 
        $alphabet = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="

        // Signature for DarkGate InternalCrypter
        $InternalCrypter = "DarkGate InternalCrypter" fullword ascii nocase
        
        // Signature for Autoit3 executable
        $Autoit3 = "Autoit3.exe" fullword ascii nocase

    condition:
        // Check for MZ header (PE file) and presence of specific strings
        uint16(0) == 0x5a4d and
        (($InternalCrypter or $Autoit3 or $alphabet) and any of ($XOR_Dec_*))
}
