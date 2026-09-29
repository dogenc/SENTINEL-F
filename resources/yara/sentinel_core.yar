/*
  SENTINEL-F Kernregeln · DGKN@Labs
  Verhaltens-/Musterregeln (keine Hash-Signaturen). Eigene Regeln einfach als
  weitere .yar-Datei in diesen Ordner legen oder DGKN_YARA_DIR setzen.
  meta.severity: critical | high | medium | low
*/

rule SENTINEL_PE_UPX_Packed
{
    meta:
        description = "Windows-Programm mit UPX gepackt"
        severity = "low"
    strings:
        $s0 = "UPX0" ascii
        $s1 = "UPX1" ascii
        $s2 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule SENTINEL_PE_Hidden_In_NonPE
{
    meta:
        description = "DOS-Stub eines Windows-Programms in einer Nicht-Programm-Datei"
        severity = "high"
    strings:
        $stub = "This program cannot be run in DOS mode" ascii
    condition:
        uint16(0) != 0x5A4D and $stub
}

rule SENTINEL_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell lädt Code herunter und führt ihn aus"
        severity = "high"
    strings:
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadData" ascii wide nocase
        $dl3 = "Invoke-WebRequest" ascii wide nocase
        $dl4 = "Net.WebClient" ascii wide nocase
        $ex1 = "IEX" ascii wide
        $ex2 = "Invoke-Expression" ascii wide nocase
        $ex3 = "[Reflection.Assembly]::Load" ascii wide nocase
    condition:
        filesize < 5MB and 1 of ($dl*) and 1 of ($ex*)
}

rule SENTINEL_HTML_Smuggling
{
    meta:
        description = "HTML-Smuggling (Datei wird im Browser aus Base64 gebaut)"
        severity = "high"
    strings:
        $b1 = "new Blob" ascii nocase
        $b2 = "createObjectURL" ascii nocase
        $b3 = "msSaveOrOpenBlob" ascii nocase
        $d1 = ".download" ascii nocase
        $a1 = "atob(" ascii nocase
    condition:
        filesize < 20MB and $a1 and 1 of ($b*) and ($d1 or $b3)
}

rule SENTINEL_Office_AutoExec_Macro
{
    meta:
        description = "Office-Makro startet automatisch und führt Befehle aus"
        severity = "high"
    strings:
        $a1 = "AutoOpen" ascii nocase
        $a2 = "Document_Open" ascii nocase
        $a3 = "Workbook_Open" ascii nocase
        $a4 = "Auto_Open" ascii nocase
        $x1 = "Shell" ascii
        $x2 = "WScript.Shell" ascii nocase
        $x3 = "CreateObject" ascii nocase
        $x4 = "URLDownloadToFile" ascii nocase
    condition:
        uint32(0) == 0xE011CFD0 and 1 of ($a*) and 2 of ($x*)
}

rule SENTINEL_Ransom_Note
{
    meta:
        description = "Typische Formulierungen einer Lösegeldforderung"
        severity = "medium"
    strings:
        $r1 = "your files have been encrypted" ascii wide nocase
        $r2 = "all your files are encrypted" ascii wide nocase
        $r3 = "to decrypt your files" ascii wide nocase
        $r4 = "bitcoin" ascii wide nocase
        $r5 = ".onion" ascii wide nocase
        $r6 = "private key" ascii wide nocase
        $r7 = "do not rename encrypted files" ascii wide nocase
    condition:
        filesize < 10MB and 3 of them
}

rule SENTINEL_PHP_Webshell
{
    meta:
        description = "PHP-Webshell führt Befehle aus Web-Anfragen aus"
        severity = "critical"
    strings:
        $p = "<?php" ascii nocase
        $w1 = /(eval|assert|system|passthru|shell_exec|exec)\s*\(\s*(base64_decode\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $w2 = /preg_replace\s*\(\s*['"][^'"]*\/e['"]/ nocase
    condition:
        $p and 1 of ($w*)
}

rule SENTINEL_Crypto_Miner
{
    meta:
        description = "Krypto-Miner (Stratum-Pool / XMRig)"
        severity = "medium"
    strings:
        $s1 = "stratum+tcp://" ascii wide nocase
        $s2 = "stratum+ssl://" ascii wide nocase
        $s3 = "xmrig" ascii wide nocase
        $s4 = "--donate-level" ascii wide
        $s5 = "cryptonight" ascii wide nocase
    condition:
        2 of them
}

rule SENTINEL_Reverse_Shell
{
    meta:
        description = "Reverse-Shell-Muster"
        severity = "critical"
    strings:
        $r1 = /bash\s+-i\s+>&\s*\/dev\/tcp\// ascii
        $r2 = "System.Net.Sockets.TCPClient" ascii wide nocase
        $r3 = /nc(\.exe)?\s+-e\s+(\/bin\/(ba)?sh|cmd)/ ascii nocase
        $r4 = "socket.socket(socket.AF_INET" ascii
        $s1 = "GetStream()" ascii wide
        $s2 = "subprocess.call([\"/bin/sh\"" ascii
        $s3 = "os.dup2(" ascii
    condition:
        $r1 or $r3 or ($r2 and $s1) or ($r4 and ($s2 or $s3))
}

rule SENTINEL_Exfil_Chat_API
{
    meta:
        description = "Datenabfluss über Telegram-Bot oder Discord-Webhook"
        severity = "high"
    strings:
        $t = "api.telegram.org/bot" ascii wide nocase
        $d = "discord.com/api/webhooks" ascii wide nocase
        $d2 = "discordapp.com/api/webhooks" ascii wide nocase
    condition:
        any of them
}

rule SENTINEL_Infostealer_Targets
{
    meta:
        description = "Greift auf mehrere Browser-/Wallet-Anmeldespeicher zu (Infostealer)"
        severity = "high"
    strings:
        $c1 = "\\Google\\Chrome\\User Data" ascii wide nocase
        $c2 = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        $c3 = "\\BraveSoftware\\Brave-Browser" ascii wide nocase
        $c4 = "logins.json" ascii wide nocase
        $c5 = "key4.db" ascii wide nocase
        $c6 = "Login Data" ascii wide
        $c7 = "wallet.dat" ascii wide nocase
        $c8 = "\\Exodus\\" ascii wide nocase
        $c9 = "\\Telegram Desktop\\tdata" ascii wide nocase
        $c10 = "Local State" ascii wide
    condition:
        4 of them
}

rule SENTINEL_Shadow_Copy_Deletion
{
    meta:
        description = "Löscht Schattenkopien (Ransomware-Vorbereitung)"
        severity = "critical"
    strings:
        $v1 = "vssadmin delete shadows" ascii wide nocase
        $v2 = "vssadmin.exe delete shadows" ascii wide nocase
        $v3 = "shadowcopy delete" ascii wide nocase
        $v4 = "wbadmin delete catalog" ascii wide nocase
        $v5 = "recoveryenabled no" ascii wide nocase
    condition:
        any of them
}

rule SENTINEL_LNK_Suspicious_Command
{
    meta:
        description = "Verknüpfung startet Skript-Interpreter"
        severity = "high"
    strings:
        $p1 = "powershell" ascii wide nocase
        $p2 = "mshta" ascii wide nocase
        $p3 = "cmd.exe" ascii wide nocase
        $p4 = "wscript" ascii wide nocase
        $p5 = "rundll32" ascii wide nocase
        $a1 = "http" ascii wide nocase
        $a2 = " -enc" ascii wide nocase
        $a3 = "hidden" ascii wide nocase
        $a4 = "iex" ascii wide nocase
        $a5 = "FromBase64" ascii wide nocase
        $a6 = "DownloadString" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and any of ($p*) and any of ($a*)
}
