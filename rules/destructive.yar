/* MRT - Destructive malware variant rules (complement the exact
 * size+SHA256 blocklist in main.go, which only catches the curated bytes).
 * Samples: Misc Malware/WannaCry.exe (3514368 B),
 *          Misc Malware/NotPetya/NotPetya.exe (362360 B).
 * Static-only markers below were read directly from those samples.
 */
rule Destructive_WannaCry_Variant {
    meta:
        author = "static analysis - WannaCry.exe"
        date = "2026-09-16"
        family = "destructive"
        description = "WannaCry ransomware: embedded .wnry names + propagation commands"
        sample = "WannaCry.exe (3514368 B)"
    strings:
        $t1 = "tasksche.exe" ascii
        $w1 = "t.wnry" ascii nocase
        $w2 = "c.wnry" ascii nocase
        $w3 = "b.wnry" ascii nocase
        $w4 = "r.wnry" ascii nocase
        $w5 = "s.wnry" ascii nocase
        $w6 = "u.wnry" ascii nocase
        $m1 = "WNcry@2ol7" ascii
        $m2 = "icacls . /grant Everyone:F /T /C /Q" ascii
        $m3 = "WanaCrypt0r" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 6MB and
        (
            ($t1 and 1 of ($w*, $m*)) or
            (2 of ($w*) and 1 of ($m*)) or
            (3 of ($w*))
        )
}

rule Destructive_NotPetya_Variant {
    meta:
        author = "static analysis - NotPetya.exe"
        date = "2026-09-16"
        family = "destructive"
        description = "NotPetya wiper: ransom text + CHKDSK masquerade + perfc marker"
        sample = "NotPetya.exe (362360 B)"
    strings:
        $r1 = "Ooops, your important files are encrypted." ascii
        $r2 = "Send $300 worth of Bitcoin" ascii
        $r3 = "CHKDSK is repairing sector" ascii
        $r4 = "perfc.dat" ascii
        $r5 = "Decrypting sector" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        (
            ($r1 and 1 of ($r2, $r3, $r4)) or
            ($r4 and 2 of ($r1, $r2, $r3, $r5))
        )
}
