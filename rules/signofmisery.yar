/* MRT - Sign of Misery rules (curated as Misc Malware/Krotten.exe).
 * Static-only markers: version string, author tag, contact address and
 * homepage are unique to CyberManiac's "InqSoft Sign 0f Misery" joke
 * malware. Policy strings (DisableTaskMgr/DisableRegistryTools) are
 * supporting only - never sufficient alone.
 */
rule SignOfMisery_JokeMalware {
    meta:
        author = "static analysis - Krotten.exe"
        date = "2026-09-16"
        family = "SignOfMisery"
        description = "InqSoft Sign 0f Misery annoyance malware (Krotten sample)"
        sample = "Krotten.exe (54569 B)"
    strings:
        $ver    = "InqSoft Sign 0f Misery" ascii nocase
        $author = "C0ded by CyberManiac" ascii nocase
        $mail   = "wordsia@notrix.de" ascii nocase
        $home   = "http://poetry.rotten.com/lightning/" ascii nocase
        $priv   = "SeSystemtimePrivilege" ascii
        $pol1   = "DisableTaskMgr" ascii
        $pol2   = "DisableRegistryTools" ascii
        $pol3   = "NoDispCPL" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 500KB and
        (
            ($ver and 1 of ($author, $mail, $home, $priv)) or
            (($author or $mail) and $home) or
            (3 of ($ver, $author, $mail, $home, $priv))
        )
}
