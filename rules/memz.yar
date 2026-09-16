/* MRT - MEMZ trojan rules.
 * Sample: Misc Malware/MEMZ-Clean.exe (12800 B).
 * Static-only markers: google.co.ck joke queries are unique to MEMZ
 * (Cook Islands domain, hardcoded query list), plus the clean-build
 * consent string. Low false-positive risk: legit software never
 * embeds google.co.ck search URLs.
 */
rule MEMZ_Trojan_Payload {
    meta:
        author = "static analysis - MEMZ-Clean.exe"
        date = "2026-09-16"
        family = "MEMZ"
        description = "MEMZ joke-trojan payload (google.co.ck query list + consent text)"
        sample = "MEMZ-Clean.exe"
    strings:
        $q1 = "google.co.ck/search?q=how+2+remove+a+virus" ascii nocase
        $q2 = "google.co.ck/search?q=minecraft+hax+download+no+virus" ascii nocase
        $q3 = "google.co.ck/search?q=how+to+remove+memz+trojan+virus" ascii nocase
        $q4 = "google.co.ck/search?q=my+computer+is+doing+weird+things+wtf+is+happenin+plz+halp" ascii nocase
        $q5 = "google.co.ck/search?q=how+to+download+memz" ascii nocase
        $g  = "google.co.ck/search?q=" ascii nocase
        $warn = "This payload is considered semi-harmful." ascii
        $memz = "MEMZ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        (
            ($warn and $g) or
            ($memz and 2 of ($q*)) or
            (3 of ($q*))
        )
}
