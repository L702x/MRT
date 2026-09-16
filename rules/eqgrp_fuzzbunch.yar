/* MRT - Equation Group (EQGRP Lost in Translation) FUZZBUNCH rules.
 * Samples: Exploits/EQGRP_Lost_in_Translation/windows/{payloads,exploits,fuzzbunch}.
 * Static-only markers: DoublePulsar XML parameter names, backdoor
 * descriptions and ETERNAL*/EDUCATED*/ECLIPSED* codenames. Single
 * codenames are weak alone (they can appear in research writeups), so
 * the conditions require pairs or framework combinations.
 */
rule EQGRP_DoublePulsar_Config {
    meta:
        author = "static analysis - windows/payloads/Doublepulsar-1.3.1.0.xml"
        date = "2026-09-16"
        family = "EQGRP"
        description = "DoublePulsar SMB/RDP ring-0 backdoor config (FUZZBUNCH payload)"
    strings:
        $p1 = "DOUBLEPULSAR_PROTOCOL_TYPE" ascii
        $p2 = "DOUBLEPULSAR_FUNCTION_TYPE" ascii
        $p3 = "DOUBLEPULSAR_ARCHITECTURE_TYPE" ascii
        $p4 = "DOUBLEPULSAR_DLL_PAYLOAD" ascii
        $d1 = "Port used by the Double Pulsar back door" ascii
        $d2 = "Ring 0 SMB (TCP 445) backdoor" ascii
        $d3 = "Ring 0 RDP (TCP 3389) backdoor" ascii
        $d4 = "Test for presence of backdoor" ascii
    condition:
        filesize < 2MB and
        (
            (2 of ($p*)) or
            (1 of ($p*) and 1 of ($d*)) or
            ($d2 and $d3)
        )
}

rule EQGRP_Fuzzbunch_Framework {
    meta:
        author = "static analysis - windows/Fuzzbunch.xml"
        date = "2026-09-16"
        family = "EQGRP"
        description = "FUZZBUNCH framework config (banner + operator DSZOPSDISK paths)"
    strings:
        $fb     = "Fuzzbunch" ascii nocase
        $banner = "FuZZbuNch" ascii
        $dsz    = "DSZOPSDISK" ascii
        $res    = "Resources Directory" ascii
        $log    = "D:\\logs" ascii
    condition:
        filesize < 2MB and
        (
            ($fb and $banner) or
            ($fb and $dsz) or
            ($banner and $dsz)
        )
}

rule EQGRP_EternalFamily_Exploit {
    meta:
        author = "static analysis - windows/exploits/*.xml"
        date = "2026-09-16"
        family = "EQGRP"
        description = "ETERNAL/EDUCATED/ECLIPSED-family SMB exploit configs (per-file)"
    strings:
        $cfg = "configversion" ascii nocase
        $ns1 = "urn:trch" ascii
        $ns2 = "xmlns:t=" ascii
        $ns3 = "xmlns=" ascii
        $e1  = "Eternalromance" ascii nocase
        $e2  = "Eternalsynergy" ascii nocase
        $e3  = "Esteemaudit" ascii nocase
        $e4  = "Explodingcan" ascii nocase
        $e5  = "Educatedscholar" ascii nocase
        $e6  = "Eclipsedwing" ascii nocase
        $e7  = "Englishmansdentist" ascii nocase
        $e8  = "Emeraldthread" ascii nocase
        $e9  = "Doublepulsar" ascii nocase
    condition:
        filesize < 2MB and $cfg and 1 of ($e*) and 1 of ($ns1, $ns2, $ns3)
}
