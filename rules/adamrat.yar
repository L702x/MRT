/* MRT - AdamRAT rules.
 * Samples (filenames are SHA256):
 *   C:\MALWARE\AdamRAT_1\529b36bde7bdde783b9a568210a31535800c6f38891400fe237b0cb776ed1344.jar (117769 B)
 *   C:\MALWARE\AdamRAT_2\f2ddbcca6683eed8112b6213e330674f31d167794d627ff65fa144043ca645c8.jar (515861 B)
 *   C:\MALWARE\AdamRAT_3\a3c099c07405f0c11987d79f82b2db5755bcaca79fbaa50dae79ad485608aefc.exe (282112 B)
 *
 * Why these rules look the way they do (heavy obfuscation that crashes decompilers):
 * - Both JARs store every .class entry with a trailing slash (e.g.
 *   "com/example/ExampleModClient.class/"). Zip readers return them as
 *   directories (is_dir=True) with valid CAFEBABE payloads, so naive
 *   scanners that skip directories miss the malware and several
 *   decompilers choke on the names. The structural rule below matches the
 *   raw ZIP entry names (local + central directory, no decompression), so
 *   it survives string encryption and never parses bytecode.
 * - AdamRAT_1 main class is 342511 B uncompressed with 6563 constant-pool
 *   entries; AdamRAT_2 main class is 1166873 B with 46305 entries (near the
 *   65535 CP limit). Both use random 12-char lowercase method names,
 *   "nothing_to_see_here" decoys, Braille-block (U+2800) junk strings and
 *   AES (SecretKeySpec/IvParameterSpec/Cipher) runtime decryption. CFR /
 *   Fernflower / Procyon die on the oversized methods - all markers used
 *   here are extracted with a minimal constant-pool UTF8 walk, never a full
 *   decompile.
 * - AdamRAT_2 is additionally protected with qProtect 1.13.0 (marker in all
 *   4 classes), O0/O-letter class names (O0O0O0OOOO00, OO0OOOO000O00O) and
 *   one entry named '<html><img src="https:O0000O000OO00O0.class/' (HTML in
 *   filename to crash tooling that renders names). Its C2 strings are
 *   encrypted, so the behavior rule has a qProtect-specific branch that
 *   keys on protector + framework combo instead of plaintext C2.
 * - Shared builder markers across _1 and _2: META-INF/a1b2c3d4 content
 *   "tghj8ahrtuath8akfpoajngjao" (26 B), LICENSE_modid (7047 B CC0, same
 *   bytes as other builders - only the FILENAME is Adam-specific),
 *   fabric.mod.json id "modid" with feathermc.com contact, and a random
 *   "<hex>.txt" holding "<32hex>:<hexblob>" key material.
 * - The .exe is a native AdamRAT (ransomware + miner + stealer): wide
 *   strings "adamrat@protonmail.com", "adamratRansom", "adamratConsole",
 *   schtasks persistence, ransom note, shadow-copy/boot destruction,
 *   Defender tampering, bank-doc theft and xmrig fetch. No Java markers.
 */

rule AdamRAT_Jar_Structural {
    meta:
        author = "static analysis - AdamRAT_1 / AdamRAT_2"
        date = "2026-09-27"
        family = "AdamRAT"
        description = "AdamRAT Fabric JAR container: trailing-slash .class entries + builder filenames. Works on raw JAR bytes without decompression; survives qProtect string encryption and decompiler-crashing control flow. Pair with the behavior rule on extracted classes."
        hash_sha256_1 = "529b36bde7bdde783b9a568210a31535800c6f38891400fe237b0cb776ed1344"
        hash_sha256_2 = "f2ddbcca6683eed8112b6213e330674f31d167794d627ff65fa144043ca645c8"
        reference = "C:\\MALWARE\\AdamRAT_1, C:\\MALWARE\\AdamRAT_2"
    strings:
        $a1     = "META-INF/a1b2c3d4" ascii
        $lic    = "LICENSE_modid" ascii
        $slash  = /\.class\// ascii
        $comex  = "com/example/" ascii
        $vub    = "vubsyodfkejzllnk" ascii
        $html   = "<html><img" ascii
        $o0     = /O0O0[O0]{2,}/ ascii
    condition:
        uint32(0) == 0x04034b50 and filesize < 30MB and
        (
            ($a1 and $lic and $slash) or
            ($a1 and $slash and $comex) or
            ($html and $slash) or
            ($html and $a1) or
            ($vub and $slash) or
            ($a1 and $vub) or
            ($a1 and $o0 and $slash)
        )
}

rule AdamRAT_Jar_Behavior_Extracted {
    meta:
        author = "static analysis - AdamRAT_1 / AdamRAT_2"
        date = "2026-09-27"
        family = "AdamRAT"
        description = "AdamRAT extracted-class behavior: RAT config keys + Discord session markdown, or qProtect + framework combo for the string-encrypted variant. Scan decompressed .class bytes or process memory, NOT raw compressed JAR (deflated entries hide these strings raw)."
        scope = "extracted-content"
        hash_sha256_1 = "529b36bde7bdde783b9a568210a31535800c6f38891400fe237b0cb776ed1344"
        hash_sha256_2 = "f2ddbcca6683eed8112b6213e330674f31d167794d627ff65fa144043ca645c8"
        reference = "C:\\MALWARE\\AdamRAT_1, C:\\MALWARE\\AdamRAT_2"
    strings:
        $c_webhook = "userWebhook" ascii wide
        $c_ratfile = "ratfileUrl" ascii wide
        $c_dl      = "downloadUrl" ascii wide
        $c_always  = "alwaysUrl" ascii wide
        $c_session = "**Session ID:**" ascii wide
        $c_nothing = "nothing_to_see_here" ascii wide
        $c_vub     = "vubsyodfkejzllnk" ascii wide
        $c_dec1    = "zxkwwwcfzrkllevf" ascii wide
        $c_aes1    = "javax/crypto/Cipher" ascii
        $c_aes2    = "javax/crypto/spec/SecretKeySpec" ascii
        $c_aes3    = "javax/crypto/spec/IvParameterSpec" ascii
        $c_pb1     = "java/lang/ProcessBuilder" ascii
        $c_pb2     = "createDirectories" ascii
        $c_pb3     = "getenv" ascii
        $c_gson1   = "com/google/gson/JsonObject" ascii
        $c_gson2   = "com/google/gson/JsonArray" ascii
        $c_qp      = "qProtect" ascii wide
        $c_o0      = /O0O0[O0]{4,}/ ascii
        $c_comex   = "com/example/" ascii wide
        $c_lure1   = "targetUsername" ascii wide
        $c_lure2   = "maxPlaytime" ascii wide
        $c_lure3   = "maxMoney" ascii wide
        $c_jar     = "java/util/jar/JarFile" ascii
        $c_http    = "java/net/HttpURLConnection" ascii
        $c_mc      = "net/minecraft/class_310" ascii
    condition:
        filesize < 2MB and
        (
            (2 of ($c_webhook, $c_ratfile, $c_dl, $c_always)) or
            ($c_session and 1 of ($c_webhook, $c_ratfile, $c_dl, $c_gson1, $c_gson2)) or
            ($c_nothing and $c_vub) or
            ($c_nothing and 1 of ($c_webhook, $c_ratfile, $c_dec1, $c_vub)) or
            ($c_nothing and 1 of ($c_lure*)) or
            ($c_vub and $c_dec1) or
            ($c_qp and $c_o0 and $c_comex) or
            ($c_qp and $c_o0 and 1 of ($c_pb1, $c_aes1, $c_gson1, $c_http, $c_jar)) or
            ($c_mc and all of ($c_aes*) and $c_jar and 1 of ($c_pb*))
        )
}

rule AdamRAT_Exe_Native {
    meta:
        author = "static analysis - AdamRAT_3"
        date = "2026-09-27"
        family = "AdamRAT"
        description = "AdamRAT native EXE: adamrat identity + ransom/miner/destructive pivots"
        hash_sha256 = "a3c099c07405f0c11987d79f82b2db5755bcaca79fbaa50dae79ad485608aefc"
        sample = "a3c099c07405f0c11987d79f82b2db5755bcaca79fbaa50dae79ad485608aefc.exe (282112 B)"
        reference = "C:\\MALWARE\\AdamRAT_3"
    strings:
        $a1 = "adamrat@protonmail.com" ascii wide nocase
        $a2 = "adamratRansom" ascii wide
        $a3 = "adamratConsole" ascii wide
        $a4 = "schtasks /create /tn \"adamrat\"" ascii wide
        $r1 = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $r2 = "Send 1 Bitcoin to:" ascii wide
        $r3 = "Send 0.5 Bitcoin to:" ascii wide
        $r4 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" ascii wide
        $r5 = "RansomwareOverlayClass" ascii wide
        $r6 = "i live here now sorry your gonna need a new pc" ascii wide nocase
        $p1 = "vssadmin delete shadows /all /quiet" ascii wide
        $p2 = "wmic shadowcopy delete" ascii wide nocase
        $p3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $p4 = "reagentc /disable" ascii wide nocase
        $p5 = "wevtutil cl System" ascii wide
        $p6 = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide
        $p7 = "http://c2.malicious.xyz/xmrig.exe" ascii wide
        $p8 = "www.threat.rip" ascii wide
        $t1 = "oC78inB5bZ4" ascii wide
        $t2 = "rick-roll.mp3" ascii wide nocase
        $s1 = "Killing taskmgr..." ascii wide
        $s2 = "Bypassing UAC..." ascii wide
        $s3 = "Stealing bank info..." ascii wide
        $s4 = "Destroying boot..." ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        (
            (2 of ($a*)) or
            (1 of ($a*) and 2 of ($r*, $p*, $s*, $t*)) or
            (1 of ($a*) and $r4) or
            (1 of ($a*) and $p7)
        )
}
