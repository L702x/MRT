/*
  SilentNet infostealer YARA rules
  Research date: 2026-07-20 | Family: SilentNet MaaS infostealer (Minecraft mods / Java dropper)

  Covers:
    - Stage 1 Java dropper JARs (obfuscated "padded" + clean "no padding" variants)
    - Stage 2 unpacked Python bundle (NtProfileIndex staging dir)
    - Stage 1 EXE/DLL variant (DoubleClick / EXE / DLL env types)
    - Network / blockchain / crypto IOCs shared by all stages

  References (local, static analysis only):
    C:\MALWARE\Discord\silentnet                         (15 padded JAR samples)
    C:\MALWARE\Papers\silentnet-main\silentnet-main      (30 recovered Python modules + README IOCs)
    C:\MALWARE\Papers\doomed                             (sample no padding.jar + Launcher/Stealer/HttpsClient stage-1 source)
    C:\MALWARE\Discord\silentnet incompetence\payload_decrypted (decrypted Python 3.12 bundle + AppHost)

  NOTE on obfuscation: padded Stage-1 class strings are XOR-encrypted at rest, so
  plaintext C2 strings are NOT visible. Structural ZIP markers (LICENSE_github,
  assets/package/icon.png, large assets blob, com/github random classes, JDK API
  triple) are the reliable signal. The Go remover scores those structurally and
  only uses plaintext strings for the clean variant + Stage 2 + EXE.
*/

rule silentnet_jar_dropper_structural {
  meta:
    family      = "SilentNet"
    stage       = "stage1-jar"
    confidence  = "high"
    description = "SilentNet Stage-1 JAR: LICENSE_github + assets/package/icon.png + large assets blob + com/github obfuscated classes"
    // All 15 Discord samples + doomed samples share this layout. Legit mods never do.
    reference   = "fabric.mod.json id=package/sample, Main-Class=com.github.<random>"

  strings:
    // ZIP central-directory entry names (visible even when class strings are XORed)
    $lic_path   = "LICENSE_github" ascii
    $icon_path  = "assets/package/icon.png" ascii
    $gh_prefix  = "com/github/" ascii
    $fabric     = "fabric.mod.json" ascii
    $manifest_mc = "Main-Class: com.github." ascii
    // Large encrypted payload blob inside the JAR (900KB-18MB, random 8-char name)
    $blob_bin   = /assets\/[a-z]{8}\.(bin|cache|dat|cfg)/ ascii
    // SilentNet fabric.mod.json template markers
    $fabric_pkg = "\"id\" : \"package\"" ascii
    $fabric_smp = "\"id\" : \"sample\"" ascii
    $fabric_desc_core = "Core library module" ascii
    $fabric_team = "Package Team" ascii
    // JDK APIs co-occurring in the Stealer/Launcher class (never obfuscated)
    $jdk_pb     = "java/lang/ProcessBuilder" ascii
    $jdk_mkdir  = "createDirectories" ascii
    $jdk_getenv = "getenv" ascii
    $jdk_redir  = "ProcessBuilder$Redirect" ascii

  condition:
    uint16(0) == 0x4B50 and filesize < 30MB and
    (
      // Strong structural hit: the exact file combo seen in every sample
      ( $lic_path and $icon_path and $gh_prefix and $blob_bin ) or
      // Fallback: manifest + fabric + JDK triple (clean / rebuilt variants)
      ( $manifest_mc and $fabric and 2 of ($jdk_pb, $jdk_mkdir, $jdk_getenv, $jdk_redir) )
    )
}

rule silentnet_stage1_clean_strings {
  meta:
    family      = "SilentNet"
    stage       = "stage1-clean"
    confidence  = "high"
    description = "SilentNet Stage-1 plaintext markers (clean / no-padding JAR, EXE, deobfuscated classes)"

  strings:
    $p1  = "NtProfileIndex" ascii wide nocase
    $p2  = "LOCALAPPDATA" ascii wide
    $p3  = "_spawn.log" ascii wide
    $p4  = "-restarted" ascii wide
    $p5  = "AppHost" ascii wide
    $p6  = "main.py" ascii wide
    $p7  = "python.exe" ascii wide
    $p8  = "jre-embedded" ascii wide
    $p9  = "X-Runtime-Env" ascii wide
    $p10 = "0x9c0a507300fd902787bb193d80fca5ce6e1bff9a" ascii wide nocase
    $p11 = "0xce6d41de" ascii wide nocase
    $p12 = "ce6d41de" ascii wide nocase
    $p13 = "sltnnt.ru" ascii wide nocase
    $p14 = "thisisafalsepositive.st" ascii wide nocase
    $p15 = "silentnet.st" ascii wide nocase
    $p16 = "polygon" ascii wide nocase
    $p17 = "getDomain" ascii wide
    $p18 = "Microsoft\\Windows" ascii wide
    $p19 = "java.home" ascii wide
    $p20 = "bin/javaw.exe" ascii wide
    $p21 = "Stealer spawned: pid=" ascii wide

  condition:
    // Clean JAR class, EXE, or unpacked .class: require staging path + one more marker
    // so a stray "polygon" or "java.home" alone never fires.
    ( $p1 and 1 of ($p2, $p3, $p4, $p5, $p6, $p7, $p8) ) or
    ( 3 of ($p*) )
}

rule silentnet_stage2_bundle {
  meta:
    family      = "SilentNet"
    stage       = "stage2-python-bundle"
    confidence  = "high"
    description = "SilentNet Stage-2 unpacked bundle: NtProfileIndex/python.exe + AppHost/app.pyd + AppHost/main.py + python312.zip"

  strings:
    $a1 = "AppHost" ascii wide
    $a2 = "NtProfileIndex" ascii wide nocase
    $a3 = "NtProfileSync" ascii wide
    $a4 = "X-Runtime-Env" ascii wide
    $a5 = "jre-embedded" ascii wide
    $a6 = "/shard/submitData" ascii wide
    $a7 = "/shard/submitLogs" ascii wide
    $a8 = "/shard/prefireMc" ascii wide
    $a9 = "/cdn/e/" ascii wide
    $a10 = "python312.zip" ascii wide
    $a11 = "staging-worker" ascii wide
    $a12 = "74af664f79d1ef1436a4bf301788c7eb207570de60034b19d76df8e7aefc69b7" ascii wide nocase
    $a13 = "x-cdn-origin-verify" ascii wide nocase
    $a14 = "trusted-upstream" ascii wide
    $main_py_loader_1 = "spec_from_file_location" ascii wide
    $main_py_loader_2 = "spec.loader.exec_module" ascii wide

  condition:
    // Any single unpacked bundle file hitting staging+pipe, C2 paths, or the hardcoded Fernet key
    ( $a2 and 1 of ($a1, $a3, $a4, $a10) ) or
    ( 2 of ($a3, $a4, $a6, $a7, $a8, $a11, $a12, $a13) ) or
    ( all of ($main_py_loader_*) and $a1 )
}

rule silentnet_c2_indicators {
  meta:
    family      = "SilentNet"
    stage       = "c2-blockchain-crypto"
    confidence  = "medium"
    description = "SilentNet network / blockchain / crypto IOCs (confirm with another rule before deleting)"

  strings:
    $d1 = "thisisafalsepositive.st" ascii wide nocase
    $d2 = "sltnnt.ru" ascii wide nocase
    $d3 = "silentnet.st" ascii wide nocase
    $ip1 = "185.178.208.191" ascii wide
    $ip2 = "185.178.208.165" ascii wide
    $ct1 = "0x9c0a507300fd902787bb193d80fca5ce6e1bff9a" ascii wide nocase
    $ct2 = "0x6767c6496541b530a5d1d0eb9b80bd5c7bf56767" ascii wide nocase
    $sel = "ce6d41de" ascii wide nocase
    $hdr1 = "X-Runtime-Env" ascii wide
    $hdr2 = "X-Edge-Cache-Revalidate" ascii wide
    $hdr3 = "x-cdn-origin-verify" ascii wide
    $url1 = "/cdn/e/" ascii wide
    $url2 = "/shard/submitData" ascii wide
    $url3 = "/shard/submitLogs" ascii wide
    $url4 = "/shard/prefireMc" ascii wide
    $url5 = "/shard/submitFile" ascii wide
    $key = "74af664f79d1ef1436a4bf301788c7eb207570de60034b19d76df8e7aefc69b7" ascii wide nocase
    $pipe = "NtProfileSync" ascii wide
    $spawn = "_spawn.log" ascii wide

  condition:
    // Never convict on this rule alone: needs C2 domain/IP/contract AND a behavior marker.
    ( 1 of ($d1, $d2, $d3, $ip1, $ip2, $ct1) and 1 of ($hdr1, $url1, $url2, $url3, $url4, $key, $pipe, $spawn, $sel) ) or
    ( 3 of ($*) )
}
