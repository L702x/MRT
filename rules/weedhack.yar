/* MRT - WeedHack rules. */

rule weedhack_stage1_jar {
  meta:
    family      = "WeedHack/Majanito MaaS stage-1"
    confidence  = "high"
    description = "WeedHack Stage-1 Fabric mod: JNIC native dir, thread_silent blob, or operator URI/contract markers"

  strings:
    $zip = { 50 4B 03 04 }
    $jnic_dir   = /native\/[0-9a-f]{16,}\// ascii
    $jnic_lib   = "dev/jnic/" ascii
    $silent_blob = "assets/thread_silent.dat" ascii
    $cfg        = "cfg.json" ascii
    $mod_kr     = "\"id\" : \"krloader\"" ascii
    $mod_loader = "\"id\" : \"loaderclient\"" ascii
    $mod_prest  = "\"id\" : \"prestigemod\"" ascii
    $mod_rypt   = "\"id\" : \"rypton\"" ascii
    $licensekey = "licenseKey" ascii
    $contract = "0x1280a841Fbc1F883365d3C83122260E0b2995B74" ascii nocase
    $exfil    = "/api/delivery/handler" ascii
    $module   = "/files/jar/module" ascii
    $stage2   = "dev.majanito.Main" ascii
    $init     = "initializeWeedhack" ascii
    $tmpdll   = "jvmtp-" ascii
    $jwflag   = "--jw" ascii
    $ethcall  = "eth_call" ascii
    $v1c2     = "receiver.cy" ascii nocase
    $doh      = "cloudflare-dns.com/dns-query" ascii
    $guid1    = "cdd17c3f-5a54-4c2e-8172-6c22f4f52b91" ascii
    $guid2    = "6170f432-a393-4e7b-9c8b-a4d1cf4062eb" ascii
    $guid3    = "f5e6d7b2-499e-462d-907e-12b4a93f25a7" ascii

  condition:
    $zip at 0 and filesize < 40MB and
    (
      ($jnic_dir and 1 of ($mod_kr, $mod_loader, $tmpdll)) or
      ($silent_blob and $mod_prest) or
      ($mod_rypt) or
      (2 of ($contract, $exfil, $module, $stage2, $init, $guid1, $guid2, $guid3))
    )
}

rule weedhack_rsa_config_key {
  meta:
    family      = "WeedHack/Majanito operator pivot"
    description = "Embedded RSA-2048 SubjectPublicKeyInfo prefix verifying blockchain-delivered C2 config; shared across KrLoader/Krypton/Prestige builds"
  strings:
    $der = { 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82 01 0F 00 30 82 01 0A 02 82 01 01 00 B2 66 37 }
  condition:
    $der
}
