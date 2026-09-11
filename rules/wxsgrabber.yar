/*
  WXSGrabber — Fabric mod stealer + PowerShell RAT (Firebase C2)
  Internal sample name: "Krypton Client.jar" (distinct from WeedHack Krypton-1.0.0.jar!)
  Persistence: %APPDATA%\.sys-cache\ + HKCU Run FabricRuntimeInit/FabricListenerInit
  C2: https://api.x-grabber.com (header X-WXS-Build-Token), Firebase wxsgrabber-default-rtdb
  Reference: C:\MALWARE\Papers\Discord Malware\REPORT_WXSGrabber.md
*/

rule wxsgrabber_fabric_mod {
  meta:
    family      = "WXSGrabber"
    confidence  = "high"
    description = "WXSGrabber Fabric mod: wxsgrabber license/entrypoint markers or C2/persistence strings"

  strings:
    $zip = { 50 4B 03 04 }
    // Structural anchors (ZIP central directory)
    $lic    = "LICENSE_wxsgrabber-mod" ascii
    $modid  = "\"id\":\"my-mod\"" ascii
    $modid2 = "\"id\" : \"my-mod\"" ascii
    $modid3 = "\"id\":\"my-mod\"" ascii
    $impl   = "net.fabricmc.core.impl." ascii
    // Persistence + C2 markers (XOR-encoded at rest in some builds; plaintext in others)
    $persist = "wxsgrabber-persistence" ascii wide
    $hdr     = "X-WXS-Build-Token" ascii wide
    $run1    = "FabricRuntimeInit" ascii wide
    $run2    = "FabricListenerInit" ascii wide
    $stage   = ".sys-cache" ascii wide
    $rtdb    = "wxsgrabber-default-rtdb" ascii wide
    $api     = "api.x-grabber.com" ascii wide
    $jarname = "Krypton Client.jar" ascii wide
    $nss1    = "PK11SDR_Decrypt" ascii wide
    $nss2    = "NSS_Init" ascii wide
    $b64api  = "aHR0cHM6Ly9hcGkueC1ncmFiYmVyLmNvbQ==" ascii
    $b64ws   = "d3NjcmlwdC5leGU=" ascii
    $b64ps   = "cG93ZXJzaGVsbC5leGU=" ascii

  condition:
    $zip at 0 and filesize < 40MB and
    (
      ($lic) or
      ($impl and 1 of ($modid, $modid2, $modid3)) or
      ($impl and 2 of ($persist, $hdr, $run1, $run2, $stage, $rtdb, $api)) or
      (3 of ($persist, $hdr, $run1, $run2, $stage, $rtdb, $api))
    )
}
