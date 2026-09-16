import "hash"

/* MRT - Discord .infected collection coverage.
 * Every rule below was built from static analysis of files ending in
 * .infected under C:\MALWARE\Discord. Confidence is stated per rule:
 * CONFIRMED = credential theft / payload-download behavior observed in
 * code or strings; SUSPICIOUS = distinctive loader/C2/auth framework
 * that warrants review; hash-pinned = packed or otherwise opaque sample
 * with no static pivots (exact SHA256, zero false-positive risk, but no
 * behavior claim). Raw-JAR rules match ZIP entry names (visible without
 * decompression); content rules are for extracted classes / binaries /
 * memory, like the Donki behavior rule.
 */

/* ---------------- CONFIRMED stealers / loaders ---------------- */

rule Discord_DR4t_CookieStealer {
    meta:
        author = "static analysis - DR4t.jar.infected"
        date = "2026-09-16"
        family = "DR4t"
        confidence = "high"
        description = "Cookie stealer with hardcoded attacker webhook (CookieStealer class + full webhook URL)"
        sample_sha256 = "a8b9330300b8f96fde7b04606eab7d95"
    strings:
        $cls  = "CookieStealer" ascii wide
        $whid = "1483463708444463105" ascii wide
        $wh   = "discord.com/api/webhooks/1483463708444463105/" ascii wide nocase
        $prof = "api.minecraftservices.com/minecraft/profile" ascii wide nocase
        $hyp  = "api.hypixel.net/player" ascii wide nocase
    condition:
        filesize < 10MB and
        (
            ($cls and $whid) or
            ($wh and 1 of ($prof, $hyp, $cls))
        )
}

rule Discord_Groov_PayloadDownloader {
    meta:
        author = "static analysis - groov.exe.infected"
        date = "2026-09-16"
        family = "Groov"
        confidence = "high"
        description = "In-memory payload downloader (MemoryClassLoader bootstrap fetching payload.jar)"
        sample_sha256 = "da77979eaaf8859b3ab2436d262241b6"
    strings:
        $boot1 = "dev/groov/bootstrap/Bootstrap" ascii wide
        $boot2 = "dev.groov.bootstrap.Bootstrap" ascii wide
        $memcl = "MemoryClassLoader" ascii wide
        $memh  = "MemoryURLStreamHandler" ascii wide
        $host  = "groov-api.virginclient.xyz" ascii wide nocase
        $pay   = "/groov/payload.jar" ascii wide
        $auth  = "/groov/api/v1/auth/verify" ascii wide
    condition:
        filesize < 10MB and
        (
            ($boot1 and $memcl and $host) or
            ($memcl and $pay) or
            ($host and $auth)
        )
}

/* ---------------- SUSPICIOUS frameworks / C2 ---------------- */

rule Discord_Anamvmnt_KeyBeacon {
    meta:
        author = "static analysis - Anamvmnt-2.0.jar.infected"
        date = "2026-09-16"
        family = "Anamvmnt"
        confidence = "medium"
        description = "Cheat license beacon POSTing to bare-IP endpoint (review: same shape as stealer check-ins)"
        sample_sha256 = "fefba413153c5cec2e76fb9984fbf5ba"
    strings:
        $fn  = "isKeyValidWithServer" ascii wide
        $ip  = "45.131.65.84" ascii wide
        $act = "/activate" ascii wide
        $ep  = "cl.class" ascii
    condition:
        filesize < 40MB and (($fn and $ip) or ($fn and $act and $ip))
}

rule Discord_Flower_PartyC2 {
    meta:
        author = "static analysis - Flower.jar.infected"
        date = "2026-09-16"
        family = "Flower"
        confidence = "medium"
        description = "Remote party/token service on free-hosting C2 plus local handshake listener"
        sample_sha256 = "574812364bb4150d61e6c05d539df5a2"
    strings:
        $h1 = "bybybybyvich.pythonanywhere.com" ascii wide nocase
        $p1 = "/party/state" ascii wide
        $h2 = "vorkis.pythonanywhere.com/token/verify" ascii wide nocase
        $lh = "localhost:3648/api/handshake" ascii wide
        $ep = "org/flower/Flower" ascii
    condition:
        filesize < 40MB and
        (
            ($h1 and $p1) or
            ($h1 and $h2) or
            ($h2 and $lh)
        )
}

rule Discord_Aoa12_AgentBlob {
    meta:
        author = "static analysis - aoa12.jar.infected"
        date = "2026-09-16"
        family = "aoa12"
        confidence = "medium"
        description = "Java agent (premain + retransformation) carrying encrypted blob; entry names survive packing"
        sample_sha256 = "a68f730f5a1d817012503bf29422777d"
    strings:
        $zip = { 50 4B 03 04 }
        $pre = "Premain-Class: net.java.f" ascii
        $ret = "Can-Retransform-Classes: true" ascii
        $main = "Main-Class: net.java.m" ascii
        $blob = "5GFV7P3VIM5AK" ascii
        $cls  = "net/java/f.class" ascii
    condition:
        $zip at 0 and filesize < 10MB and
        (
            ($pre and $blob) or
            ($pre and $ret and $main) or
            ($blob and $cls)
        )
}

rule Discord_Hitmod_Loader {
    meta:
        author = "static analysis - Hitmod-1.0.5 / ukus_Armor_HUD (shared com/example loader)"
        date = "2026-09-16"
        family = "HitmodLoader"
        confidence = "medium"
        description = "Custom classloader + HTTP layer hiding behind template names (JNIC-resistant entry names)"
        sample_sha256_hitmod = "31fb5f91e27fccb7e68aa1d0e5635aaf"
        sample_sha256_ukus = "8869e7586c5a429d1ff0470fd08c0ce5"
    strings:
        $zip = { 50 4B 03 04 }
        $e1 = "com/example/Entrypoint.class" ascii
        $e2 = "com/example/ExampleMixin.class" ascii
        $e3 = "com/example/ExampleMod.class" ascii
        $e4 = "com/example/FabricAdapter.class" ascii
        $e5 = "com/example/Helper.class" ascii
        $jvm = "checkJVMLauncher" ascii wide
        $cdf = "classDefinitions" ascii wide
    condition:
        $zip at 0 and filesize < 10MB and
        (
            (4 of ($e*)) or
            (2 of ($e*) and $jvm and $cdf)
        )
}

rule Discord_Boost_Telemetry {
    meta:
        author = "static analysis - boostisraeledition.dll.infected"
        date = "2026-09-16"
        family = "Boost"
        confidence = "medium"
        description = "Cheat DRM/telemetry: HWID gate to bare-IP C2 plus hardcoded Discord webhooks"
        sample = "boostisraeledition.dll.infected"
    strings:
        $u1 = "BOOST_URL_GET_HWIDS" ascii wide
        $u2 = "BOOST_URL_WEBHOOK_IRC" ascii wide
        $c2 = "43.226.0.154:5000/get_hwids" ascii wide
        $rs = "remember_session_v2.dat" ascii wide
        $ws = "WebhookSender" ascii wide
        $w1 = "discord.com/api/webhooks/1404099194175619203/" ascii wide nocase
        $w2 = "discord.com/api/webhooks/1454133663368482816/" ascii wide nocase
    condition:
        filesize < 20MB and
        (
            ($u1 and $c2) or
            ($u1 and $rs) or
            (1 of ($w1, $w2) and $c2)
        )
}

rule Discord_DuckClient_Backend {
    meta:
        author = "static analysis - DuckClient_2.0.apk.infected"
        date = "2026-09-16"
        family = "DuckClient"
        confidence = "medium"
        description = "Android cheat licensing/analytics backend (key registration + link actions)"
        sample = "DuckClient_2.0.apk.infected (87 MB, 36 dex)"
    strings:
        $api = "duckapi.scienceontheweb.net" ascii wide nocase
        $reg = "action=register_key" ascii wide
        $lnk = "action=getlink" ascii wide
        $clk = "action=click" ascii wide
    condition:
        filesize < 150MB and
        (
            ($api and $reg) or
            ($api and $lnk)
        )
}

rule Discord_Slither_Framework {
    meta:
        author = "static analysis - VelarisRecode-4.3.5 (full framework; older Slither builds lack it)"
        date = "2026-09-16"
        family = "Slither"
        confidence = "medium"
        description = "Remote-bootstrap loader framework (pre-launch remote deps + child loaders + log cleaner)"
        sample_sha256 = "bca00c451d4ccdcd631d5846cf294ff4"
    strings:
        $r1 = "com/slither/velaris/util/RemoteDeps" ascii
        $r2 = "VelarisRemoteClassLoader" ascii
        $r3 = "ClassPackRuntime" ascii
        $r4 = "LogCleaner" ascii
        $r5 = "RemoteClassFetcher" ascii
        $r6 = "VelarisRemoteBootstrap" ascii
        $r7 = "NativeLoader" ascii
    condition:
        filesize < 40MB and (4 of ($r*))
}

rule Discord_Slither_Distributor {
    meta:
        author = "static analysis - Velaris x4 + cyemer-1.21.11 (shared slither codebase)"
        date = "2026-09-16"
        family = "Slither"
        confidence = "low"
        description = "Slither distributor fingerprint (package + shared assets); cheat, review before removal"
    strings:
        $zip = { 50 4B 03 04 }
        $pkg = "com/slither/" ascii
        $a1  = "astolfo.png" ascii
        $a2  = "frieren.png" ascii
        $a3  = "semibold.ttf" ascii
        $lc  = "LogCleaner" ascii
    condition:
        $zip at 0 and filesize < 60MB and ($pkg and 2 of ($a1, $a2, $a3, $lc))
}

rule Discord_FeatherEnv_Spoof {
    meta:
        author = "static analysis - feather-env-1.0.0-obf.jar.infected"
        date = "2026-09-16"
        family = "FeatherEnv"
        confidence = "medium"
        description = "Obfuscated mod impersonating Sodium (real id, authors, fake future MC version)"
        sample_sha256 = "f56d29a22f708fd46b5793ef536cde4c"
    strings:
        $zip = { 50 4B 03 04 }
        $id  = "\"id\": \"sodium\"" ascii
        $nm  = "\"name\": \"Sodium\"" ascii
        $ep  = "dev.recode.astro.AstroRecode" ascii
        $ver = "\"minecraft\": \"26.1\"" ascii
    condition:
        $zip at 0 and filesize < 40MB and
        (
            ($id and $nm and $ep) or
            ($ep and $ver)
        )
}

rule Discord_InjectableArgon_Agent {
    meta:
        author = "static analysis - injectableargon.jar.infected"
        date = "2026-09-16"
        family = "InjectableArgon"
        confidence = "medium"
        description = "Java-agent injector that fetches remote jars (agent + downloader combo)"
        sample_sha256 = "74b9d534e3a7c5080132c187ba3ded5e"
    strings:
        $zip = { 50 4B 03 04 }
        $am  = "dev/injection/agent/Main.class" ascii
        $ag  = "dev/lvstrng/argon/Main" ascii
        $pm  = "premain" ascii wide
        $im  = "AgentMain" ascii wide
        $dl  = "ImmediatelyFast-Fabric" ascii
    condition:
        $zip at 0 and filesize < 10MB and
        (
            ($am and $ag) or
            ($am and $pm and $dl)
        )
}

rule Discord_FrenchPacket_Cheat {
    meta:
        author = "static analysis - FrenchPacket.dll.infected"
        date = "2026-09-16"
        family = "FrenchPacket"
        confidence = "medium"
        description = "Bedrock packet cheat (MinHook packet hooks + ImGui overlay); cheat, review before removal"
        sample_sha256 = "d89984831b1e55731d514ca996312d37"
    strings:
        $n1 = "French Packet" ascii wide
        $p1 = "[PacketV2]" ascii wide
        $p2 = "ContainerScreenController::_isCursorSelectedActive" ascii wide
        $p3 = "LoopbackPacketSender::sendPacket" ascii wide
        $p4 = "packetv2.log" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and
        (
            ($n1 and 1 of ($p*)) or
            (3 of ($p*))
        )
}

/* ---------------- hash-pinned uncharacterized ----------------
 * Exact size+SHA256 pins for packed/opaque Discord samples with no
 * static pivots. Zero false-positive risk; behavior intentionally
 * unclaimed - re-analyze after unpacking. Uses the YARA hash module
 * (imported at the top of this file).
 */

rule Discord_Uncharacterized_PremiumDLL {
    meta:
        family = "uncharacterized"
        confidence = "low"
        description = "Packed 25MB cheat DLL, strings obfuscated, no imports visible (hash pin)"
        sample = "Premium (1).dll.infected"
    condition:
        filesize == 25947648 and
        hash.sha256(0, filesize) == "c2fc2347a5961bff315fb462260b3c2653db8dee4f6921bfd341058625429959"
}

rule Discord_Uncharacterized_MainEXE {
    meta:
        family = "uncharacterized"
        confidence = "low"
        description = "115MB PyInstaller bundle with crypto lib, no network indicators visible (hash pin)"
        sample = "main.exe.infected"
    condition:
        filesize == 115831378 and
        hash.sha256(0, filesize) == "5a87660501b12d5b72bff6ee2df06480f533e9ef803707d1ed6cec01d582e76a"
}

rule Discord_Uncharacterized_MCUnlocker {
    meta:
        family = "uncharacterized"
        confidence = "low"
        description = "22MB PyInstaller CustomTkinter unlocker tool, no network indicators visible (hash pin)"
        sample = "MinecraftUnlocker.exe.infected"
    condition:
        filesize == 22224386 and
        hash.sha256(0, filesize) == "0524c41cdbd2612e60ea67e85c77c9aad2bd78f0b0a0ce34db8e2c2f0000efa8"
}

rule Discord_Uncharacterized_RattedZipExe {
    meta:
        family = "uncharacterized"
        confidence = "low"
        description = "Deceptive .zip.exe naming ('ratted file'), no static pivots recovered (hash pin)"
        sample = "ratted file.zip.exe.infected"
    condition:
        filesize == 3016008 and
        hash.sha256(0, filesize) == "ddef2a756beb4cbc1cb5dd2a4483a7862bcb66409f930fab7ad0b0f62a97f60a"
}

rule Discord_Uncharacterized_InjectorEXE {
    meta:
        family = "uncharacterized"
        confidence = "low"
        description = ".NET injector with HTTP client, no C2 recovered statically (hash pin)"
        sample = "injector.exe.infected"
    condition:
        filesize == 197277 and
        hash.sha256(0, filesize) == "3f191f8f9e1d0abfd3977670ce3e35bad00853203746aa085bea4de2d2ba31d3"
}

rule Discord_Uncharacterized_RyoikiSetup {
    meta:
        family = "uncharacterized"
        confidence = "low"
        description = "195MB NSIS installer for Electron launcher, payload not evaluated (hash pin)"
        sample = "Ryoiki Launcher Setup 1.0.0.exe.infected"
    condition:
        filesize == 195225654 and
        hash.sha256(0, filesize) == "05ea927010c80da7c68f2717906f126cbc47fe7c662e98b202a8316b7b556147"
}

rule Discord_Uncharacterized_RespocketZip {
    meta:
        family = "uncharacterized"
        confidence = "low"
        description = "VPN-bypass loader bundle (Bypass/wintun/SQLite), empty config dir (hash pin)"
        sample = "respocket.zip.infected"
    condition:
        filesize == 60808134 and
        hash.sha256(0, filesize) == "b9493af42cf34d2ce294ef57c7d5acf3cb21a2a406eeef1e77b9c9edce6560f6"
}

rule Discord_Uncharacterized_FrenchPacketZip {
    meta:
        family = "FrenchPacket"
        confidence = "low"
        description = "FrenchPacket cheat bundle archive (hash pin; see FrenchPacket_Cheat for strings)"
        sample = "FrenchPacket.zip.infected"
    condition:
        filesize == 2640274 and
        hash.sha256(0, filesize) == "d383a8e86f88ac672269562686bcf3927603659c83165f5371e36a5e37dd0761"
}
