rule DonkiStealer_Jar_Filenames_JNIC_Resistant {
    meta:
        author = "static analysis - Module.jar"
        date = "2026-09-11"
        hash_sha256 = "25B2E5E52C023EFB7D83201A5FD0EDFECA1642EF98CAB7B8069F45EE6FD7269B"
        description = "JNIC-resistant container rule. Matches ZIP entry names only, which JNIC preserves (it replaces method bodies with native stubs and adds native libs, but keeps .class entry names). Works on raw JAR bytes without decompression. Survives JNIC string encryption (stringObf) and method translation. Fails only if an additional Java name obfuscator renames com/example before JNIC - see behavior rule for that case."
        family = "Donki"
        sample = "Module.jar (unobfuscated)"
    strings:
        // ZIP local file header magic checked in condition, these are central-directory/local-header filenames (plaintext even when file data is DEFLATE-compressed)
        $jar_main      = "com/example/Main.class" ascii
        $jar_abepay    = "com/example/util/ABEPayloadReal.class" ascii
        $jar_dllinj    = "com/example/util/DllInjectionHelper.class" ascii
        $jar_handle    = "com/example/util/HandleDuplicator.class" ascii
        $jar_proc      = "com/example/util/ProcessHelper.class" ascii
        $jar_crypto    = "com/example/util/CryptoHelper.class" ascii
        $jar_rpc       = "com/example/util/RPCHelper.class" ascii
        $jar_staging   = "com/example/util/StagingHelper.class" ascii
        $jar_browser   = "com/example/handlers/browser/BrowserHandler.class" ascii
        $jar_discord   = "com/example/handlers/discord/DiscordHandler.class" ascii
        $jar_files     = "com/example/handlers/files/FileHandler.class" ascii
        $jar_logging   = "com/example/logging/LoggingManager.class" ascii
        $jar_w         = "com/example/handlers/WHandler.class" ascii
        // Shaded libs JNIC typically excludes from translation for size/perf - combo is distinctive (Minecraft MCA/NBT lib + stealer stack)
        $lib_querz_mca = "net/querz/mca/MCAFile.class" ascii
        $lib_querz_nbt = "net/querz/nbt/tag/CompoundTag.class" ascii
        $lib_jna_dll   = "com/sun/jna/win32-x86-64/jnidispatch.dll" ascii
        $lib_okhttp    = "okhttp3/OkHttpClient.class" ascii
    condition:
        uint32(0) == 0x04034b50 and
        (
            // strict: entry point + core stealer modules (unobfuscated or JNIC-only, no name obfuscation)
            ($jar_main and $jar_abepay and $jar_dllinj and $jar_browser and $jar_discord and $jar_files)
            or
            // tolerant: any 6 of the com/example entries + querz combo (handles partial include/exclude configs)
            (6 of ($jar_main, $jar_abepay, $jar_dllinj, $jar_handle, $jar_proc, $jar_crypto, $jar_rpc, $jar_staging, $jar_browser, $jar_discord, $jar_files, $jar_logging, $jar_w) and 1 of ($lib_*))
        )
}

rule DonkiStealer_Behavior_Strings {
    meta:
        author = "static analysis - Module.jar"
        date = "2026-09-11"
        hash_sha256 = "25B2E5E52C023EFB7D83201A5FD0EDFECA1642EF98CAB7B8069F45EE6FD7269B"
        description = "Content-level rule for extracted .class files, JNIC native libs (.dll/.so), and process memory. Uses only string literals, never bytecode opcodes (method bodies become native stubs under JNIC). Valid after JNIC when stringObf=false (the JNIC default) because literals migrate plaintext into the native lib .rdata; always valid in memory after decryption. Scan extracted JAR contents or memory, NOT raw compressed JAR, with this rule."
        family = "Donki"
        sample = "Module.jar (unobfuscated)"
    strings:
        // C2 resolution via Ethereum contract (most distinctive - decentralized C2 hiding)
        $c_contract = "0x9044f5762e43b23ba91d124b51a045f1b51da652" ascii wide nocase
        $c_selector = "0x1f1bd692" ascii wide nocase
        $c_ethcall  = "eth_call" ascii wide nocase
        // C2 endpoints (constructed as base+\"/api\"+\"/receive\"+suffix in Main.initialize)
        $u_receive  = "/api/receive" ascii wide nocase
        $u_sess     = "/sess" ascii wide nocase
        $u_dta      = "/DTA" ascii wide nocase
        $u_file     = "/file" ascii wide nocase
        $u_logs     = "/logs" ascii wide nocase
        $u_stage    = "/files/jar/security" ascii wide nocase
        $u_idxjs    = "/api/static/index.js" ascii wide nocase
        $u_track    = "X-Tracking-ID" ascii wide nocase
        // Exfil JSON keys
        $j_mc       = "minecraftInfo" ascii wide nocase
        $j_sys      = "systemInfo" ascii wide nocase
        $j_dc       = "discordTokens" ascii wide nocase
        $j_br       = "browserData" ascii wide nocase
        $j_fi       = "fileInfo" ascii wide nocase
        $j_fc       = "donkiFileInfos" ascii wide nocase
        $j_uuid     = "logUuid" ascii wide nocase
        // Family markers
        $f_donki    = "Initializing Donki" ascii wide nocase
        $f_staging  = "donki_staging" ascii wide nocase
        $f_secmgr   = "SecurityManager.jar" ascii wide nocase
        $f_majanito = "dev.majanito.security.Main" ascii wide nocase
        $f_pipe     = "abe_decrypt_" ascii wide nocase
        $f_appbound = "app_bound_encrypted_key" ascii wide nocase
        $f_dqw      = "dQw4w9WgXcQ:" ascii wide nocase
        $f_grind    = "[GRIND] entering" ascii wide nocase
        $f_roll     = "[ROLL] packing" ascii wide nocase
        $f_blazed   = "[BLAZED] sent" ascii wide nocase
        // Chrome ABE COM identity (must stay plaintext for CoCreateInstance to work)
        $clsid_chrome = "{708860E0-F641-4611-8895-7D867DD3675B}" ascii wide nocase
        $clsid_edge   = "{1FCBE96C-1697-43AF-9140-2897C7C69767}" ascii wide nocase
        // Browser extension ID (MetaMask) - high-entropy, family-specific exfil list
        $ext_mm = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide nocase
        // SQLite queries (stealer DB theft)
        $sql_login   = "SELECT origin_url, username_value, password_value FROM logins" ascii wide nocase
        $sql_cookie  = "SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies" ascii wide nocase
        $sql_mcusers = "SELECT username, uuid, access_token, refresh_token, expires FROM minecraft_users" ascii wide nocase
        $sql_token   = "SELECT service, encrypted_token" ascii wide nocase
        // Discord validation + injection
        $dc_api   = "discord.com/api/v9/users/@me" ascii wide nocase
        $dc_core  = "discord_desktop_core" ascii wide nocase
        // Persistence / staging
        $p_cfgdir = "SecurityUpdates" ascii wide nocase
        $p_sqlite = "sqlite-jdbc-3.23.1.jar" ascii wide nocase
    condition:
        (
            // anchor: on-chain C2 contract must be present (kills almost all FPs)
            $c_contract and
            (
                // plus any 4 behavior markers (endpoints / json / family / sql / discord / clsid / ext)
                4 of ($u_*, $j_*, $f_*, $clsid_*, $ext_*, $sql_*, $dc_*, $p_*, $c_selector, $c_ethcall)
            )
        )
        or
        (
            // no-contract fallback for memory fragments or partial native dumps: need strong combo
            8 of ($u_*, $j_*, $f_*, $clsid_*, $ext_*, $sql_*, $dc_*, $p_*, $c_selector, $c_ethcall)
        )
}
