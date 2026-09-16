/* MRT - Generic (sample-independent) rules.
 * These fire on behavior combinations, never on single strings that also
 * occur in legitimate software. Scope notes are per-rule: content rules
 * marked "extracted" are for decompiled classes / script bodies / memory,
 * NOT raw compressed JARs (deflated entries hide their strings raw).
 */

rule Generic_DefenderTamper_EncodedExec {
    meta:
        author = "MRT default flags"
        date = "2026-09-16"
        family = "generic"
        description = "Defender/AMSI tampering combined with encoded PowerShell execution"
    strings:
        $def1 = "Add-MpPreference" ascii wide nocase
        $def2 = "Set-MpPreference" ascii wide nocase
        $def3 = "DisableRealtimeMonitoring" ascii wide nocase
        $def4 = "DisableBehaviorMonitoring" ascii wide nocase
        $def5 = "DisableIOAVProtection" ascii wide nocase
        $def6 = "AmsiScanBuffer" ascii wide
        $ps1  = "powershell" ascii wide nocase
        $ps2  = "pwsh" ascii wide nocase
        $enc  = "-EncodedCommand" ascii wide nocase
        $b64  = "FromBase64String" ascii wide
        $iex  = "Invoke-Expression" ascii wide
    condition:
        filesize < 20MB and
        (
            (1 of ($def*) and 1 of ($ps1, $ps2, $enc, $b64, $iex)) or
            (($ps1 or $ps2) and ($enc or ($b64 and $iex)))
        )
}

rule Generic_CredTheft_Combo {
    meta:
        author = "MRT default flags"
        date = "2026-09-16"
        family = "generic"
        description = "Browser credential-store access combined with Discord/session exfil pivot (scan extracted classes, scripts, or memory - NOT raw compressed JAR)"
        scope = "extracted-content"
    strings:
        $sql_login   = "SELECT origin_url, username_value, password_value FROM logins" ascii wide nocase
        $sql_cookie  = "SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies" ascii wide nocase
        $sql_mcusers = "SELECT username, uuid, access_token, refresh_token, expires FROM minecraft_users" ascii wide nocase
        $short1 = "FROM logins" ascii wide nocase
        $short2 = "FROM cookies" ascii wide nocase
        $short3 = "Login Data" ascii wide
        $short4 = "Web Data" ascii wide
        $dc_api   = "discord.com/api/v9/users/@me" ascii wide nocase
        $dc_core  = "discord_desktop_core" ascii wide nocase
        $abe      = "app_bound_encrypted_key" ascii wide nocase
        $wh1      = "discord.com/api/webhooks" ascii wide nocase
        $wh2      = "discordapp.com/api/webhooks" ascii wide nocase
        $sess     = "accessToken" ascii wide
        $mc       = "minecraftInfo" ascii wide
        $tok      = "discordTokens" ascii wide
        $br       = "browserData" ascii wide
    condition:
        filesize < 10MB and
        (
            (1 of ($sql_*) and 1 of ($dc_api, $dc_core, $abe, $wh1, $wh2) and 1 of ($sess, $mc, $tok, $br)) or
            (2 of ($sql_*) and 1 of ($dc_api, $dc_core, $abe, $wh1, $wh2, $tok, $br)) or
            (2 of ($short*) and 1 of ($dc_api, $dc_core, $abe, $wh1, $wh2))
        )
}

rule Generic_Persistence_Launcher_Combo {
    meta:
        author = "MRT default flags"
        date = "2026-09-16"
        family = "generic"
        description = "Autorun/scheduled-task persistence wired to a hidden script interpreter"
    strings:
        $run1 = "CurrentVersion\\Run" ascii wide
        $run2 = "CurrentVersion\\RunOnce" ascii wide
        $sch1 = "schtasks" ascii wide nocase
        $sch2 = "/create" ascii wide
        $cmstp = "cmstp.exe" ascii wide nocase
        $inf   = ".inf" ascii wide
        $wsh  = "wscript" ascii wide nocase
        $psh  = "powershell" ascii wide nocase
        $hid1 = "-WindowStyle Hidden" ascii wide nocase
        $hid2 = "-W Hidden" ascii wide nocase
        $vbs  = ".vbs" ascii wide nocase
    condition:
        filesize < 20MB and
        (
            ((1 of ($run*)) and (1 of ($wsh, $psh, $hid1, $hid2, $vbs))) or
            ($sch1 and $sch2 and (1 of ($wsh, $psh, $hid1, $hid2, $vbs))) or
            ($cmstp and $inf)
        )
}
