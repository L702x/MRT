/* MRT - Generic Minecraft-mod infostealer catch-all.
 * Purpose: catch trojanized Fabric/Forge mods and loaders that are NOT in
 * the curated families (SilentNet/Donki/WeedHack/WXSGrabber), e.g. new
 * compromised mods such as the "MALWARE - compromised mods" set.
 * Scope: content-level rule for EXTRACTED .class files, decompiled sources
 * and process memory - NOT raw compressed JARs (browser SQL lives inside
 * deflated entries, like the Donki behavior rule). Pair with a ZIP entry
 * listing step in the pipeline.
 * Safety: legitimate mods never read browser credential stores, so the
 * rule requires at least one browser credential SQL string plus an
 * independent Discord/session-theft pivot. Never fires on SQL or Discord
 * strings alone.
 */
rule Minecraft_Infostealer_Generic {
    meta:
        author = "static analysis - compromised-mod triage"
        date = "2026-09-16"
        family = "minecraft-stealer"
        description = "Generic Java mod stealer: browser cred SQL + Discord/session theft in extracted classes"
    strings:
        $sql_login   = "SELECT origin_url, username_value, password_value FROM logins" ascii wide nocase
        $sql_cookie  = "SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies" ascii wide nocase
        $sql_mcusers = "SELECT username, uuid, access_token, refresh_token, expires FROM minecraft_users" ascii wide nocase
        $dc_api   = "discord.com/api/v9/users/@me" ascii wide nocase
        $dc_core  = "discord_desktop_core" ascii wide nocase
        $abe      = "app_bound_encrypted_key" ascii wide nocase
        $sess     = "accessToken" ascii wide
        $mc       = "minecraftInfo" ascii wide
        $tok      = "discordTokens" ascii wide
        $br       = "browserData" ascii wide
    condition:
        filesize < 10MB and
        (
            (1 of ($sql_*) and 1 of ($dc_api, $dc_core, $abe) and 1 of ($sess, $mc, $tok, $br)) or
            (2 of ($sql_*) and 1 of ($dc_api, $dc_core, $abe, $tok, $br))
        )
}
