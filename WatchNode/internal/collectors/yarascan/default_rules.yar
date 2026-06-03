/*
 * Sentinel SIEM — default in-memory YARA ruleset.
 * Bundled with the agent and materialised to disk at start. Operators can point
 * the collector at a richer ruleset via collectors.yara_memory.rules_file.
 * These are intentionally conservative (low false-positive) starter rules.
 */

rule Sentinel_MemScan_Test
{
    meta:
        description = "Test rule — fires if a process's memory contains the Sentinel test marker. Use it to validate the scanning pipeline."
        author      = "Sentinel SIEM"
    strings:
        $marker = "SENTINEL_YARA_MEMTEST"
    condition:
        $marker
}

rule CobaltStrike_Beacon_Indicators
{
    meta:
        description = "Generic Cobalt Strike beacon strings often resident in memory"
        reference   = "MITRE T1071 / T1620"
    strings:
        $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
        $s2 = "could not spawn %s"
        $s3 = "beacon.x64.dll" nocase
        $s4 = "ReflectiveLoader"
    condition:
        2 of them
}

rule Meterpreter_Indicators
{
    meta:
        description = "Meterpreter / Metasploit stager strings in memory"
        reference   = "MITRE T1055"
    strings:
        $a = "metsrv.dll" nocase
        $b = "core_channel_open"
        $c = "stdapi_sys_process_execute"
    condition:
        2 of them
}
