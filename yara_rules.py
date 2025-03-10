# yara_rules.py
yara_rules = """
rule Invoke_Expression_Obfuscation
{
    meta:
        description = "Detects Invoke-Expression with potential obfuscation"
        severity = "high"
    strings:
        $invoke_exp = /Invoke-Expression\\s+\\(.*\\)/ nocase
        $encoded_cmd = /-EncodedCommand\\s+/ nocase
    condition:
        $invoke_exp or $encoded_cmd
}

rule Suspicious_Base64_Usage
{
    meta:
        description = "Detects suspicious Base64 decoding often used in payloads"
        severity = "medium"
    strings:
        $base64 = /FromBase64String/ nocase
        $decode = /System\\.Text\\.Encoding::UTF8\\.GetString/ nocase
    condition:
        $base64 and $decode
}

rule Obfuscated_Variable_Names
{
    meta:
        description = "Detects obfuscated variable naming patterns"
        severity = "low"
    strings:
        $obf_var = /\\$[A-Za-z0-9]{12,}/
    condition:
        $obf_var
}
"""
