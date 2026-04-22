/*
 * curlguard foundation YARA rules
 * Detects common malware patterns in shell scripts
 */

rule base64_encoded_shell {
  meta:
    description = "Detects base64-encoded shell command payloads"
    severity = "high"
  strings:
    $b64_magic = /[A-Za-z0-9+\/]{50,}={0,2}/
    $pipe_bash = /\|\s*bash/
    $decode_cmd = /(base64\s+-d|openssl\s+base64|-d\s+<<<)/i
  condition:
    $b64_magic and $decode_cmd
}

rule suspicious_pipe_bash {
  meta:
    description = "Detects curl/wget piped to bash - common install attack"
    severity = "critical"
  strings:
    $curl_pipe = /curl\s+[^\|]+\|\s*bash/
    $wget_pipe = /wget\s+[^\|]+\|\s*bash/
    $fetch_pipe = /fetch\s+[^\|]+\|\s*bash/
  condition:
    any of them
}

rule obfuscated_download {
  meta:
    description = "Detects obfuscated download with eval/exec"
    severity = "high"
  strings:
    $eval_sh = /eval\s+\$/i
    $exec_redirect = /exec\s+.*\>/i
    $sh_c_bypass = /sh\s+-c\s+['\"].*\$/
  condition:
    2 of them
}

rule known_malware_header {
  meta:
    description = "Detects common malware file signatures"
    severity = "critical"
  strings:
    $shebang_bash = /#!\/bin\/(ba)?sh/
    $suspicious_comment = /\b(MALWARE|TROJAN|BACKDOOR)\b/i
    $crypto_pool = /stratum\+tcp:\/\/[^\s]+:\d+/ nocase
  condition:
    $shebang_bash and ($suspicious_comment or $crypto_pool)
}

rule network_ioc {
  meta:
    description = "Detects suspicious network indicators"
    severity = "medium"
  strings:
    $ip_literal = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/
    $suspicious_tld = /\.(ru|cn|tk|ml|ga|cf|gq)\// nocase
    $tor_redirect = /onion\// nocase
  condition:
    $ip_literal and ($suspicious_tld or $tor_redirect)
}