/*
 * curlguard foundation YARA rules
 * Detects common malware patterns in shell scripts
 */

rule base64_encoded_shell {
  meta:
    description = "Detects base64-encoded shell command payloads"
    category = "behavior"
    confidence = "medium"
    severity = "high"
  strings:
    $pipe_exec = /(base64\s+(-d|--decode)|openssl\s+base64\s+-d)[ \t]*\|[ \t]*(ba)?sh\b/i
    $sub_exec = /(eval|bash[ \t]+-c|sh[ \t]+-c)[ \t]+["']?\$\([^\n]{0,256}base64[ \t]+(-d|--decode)/i
  condition:
    any of them
}

rule suspicious_pipe_bash {
  meta:
    description = "Detects curl/wget piped to bash - common install attack"
    category = "behavior"
    confidence = "medium"
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
    category = "behavior"
    confidence = "medium"
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
    category = "behavior"
    confidence = "medium"
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
    category = "indicator"
    confidence = "low"
    severity = "medium"
  strings:
    $ip_literal = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    $suspicious_tld = /\.(ru|cn|tk|ml|ga|cf|gq)\// nocase
    $tor_redirect = /onion\// nocase
  condition:
    $ip_literal and ($suspicious_tld or $tor_redirect)
}
