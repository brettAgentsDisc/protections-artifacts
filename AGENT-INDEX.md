# Protections Artifacts Index
Generated for agent-assisted navigation.

## Overview
- Purpose: Elastic Security's open-source detection logic repository containing endpoint behavior protection rules (EQL-based TOML), YARA malware signatures, and ransomware detection artifacts used by Elastic Defend (Elastic Security for Endpoint).
- Total rule files: 1,886
- Rule formats: TOML (behavior rules with EQL queries), .yar (YARA signature rules), .lua (ransomware detection logic)
- Rule categories: Behavior rules by platform (Windows, Linux, macOS, cross-platform) mapped to MITRE ATT&CK tactics; YARA rules by OS and threat type (Trojan, Ransomware, Hacktool, VulnDriver, Exploit, Cryptominer, Rootkit, etc.)
- License: Elastic License v2

## Directory: behavior/
Description: EQL-based malicious behavior protection rules that run on the Elastic Agent endpoint. Each rule is a TOML file containing a rule definition (description, id, name, version, EQL query, MITRE ATT&CK mapping, response actions). Rules are organized by target OS platform and named by MITRE ATT&CK tactic prefix.
File count: 1,202 TOML rules total

### behavior/rules/windows/
Description: Windows-specific endpoint behavior rules. Largest rule set covering all MITRE ATT&CK tactics.
File count: 756
Tactic breakdown: Defense Evasion (~322), Execution (~96), Privilege Escalation (~73), Initial Access (~62), Persistence (~61), Credential Access (~52), Command and Control (~40), Discovery (~20), Impact (~19), Collection (~12), Lateral Movement (~10)
Example files:
- behavior/rules/windows/collection_getasynckeystate_api_call_from_suspicious_process.toml -- Detects keylogger activity via GetAsyncKeyState API
- behavior/rules/windows/credential_access_lsass_access_attempt_from_an_unsigned_executable.toml -- Detects LSASS credential dumping attempts
- behavior/rules/windows/defense_evasion_allowprotectedrenames_registry_modification.toml -- Detects defense evasion via registry changes
- behavior/rules/windows/execution_.net_com_object_created_in_non_standard_windows_script_interpreter.toml -- Detects suspicious .NET COM execution
- behavior/rules/windows/initial_access_execution_from_a_macro_enabled_office_document.toml -- Detects macro-based initial access
- behavior/rules/windows/lateral_movement_execution_of_a_file_dropped_from_smb.toml -- Detects lateral movement via SMB file drops
- behavior/rules/windows/persistence_browser_native_messaging_registry_modification.toml -- Detects browser-based persistence mechanisms
- behavior/rules/windows/privilege_escalation_access_token_manipulation_via_child_process.toml -- Detects token manipulation for privilege escalation

### behavior/rules/linux/
Description: Linux-specific endpoint behavior rules covering server and container environments.
File count: 158
Key tactics: Execution (~58), Defense Evasion (~47), Persistence (~26), Privilege Escalation (~14), Command and Control (~11), Credential Access (~7)
Example files:
- behavior/rules/linux/execution_linux_reverse_shell.toml -- Detects reverse shell execution on Linux
- behavior/rules/linux/defense_evasion_binary_executed_from_shared_memory_directory.toml -- Detects fileless execution from /dev/shm
- behavior/rules/linux/persistence_at_utility_launched_through_udevadm.toml -- Detects persistence via udev rules
- behavior/rules/linux/credential_access_potential_linux_credential_dumping_via_proc_filesystem.toml -- Detects credential theft via /proc

### behavior/rules/macos/
Description: macOS-specific endpoint behavior rules with strong focus on credential theft, osascript abuse, and curl-based attacks.
File count: 268
Key tactics: Execution (~105), Defense Evasion (~61), Command and Control (~42), Credential Access (~35), Persistence (~21)
Example files:
- behavior/rules/macos/execution_abnormal_auval_child_process_execution.toml -- Detects abuse of macOS audio validation
- behavior/rules/macos/credential_access_keychain_dump_via_native_security_tool.toml -- Detects Keychain credential theft
- behavior/rules/macos/command_and_control_shlayer_malware_infection.toml -- Detects Shlayer adware/malware
- behavior/rules/macos/persistence_default_application_hijacking.toml -- Detects app hijacking persistence

### behavior/rules/cross-platform/
Description: Rules that apply to multiple operating systems (Linux + macOS typically).
File count: 20
Example files:
- behavior/rules/cross-platform/execution_potential_reverse_shell_activity_via_terminal.toml -- Cross-platform reverse shell detection
- behavior/rules/cross-platform/impact_darkradiation_ransomware_infection.toml -- DarkRadiation ransomware detection
- behavior/rules/cross-platform/privilege_escalation_sudo_heap_based_buffer_overflow_attempt.toml -- CVE-based sudo exploit detection

## Directory: yara/
Description: YARA signature rules for file and memory scanning used by Elastic Endpoint malware protection. Rules detect malware families across Linux, Windows, and macOS. Each .yar file contains one or more YARA rules with standardized metadata (id, fingerprint, creation_date, threat_name, severity, scan_context).
File count: 684 .yar rule files

### yara/rules/ (by OS)
- Windows: 389 rules
- Linux: 225 rules
- macOS: 48 rules (MacOS + Macos naming)
- Multi-platform: 22 rules

### yara/rules/ (by threat type)
- Trojan: 320 rules (largest category -- RATs, stealers, loaders)
- Ransomware: 78 rules (Akira, Babuk, BlackBasta, Clop, Conti, Hive, LockBit, etc.)
- Hacktool: 69 rules (Mimikatz, Cobalt Strike, Metasploit, etc.)
- VulnDriver: 60 rules (vulnerable driver detection for BYOVD attacks)
- Exploit: 48 rules (CVE-based exploits including Log4j, DirtyCow, etc.)
- Cryptominer: 27 rules (XMRig, coin miners)
- Rootkit: 20 rules (kernel-level rootkits)
- Infostealer: 13 rules
- Backdoor: 13 rules
- Virus: 10 rules
- Wiper: 4 rules
- Other: PUP, Packer, Shellcode, Worm, Webshell, Proxy, etc.

Example files:
- yara/rules/Windows_Trojan_CobaltStrike.yar -- Cobalt Strike framework detection
- yara/rules/Windows_Ransomware_Akira.yar -- Akira ransomware signatures
- yara/rules/Windows_Hacktool_Mimikatz.yar -- Mimikatz credential tool detection
- yara/rules/Windows_VulnDriver_ATSZIO.yar -- Vulnerable driver (BYOVD) detection
- yara/rules/Linux_Exploit_Log4j.yar -- Log4Shell exploit detection
- yara/rules/Linux_Cryptominer_Xmrig.yar -- XMRig cryptominer detection
- yara/rules/MacOS_Backdoor_Applejeus.yar -- North Korean AppleJeus backdoor
- yara/rules/Multi_Cryptominer_Xmrig.yar -- Cross-platform XMRig detection

## Directory: ransomware/
Description: Elastic Defend's ransomware-specific detection artifact and testing tools. The core artifact is a Lua script implementing a scoring-based behavioral detection system that monitors file modification events for anomalous patterns (entropy mismatch, header manipulation, ransom notes, canary files).
File count: 4 (1 Lua artifact, 2 test scripts, 1 README)

Example files:
- ransomware/artifact.lua -- Core ransomware detection logic (scoring engine)
- ransomware/testing/mock_ransomware.py -- Python script to generate test files and launch mock ransomware
- ransomware/testing/mock_ransomware.ps1 -- PowerShell script simulating file encryption for testing

## Directory: .github/
Description: GitHub issue templates for reporting bugs, requesting new rules, and contributing YARA rules.
File count: 7 (6 issue templates + 1 workflow)

Example files:
- .github/ISSUE_TEMPLATE/behavior_bug_issue.md -- Template for reporting behavior rule bugs
- .github/ISSUE_TEMPLATE/behavior_new_endpoint_rule.md -- Template for requesting new behavior rules
- .github/ISSUE_TEMPLATE/behavior_custom_issue.md -- Template for custom behavior issues
- .github/ISSUE_TEMPLATE/yara_add_new_rule.md -- Template for adding YARA rules
- .github/ISSUE_TEMPLATE/yara_request_coverage.md -- Template for requesting YARA malware coverage
- .github/ISSUE_TEMPLATE/yara_rule_tuning.md -- Template for tuning existing YARA rules
- .github/workflows/duplicate_issue.yml -- Workflow for managing duplicate issues

## Rule Format Reference

### Behavior Rules (TOML)
Each behavior rule file contains:
- `[rule]` section: description, id (UUID), license, name, os_list, version, reference links
- `query`: EQL (Event Query Language) query string for detection
- `min_endpoint_version`: minimum Elastic Agent version required
- `[[actions]]`: response actions (kill_process, rollback)
- `[[threat]]`: MITRE ATT&CK mapping (tactic, technique, subtechnique)
- `[internal]`: internal metadata

### YARA Rules (.yar)
Each YARA rule file contains one or more standard YARA rules with:
- `meta`: id (UUID), fingerprint (SHA256), creation_date, last_modified, threat_name (OS.Type.Family), reference_sample, severity, arch_context, scan_context (file/memory), os, license
- `strings`: hex patterns, text strings, or regex for matching
- `condition`: boolean logic combining string matches

## Documentation

### Root Documentation
- README.md -- Repository overview, directory index, contribution links
- SDP.md -- Safe Deployment Practices: staged rollouts, testing, rollback, customer controls
- LICENSE.txt -- Elastic License v2 full text

### Component Documentation
- behavior/README.md -- Behavior rules overview, MITRE ATT&CK tactic focus, version info, rule counts by OS/tactic
- yara/README.md -- YARA rules overview, use cases, contribution info
- yara/CONTRIBUTING.md -- Contribution guide: issue types, YARA principles, quality testing, metadata schema reference
- ransomware/README.md -- Ransomware detection architecture: scoring system, detection features (entropy, headers, canary files)
- ransomware/testing/README.md -- How to test ransomware protection with mock scripts

## Flat Documentation File List
- .github/ISSUE_TEMPLATE/behavior_bug_issue.md
- .github/ISSUE_TEMPLATE/behavior_custom_issue.md
- .github/ISSUE_TEMPLATE/behavior_new_endpoint_rule.md
- .github/ISSUE_TEMPLATE/yara_add_new_rule.md
- .github/ISSUE_TEMPLATE/yara_request_coverage.md
- .github/ISSUE_TEMPLATE/yara_rule_tuning.md
- LICENSE.txt
- README.md
- SDP.md
- behavior/README.md
- ransomware/README.md
- ransomware/testing/README.md
- yara/CONTRIBUTING.md
- yara/README.md
