from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple


class AttackKeywordClassifier:
    """
    启发式 ATT&CK 关键词匹配器（多标签），并提供“编号:中文”格式化。
    """

    TACTIC_NAMES = {
        "TA0001": "Initial Access / 初始访问",
        "TA0002": "Execution / 执行",
        "TA0003": "Persistence / 持久化",
        "TA0004": "Privilege Escalation / 提权",
        "TA0005": "Defense Evasion / 防御规避",
        "TA0006": "Credential Access / 凭据访问",
        "TA0007": "Discovery / 发现",
        "TA0008": "Lateral Movement / 横向移动",
        "TA0009": "Collection / 收集",
        "TA0010": "Exfiltration / 数据外传",
        "TA0011": "Command and Control / 命令与控制",
        "TA0040": "Impact / 影响",
        "TA0043": "Reconnaissance / 侦察",
    }

    TECHNIQUE_NAMES = {
        "T1046": "Network Service Discovery / 网络服务发现",
        "T1110": "Brute Force / 暴力破解",
        "T1003": "OS Credential Dumping / 凭据转储",
        "T1555": "Credentials from Password Stores / 密码库凭据",
        "T1190": "Exploit Public-Facing Application / 公网服务漏洞利用",
        "T1566": "Phishing / 钓鱼",
        "T1059": "Command and Scripting Interpreter / 命令与脚本解释器",
        "T1059.001": "PowerShell / PowerShell",
        "T1059.004": "Unix Shell / Unix Shell",
        "T1505.003": "Web Shell / WebShell",
        "T1053": "Scheduled Task/Job / 计划任务",
        "T1136": "Create Account / 创建账户",
        "T1543": "Create or Modify System Process / 服务/进程持久化",
        "T1068": "Exploitation for Privilege Escalation / 漏洞提权",
        "T1548": "Abuse Elevation Control Mechanism / UAC 等提升机制",
        "T1562": "Impair Defenses / 削弱防护",
        "T1027": "Obfuscated/Compressed Files & Info / 混淆与压缩",
        "T1021": "Remote Services / 远程服务",
        "T1021.001": "Remote Services: RDP / RDP 远程服务",
        "T1021.002": "Remote Services: SMB/Windows Admin Shares / SMB/管理共享 远程服务",
        "T1021.004": "Remote Services: SSH / SSH 远程服务",
        "T1560": "Archive Collected Data / 打包收集数据",
        "T1041": "Exfiltration Over C2 Channel / 经 C2 渠道外传",
        "T1071": "Application Layer Protocol / 应用层协议",
        "T1071.001": "Web Protocols (HTTP/HTTPS) / Web 协议（HTTP/HTTPS）",
        "T1071.004": "DNS / DNS",
        "T1572": "Protocol Tunneling / 协议隧道",
        "T1105": "Ingress Tool Transfer / 工具/文件传入",
        "T1210": "Exploitation of Remote Services / 远程服务漏洞利用",
        "T1496": "Resource Hijacking / 资源劫持（挖矿）",
        "T1595": "Active Scanning / 主动扫描",
        "T1595.003": "Wordlist Scanning / 字典扫描（目录/路径）",
        "T1083": "File and Directory Discovery / 文件与目录发现",
        "T1203": "Exploitation for Client Execution / 客户端执行漏洞利用",
    }
    TECHNIQUE_ZH_FALLBACK = {
        "T1059.001": "PowerShell",
        "T1059.004": "Unix Shell",
        "T1021.001": "RDP 远程服务",
        "T1021.002": "SMB/管理共享 远程服务",
        "T1021.004": "SSH 远程服务",
        "T1071": "应用层协议",
    }

    def __init__(self):
        self._rules = self._compile_rules()

    # ------------------- 对外 API -------------------

    def classify_multilabel(self, alert_name: Any, max_tags: Optional[int] = None) -> Tuple[List[str], List[str]]:
        hits = self._classify_all(alert_name)
        tacs, techs, seen_t, seen_k = [], [], set(), set()
        for _, tac, tech in hits:
            if (max_tags is None or len(tacs) < max_tags) and tac not in seen_t:
                tacs.append(tac)
                seen_t.add(tac)
            if (max_tags is None or len(techs) < max_tags) and tech not in seen_k:
                techs.append(tech)
                seen_k.add(tech)
        return tacs, techs

    def format_tactic_list(self, tactic_ids: List[str]) -> str:
        return "; ".join([f"{t}:{self._tactic_zh(t)}" for t in tactic_ids if t])

    def format_technique_list(self, tech_ids: List[str]) -> str:
        return "; ".join([f"{k}:{self._tech_zh(k)}" for k in tech_ids if k])

    # ------------------- 内部实现 -------------------

    def _classify_all(self, alert_name: Any) -> List[tuple[int, str, str]]:
        s = "" if alert_name is None else str(alert_name)
        hits = []
        for r in self._rules:
            if r["regex"].search(s):
                hits.append((r["priority"], r["tactic"], r["technique"]))
        hits.sort(key=lambda x: x[0])
        # 去重 (tactic, technique) 保留优先级较高的
        seen = set()
        out: List[tuple[int, str, str]] = []
        for pr, tac, tech in hits:
            key = (tac, tech)
            if key not in seen:
                out.append((pr, tac, tech))
                seen.add(key)
        return out

    def _zh_only(self, mixed: str, fallback: str = "") -> str:
        if not mixed:
            return fallback
        if " / " in mixed:
            try:
                return mixed.split(" / ", 1)[1]
            except Exception:
                pass
        return fallback or mixed

    def _tactic_zh(self, tid: str) -> str:
        nm = self.TACTIC_NAMES.get(tid, "")
        zh = self._zh_only(nm, fallback="")
        return zh if zh else tid

    def _tech_zh(self, kid: str) -> str:
        nm = self.TECHNIQUE_NAMES.get(kid, "")
        zh = self._zh_only(
            nm, fallback=self.TECHNIQUE_ZH_FALLBACK.get(kid, ""))
        return zh if zh else kid

    def _compile_rules(self) -> List[Dict[str, Any]]:
        RULES: List[Dict[str, Any]] = [
            {"pattern": r"(通用)?敏感文件名特征|敏感文件名|敏感\s*filename",
             "technique": "T1595.003", "tactic": "TA0043", "priority": 5},
            {"pattern": r"(通用)?目录穿越特征|目录穿越|path\s*traversal|directory\s*traversal|\.\./\.\.",
             "technique": "T1190", "tactic": "TA0001", "priority": 6},
            {"pattern": r"(通用)?特殊活动特征\s*-\s*SSH扫描器|SSH\s*扫描器|SSH\s*scanner",
             "technique": "T1046", "tactic": "TA0007", "priority": 9},
            {"pattern": r"(/etc/hosts|hosts\s*文件)",
             "technique": "T1083", "tactic": "TA0007", "priority": 10},
            {"pattern": r"(用户代理|User-?Agent)",
             "technique": "T1071.001", "tactic": "TA0011", "priority": 12},
            {"pattern": r"\bbash(\s+shell)?\b|bash\s+-i|/bin/bash|/bin/sh",
             "technique": "T1059.004", "tactic": "TA0002", "priority": 8},
            {"pattern": r"(字符串)?缓冲区溢出|buffer\s*overflow",
             "technique": "T1203", "tactic": "TA0002", "priority": 7},

            {"pattern": r"(xmr(ig)?|挖矿工具|矿池|私有矿池|cryptominer|crypto\s*mining|coinhive)",
             "technique": "T1496", "tactic": "TA0040", "priority": 2},
            {"pattern": r"(wannamine)",
             "technique": "T1496", "tactic": "TA0040", "priority": 2},

            {"pattern": r"(ms17[-_ ]?010|永恒之蓝|eternalblue)",
             "technique": "T1210", "tactic": "TA0008", "priority": 3},
            {"pattern": r"(ms08[-_ ]?067)",
             "technique": "T1210", "tactic": "TA0008", "priority": 3},

            {"pattern": r"(风险对象访问|威胁情报风险对象访问).*(ramnit|sality|spchrome|驱动人生|wannamine|xmrig)",
             "technique": "T1071.001", "tactic": "TA0011", "priority": 4},
            {"pattern": r"(风险对象访问|威胁情报风险对象访问)",
             "technique": "T1071.001", "tactic": "TA0011", "priority": 14},

            {"pattern": r"(敏感目录|目录爆破|dirb|dirbuster|dirsearch|路径爆破|字典扫描)",
             "technique": "T1595.003", "tactic": "TA0043", "priority": 5},
            {"pattern": r"(敏感关键字|敏感关键词|keyword\s*scan|关键字扫描)",
             "technique": "T1595", "tactic": "TA0043", "priority": 5},

            {"pattern": r"(端口|扫描|scan|nmap|masscan|探测|扫端口|主机发现|主机扫描|漏洞扫描|poc扫描)",
             "technique": "T1046", "tactic": "TA0007", "priority": 10},
            {"pattern": r"(paramiko.*(scan|扫描)|ssh\s*扫描|ssh\s*scanner|go.*ssh)",
             "technique": "T1046", "tactic": "TA0007", "priority": 9},

            {"pattern": r"(暴力破解|弱口令|字典攻击|brute\s*force|hydra|medusa)",
             "technique": "T1110", "tactic": "TA0006", "priority": 10},
            {"pattern": r"(mimikatz|lsass|凭据转储|哈希转储|lsass\.exe)",
             "technique": "T1003", "tactic": "TA0006", "priority": 10},
            {"pattern": r"(浏览器密码|密码管理器|凭据窃取|password\s*store|credential\s*steal)",
             "technique": "T1555", "tactic": "TA0006", "priority": 10},

            {"pattern": r"(sql注入|sqli|SQL\s*注入|xss|跨站脚本|跨站|文件上传漏洞|任意文件上传|struts2|s2[- _]?\d+|log4j|log4shell|shiro|weblogic|spring\s*boot|spring4shell|cve-\d{4}-\d+)",
             "technique": "T1190", "tactic": "TA0001", "priority": 8},
            {"pattern": r"(钓鱼|鱼叉|邮件链接|诱导下载|spearphishing|phishing)",
             "technique": "T1566", "tactic": "TA0001", "priority": 8},

            {"pattern": r"(命令执行|远程命令执行|RCE|代码执行|execute\s*command)",
             "technique": "T1059", "tactic": "TA0002", "priority": 9},
            {"pattern": r"(powershell(\.exe)?(?!\S)|\bpowershell\b)",
             "technique": "T1059.001", "tactic": "TA0002", "priority": 8},
            {"pattern": r"(/bin/sh|/bin/bash|bash\s+-i|shell脚本|^bash$)",
             "technique": "T1059.004", "tactic": "TA0002", "priority": 8},
            {"pattern": r"(反弹\s*shell|reverse\s*shell|/dev/tcp/|nc\s+-e|powershell\.exe\s+-nop)",
             "technique": "T1059", "tactic": "TA0002", "priority": 8},

            {"pattern": r"(webshell|一句话木马|菜刀|冰蝎|蚁剑|中国菜刀)",
             "technique": "T1505.003", "tactic": "TA0003", "priority": 7},
            {"pattern": r"(计划任务|schtasks|cron\b|at\s+)",
             "technique": "T1053", "tactic": "TA0003", "priority": 9},
            {"pattern": r"(新增用户|添加用户|创建账户|新建账户|user(add|create))",
             "technique": "T1136", "tactic": "TA0003", "priority": 9},
            {"pattern": r"(服务创建|sc\s+create|服务安装|注册服务|systemctl\s+enable)",
             "technique": "T1543", "tactic": "TA0003", "priority": 9},

            {"pattern": r"(提权|提权漏洞|提权成功|提权尝试|提权利用)",
             "technique": "T1068", "tactic": "TA0004", "priority": 9},
            {"pattern": r"(uac绕过|uac\s*bypass|提权绕过)",
             "technique": "T1548", "tactic": "TA0004", "priority": 8},
            {"pattern": r"(禁用安全产品|关闭防火墙|关闭杀软|结束进程|防护绕过|disable\s*(edr|av|defender)|taskkill)",
             "technique": "T1562", "tactic": "TA0005", "priority": 9},
            {"pattern": r"(混淆|加壳|无文件|内存加载|反沙箱|反调试|obfuscat|pack|fileless|amsi\s*bypass)",
             "technique": "T1027", "tactic": "TA0005", "priority": 9},

            {"pattern": r"(ssh(?!.*扫描)|22\s*端口横向|ssh\s*login|scp\s|sftp\s)",
             "technique": "T1021.004", "tactic": "TA0008", "priority": 12},
            {"pattern": r"(rdp|远程桌面|3389)",
             "technique": "T1021.001", "tactic": "TA0008", "priority": 12},
            {"pattern": r"(smb|ipc\$|445端口横向|wmic\b|psexec)",
             "technique": "T1021.002", "tactic": "TA0008", "priority": 12},
            {"pattern": r"(lateral\s*movement|横向)",
             "technique": "T1021", "tactic": "TA0008", "priority": 13},

            {"pattern": r"(打包数据|压缩数据|rar\b|zip\b|7z\b|archive\b)",
             "technique": "T1560", "tactic": "TA0009", "priority": 11},
            {"pattern": r"(数据外传|数据外泄|泄露敏感|外带|exfil)",
             "technique": "T1041", "tactic": "TA0010", "priority": 11},

            {"pattern": r"(命令与控制|c2\b|beacon|回连|心跳|cobalt\s*strike|meterpreter|cs连接|c2连接)",
             "technique": "T1071", "tactic": "TA0011", "priority": 7},
            {"pattern": r"(隧道|tunnel|frp|lcx|regeorg|chisel|socat\s*隧道|端口转发|port\s*forward)",
             "technique": "T1572", "tactic": "TA0011", "priority": 7},
            {"pattern": r"(dns\s*隧道|dnscat|iodine)",
             "technique": "T1071.004", "tactic": "TA0011", "priority": 6},
            {"pattern": r"(http\s*隧道|https\s*隧道|web\s*通道)",
             "technique": "T1071.001", "tactic": "TA0011", "priority": 6},
            {"pattern": r"(下载文件|wget\b|curl\b|certutil\.exe\s+-urlcache|invoke-webrequest|bitsadmin)",
             "technique": "T1105", "tactic": "TA0011", "priority": 8},
        ]
        for r in RULES:
            r["regex"] = re.compile(r["pattern"], re.I)
        return RULES
