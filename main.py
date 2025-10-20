from __future__ import annotations
import sys
import json
from typing import Any, Dict, List, Tuple, Optional

import pandas as pd

from json_source_reader import JsonSourceReader
from payload_printable import PayloadPrintableParser
from attack_keyword_classifier import AttackKeywordClassifier
from malware_parser import MalwareNameParser
from template_writer import TemplateWriter

# ==================== 统一列头 ====================
HEADERS = [
    "recordTimestamp", "uploadTimestamp", "insertTimestamp",
    "productType", "manage", "originProductType",
    "deviceId", "deviceIp", "uuId",
    "srcIp", "srcPort", "srcCountry", "srcProvince", "srcCity",
    "dstIp", "dstPort", "dstCountry", "dstProvince",
    "threatClass", "reqRuleId", "ruleName", "ruleDescription",
    "l4Protocol", "attackState", "action", "tactic", "technique",
    "riskLevel", "virusFamily", "virusName",
    "payload", "reqMethod", "url", "httpUri", "referer", "userAgent",
    "reqContentType", "dnsQueries", "dnsQTypes",
    "smbCommand", "smbFlags", "smbFlags2", "smbWordCount",
    "smbProcessId", "smbUserId", "smbMessageId",
    "sshProtocolVersion", "sshClientVersion", "ftpCommandMsg",
    "l7Protocol", "proofType",
    "severity", "confidence", "packetData", "requestBody",
    "engine", "l3Protocol", "rawMsg",
    "eventType", "eventSubType", "eventLevel",
]


class Pipeline:
    """
    负责“读取 JSON → 抽取 _source → 构建行 → 写回模板”的编排。
    """

    def __init__(self):
        self.reader = JsonSourceReader()
        self.pp = PayloadPrintableParser()
        self.attck = AttackKeywordClassifier()
        self.malware = MalwareNameParser()
        self.writer = TemplateWriter()

    # —— 内部：用与 Base64 解码与清洗逻辑（仅用于 payload 列）——
    def _decode_payload_for_sheet(self, b64s: str) -> str:
        return self.pp.decode_payload_for_sheet(b64s)

    def build_row(self, src: Dict[str, Any]) -> List[Any]:
        # 基础字段
        lOccurTime = src.get("lOccurTime", "")
        reportingTime = src.get("reportingTime", "")
        processTime = src.get("processTime", "")
        deviceTypeOneName = src.get("deviceTypeOneName", "")
        deviceTypeTwoName = src.get("deviceTypeTwoName", "")
        deviceName = src.get("deviceName", "")
        deviceCode = src.get("deviceCode", "")
        cDevIp = src.get("cDevIp", "")
        _id = src.get("id", "")
        cSrcIp = src.get("cSrcIp", "")
        iSrcPort = src.get("iSrcPort", "")
        srcCountry = src.get("srcCountry", "")
        sourceProvince = src.get(
            "sourceProvince", src.get("srcIpProvince", ""))
        sourceCity = src.get("sourceCity", "")
        cDstIp = src.get("cDstIp", "")
        iDstPort = src.get("iDstPort", "")
        dstCountry = src.get("dstCountry", "")
        dstIpProvince = src.get("dstIpProvince", src.get("dstProvince", ""))
        ceventType = src.get("ceventType", "")
        sid = src.get("sid", "")
        ceventName = src.get("ceventName", "")   # 供 ruleName & ATT&CK & 病毒家族解析
        cEventMsg = src.get("cEventMsg", "")
        cprotocol = src.get("cprotocol", "")
        eventState = src.get("eventState", "")
        ceventLevel = src.get("ceventLevel", "")

        # —— 提取 ceventSType，用于写 eventSubType
        ceventSType = src.get("ceventSType", "")

        # —— 恶意家族解析：按你的要求基于 ceventName ——
        virus_family, virus_name = self.malware.parse_family_and_name(
            ceventName)

        # —— payloadPrintable 抽取与 L7 推导 ——
        pp_text = src.get("payloadPrintable", "") or ""
        pp_map = self.pp.extract_fields(pp_text)
        orders = self.pp.extract_orders(pp_text)
        l7Protocol, proofType = self.pp.derive_l7(orders)

        # —— SSH 版本/Client Version、HTTP 等字段 ——
        ssh_banner = pp_map.get("ssh.protocol", "")
        if isinstance(ssh_banner, list):
            ssh_banner = ssh_banner[0] if ssh_banner else ""
        ssh_client_version = str(ssh_banner)
        ssh_protocol_version = self.pp.only_ssh_version(ssh_banner)

        http_method = pp_map.get("http.request.method", "")
        http_full_uri = pp_map.get("http.request.full_uri", "")
        http_referer = pp_map.get("http.referer", "")
        user_agent = pp_map.get("User-Agent", "")
        http_content_type = pp_map.get("http.content_type", "")
        dns_qry_name = pp_map.get("dns.qry.name", "")
        dns_qry_type = pp_map.get("dns.qry.type", "")
        smb_cmd = pp_map.get("smb.cmd", "")
        smb_flags = pp_map.get("smb.flags", "")
        smb_flags2 = pp_map.get("smb.flags2", "")
        smb_wct = pp_map.get("smb.wct", "")
        smb_pid = pp_map.get("smb.pid", "")
        smb_uid = pp_map.get("smb.uid", "")
        smb_mid = pp_map.get("smb.mid", "")
        data_text_lines = pp_map.get("data-text-lines", "")

        # —— packetData：原样写入 cRequestMsg；payload：Base64 解码→清洗 ——
        packet_data_raw = src.get("cRequestMsg", "") or ""
        payload_for_sheet = self._decode_payload_for_sheet(
            (src.get("payload") or "").strip())

        # —— ATT&CK 分类（启发式） ——
        tacs, techs = self.attck.classify_multilabel(ceventName)
        tactic_str = self.attck.format_tactic_list(
            tacs)       # "TA0001:初始访问; ..."
        technique_str = self.attck.format_technique_list(
            techs)   # "T1046:网络服务发现; ..."

        # —— 其他列 ——
        action_val = ""
        severity = ceventLevel
        confidence = "高可信" if str(
            src.get("cIsAlert", "")).strip() == "1" else ""
        engine = "suricata"
        l3Protocol = "IP"
        raw_msg = src.get("signaturemsg", "") or src.get("signatureMsg", "")

        # —— 三列的取值 ——
        eventType_val = ceventType                         # 来自 _source.ceventType
        eventSubType_val = ceventSType                     # 来自 _source.ceventSType
        eventLevel_val = "低危"                            # 固定值

        return [
            lOccurTime, reportingTime, processTime,
            deviceTypeOneName, deviceTypeTwoName, deviceName,
            deviceCode, cDevIp, _id,
            cSrcIp, iSrcPort, srcCountry, sourceProvince, sourceCity,
            cDstIp, iDstPort, dstCountry, dstIpProvince,
            ceventType, sid, ceventName, cEventMsg,
            cprotocol,                # l4Protocol
            eventState,               # attackState
            action_val,               # action
            tactic_str,               # tactic
            technique_str,            # technique
            ceventLevel,              # riskLevel（维持与旧逻辑一致）
            virus_family, virus_name,
            payload_for_sheet,
            http_method, http_full_uri, http_full_uri,
            http_referer, user_agent, http_content_type,
            dns_qry_name, dns_qry_type,
            smb_cmd, smb_flags, smb_flags2, smb_wct,
            smb_pid, smb_uid, smb_mid,
            ssh_protocol_version, ssh_client_version, data_text_lines,
            l7Protocol, proofType,
            severity, confidence,
            packet_data_raw,
            "",  # requestBody 占位
            engine, l3Protocol, raw_msg,
            eventType_val, eventSubType_val, eventLevel_val,
        ]

    def process_to_template(self, json_path: str, template_path: str, sheet_name: Optional[str] = None) -> Tuple[int, int, Optional[str]]:
        data = self.reader.load_json(json_path)
        sources = self.reader.extract_sources(data)  # List[Dict]
        rows = [self.build_row(src) for src in sources]
        df = pd.DataFrame(rows, columns=HEADERS)
        return self.writer.fill_template_with_df(
            df=df, template_path=template_path, save_path=None,
            do_backup_if_overwrite=True, sheet_name=sheet_name
        )


# ============== GUI 入口：拆分到独立 class，但这里提供启动器 ==============
if __name__ == "__main__":
    from gui_app import MappingGuiApp
    MappingGuiApp(Pipeline).run()
