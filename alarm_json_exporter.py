from __future__ import annotations
import json
import os
from typing import Any, Dict, List, Optional

from json_source_reader import JsonSourceReader
from payload_printable import PayloadPrintableParser


class AlarmJsonExporter:
    """
    从 ES 风格 JSON（1.json）抽取 _source，映射成精简的新 JSON。
    字段来源：
      - applicationProtocol：沿用 proofType 的推导逻辑（derive_l7 的第二返回值）
      - payload：沿用现有 decode_payload_for_sheet 解码/清洗逻辑
    """

    FIELDS = [
        "alarmId", "alarmEngine", "alarmName", "alarmType", "alarmDesc",
        "alarmLevel", "ruleId", "ruleName", "ruleDesc", "alarmTime",
        "transportProtocol", "applicationProtocol",
        "srcIp", "srcPort", "dstIp", "dstPort",
        "payload", "dataRaw",
    ]

    def __init__(self) -> None:
        self.reader = JsonSourceReader()
        self.pp = PayloadPrintableParser()

    def _map_one(self, src: Dict[str, Any]) -> Dict[str, Any]:
        # —— applicationProtocol（= proofType 的映射逻辑）——
        orders = self.pp.extract_orders(src.get("payloadPrintable", "") or "")
        _l7, proof_type = self.pp.derive_l7(orders)

        # —— payload（沿用解码清洗逻辑）——
        payload_text = self.pp.decode_payload_for_sheet(
            (src.get("payload") or "").strip()
        )

        # —— 直取/重命名映射 ——
        out: Dict[str, Any] = {
            "alarmId": src.get("id", ""),
            "alarmEngine": "suricata",
            "alarmName": src.get("ceventName", ""),
            "alarmType": src.get("ceventType", ""),
            "alarmDesc": src.get("cEventMsg", ""),
            "alarmLevel": src.get("ceventLevel", ""),
            "ruleId": src.get("sid", ""),
            "ruleName": src.get("ceventName", ""),
            "ruleDesc": src.get("cEventMsg", ""),
            "alarmTime": src.get("processTime", ""),
            "transportProtocol": src.get("cprotocol", ""),
            "applicationProtocol": proof_type,
            "srcIp": src.get("cSrcIp", ""),
            "srcPort": src.get("iSrcPort", ""),
            "dstIp": src.get("cDstIp", ""),
            "dstPort": src.get("iDstPort", ""),
            "payload": payload_text,
            "dataRaw": src.get("signaturemsg", "") or src.get("signatureMsg", ""),
        }
        # 只保留目标字段顺序
        return {k: out.get(k, "") for k in self.FIELDS}

    def export(self, json_path: str, out_path: Optional[str] = None) -> str:
        """
        读取 json_path（支持 ES 风格），写出数组 JSON 到 out_path。
        返回 out_path。
        """
        data = self.reader.load_json(json_path)
        sources = self.reader.extract_sources(data)
        records: List[Dict[str, Any]] = [self._map_one(s) for s in sources]

        if out_path is None:
            base, _ = os.path.splitext(json_path)
            out_path = f"{base}.alarm.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
        return out_path
