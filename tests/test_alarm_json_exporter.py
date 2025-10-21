import json
from pathlib import Path

import pytest

from alarm_json_exporter import AlarmJsonExporter


def test_export_basic_mapping(monkeypatch, tmp_path: Path):
    """基本字段映射 + applicationProtocol / payload 逻辑复用校验"""
    exp = AlarmJsonExporter()

    # 伪造一条 _source（不走真实文件与解析）
    src = {
        "id": "ALARM-001",
        "ceventName": "ET MALWARE Possible Evil Traffic",
        "ceventType": "malware",
        "cEventMsg": "Suspicious beacon detected",
        "ceventLevel": "高危",
        "sid": 2200074,
        "processTime": "2025-10-21T10:20:30Z",
        "cprotocol": "TCP",
        "cSrcIp": "192.168.1.10",
        "iSrcPort": 51658,
        "cDstIp": "185.244.25.108",
        "iDstPort": 80,
        "payloadPrintable": "GET /foo HTTP/1.1\\r\\nHost: example.com\\r\\n",
        # RAW_PAYLOAD(hex-like just as a placeholder)
        "payload": "5241575f5041594c4f4144",
        "signaturemsg": "Raw signature text here",
    }

    # 打桩 JsonSourceReader：不读磁盘
    monkeypatch.setattr(exp.reader, "load_json", lambda _: {"dummy": True})
    monkeypatch.setattr(exp.reader, "extract_sources", lambda __: [src])

    # 打桩 PP 逻辑：确保 applicationProtocol 和 payload 走既定分支
    monkeypatch.setattr(exp.pp, "extract_orders", lambda text: [
                        "GET /", "Host: example.com"])
    # derive_l7 返回 (l7, proof_type)，此处只关心第二个（proof_type）
    monkeypatch.setattr(exp.pp, "derive_l7", lambda orders: ("HTTP", "http"))
    monkeypatch.setattr(exp.pp, "decode_payload_for_sheet",
                        lambda payload: "decoded_payload")

    out_path = tmp_path / "out.json"
    written = exp.export("ignored.json", str(out_path))

    assert written == str(out_path)
    data = json.loads(out_path.read_text(encoding="utf-8"))

    assert isinstance(data, list) and len(data) == 1
    row = data[0]

    # 固定与直接映射字段
    assert row["alarmId"] == "ALARM-001"
    assert row["alarmEngine"] == "suricata"
    assert row["alarmName"] == "ET MALWARE Possible Evil Traffic"
    assert row["alarmType"] == "malware"
    assert row["alarmDesc"] == "Suspicious beacon detected"
    assert row["alarmLevel"] == "高危"
    assert row["ruleId"] == 2200074
    assert row["ruleName"] == "ET MALWARE Possible Evil Traffic"
    assert row["ruleDesc"] == "Suspicious beacon detected"
    assert row["alarmTime"] == "2025-10-21T10:20:30Z"
    assert row["transportProtocol"] == "TCP"

    # 复用 proofType 逻辑的 applicationProtocol
    assert row["applicationProtocol"] == "http"

    # 端口/IP
    assert row["srcIp"] == "192.168.1.10"
    assert row["srcPort"] == 51658
    assert row["dstIp"] == "185.244.25.108"
    assert row["dstPort"] == 80

    # 复用 payload 解码清洗逻辑
    assert row["payload"] == "decoded_payload"

    # dataRaw 默认取 signaturemsg
    assert row["dataRaw"] == "Raw signature text here"

    # 只包含规定字段
    expected_keys = set(exp.FIELDS)
    assert set(row.keys()) == expected_keys


def test_dataRaw_fallback_signatureMsg(monkeypatch, tmp_path: Path):
    """当 signaturemsg 缺失时，dataRaw 应回退使用 signatureMsg"""
    exp = AlarmJsonExporter()

    src = {
        "id": "ALARM-002",
        "ceventName": "ET POLICY Something",
        "ceventType": "policy",
        "cEventMsg": "Policy match",
        "ceventLevel": "中危",
        "sid": 1234567,
        "processTime": "2025-10-21T11:22:33Z",
        "cprotocol": "UDP",
        "cSrcIp": "10.0.0.1",
        "iSrcPort": 53,
        "cDstIp": "8.8.8.8",
        "iDstPort": 53,
        "payloadPrintable": "",
        "payload": "",
        # 没有 signaturemsg，只有 signatureMsg
        "signatureMsg": "UpperCamelSignatureMsg",
    }

    monkeypatch.setattr(exp.reader, "load_json", lambda _: {"dummy": True})
    monkeypatch.setattr(exp.reader, "extract_sources", lambda __: [src])
    monkeypatch.setattr(exp.pp, "extract_orders", lambda text: [])
    monkeypatch.setattr(exp.pp, "derive_l7", lambda orders: ("DNS", "dns"))
    monkeypatch.setattr(exp.pp, "decode_payload_for_sheet", lambda payload: "")

    out_path = tmp_path / "out2.json"
    exp.export("ignored.json", str(out_path))

    data = json.loads(out_path.read_text(encoding="utf-8"))
    row = data[0]

    assert row["applicationProtocol"] == "dns"
    assert row["dataRaw"] == "UpperCamelSignatureMsg"
    assert row["srcPort"] == 53 and row["dstPort"] == 53
