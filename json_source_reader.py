from __future__ import annotations
import json
from typing import Any, Dict, List


class JsonSourceReader:
    """
    读取 JSON（例如 1.json/2.json），并抽取所有 _source（容忍直接为对象列表的情况）。
    主要针对 ElasticSearch 风格：{"hits":{"hits":[{"_source":{...}}, ...]}}
    """

    def load_json(self, path: str) -> Any:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _read_hits(self, data: Any) -> List[Any]:
        # 标准 ES 结构：{"hits":{"hits":[...]} }
        if isinstance(data, dict):
            hits = data.get("hits")
            if isinstance(hits, dict):
                inner = hits.get("hits")
                if isinstance(inner, list):
                    return inner
            # 容错：有些数据直接是 {"hits":[...]}
            if isinstance(hits, list):
                return hits
            # 容错：直接一条对象
            if "_source" in data:
                return [data]
        # 顶层就是数组
        if isinstance(data, list):
            return data
        return []

    def extract_sources(self, data: Any) -> List[Dict[str, Any]]:
        sources: List[Dict[str, Any]] = []
        for h in self._read_hits(data):
            if isinstance(h, dict):
                src = h.get("_source", {})
                if not isinstance(src, dict) or not src:
                    src = h if isinstance(h, dict) else {}
                if isinstance(src, dict):
                    sources.append(src)
        return sources
