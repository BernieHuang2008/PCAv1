import json
import unicodedata
from typing import Any

def _normalize_nfc(obj: Any) -> Any:
    """
    递归遍历 JSON 结构，对所有字符串值进行 NFC 归一化。
    - 键名不归一化（保持原样）。
    - 支持 dict、list 以及基本类型。
    """
    if isinstance(obj, dict):
        return {key: _normalize_nfc(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [_normalize_nfc(item) for item in obj]
    elif isinstance(obj, str):
        return unicodedata.normalize('NFC', obj)
    else:
        return obj

def serialize_JSON_to_JCS(json_obj: dict) -> str:
    """
    将 JSON 对象序列化为符合 RFC 8785 的字符串。

    步骤：
    `原始输入 → NFC 归一化 → 作为JSON相应字段的值 → JCS 序列化`
    1. 对 JSON 对象中的所有字符串值进行 NFC 归一化（键名除外）。
    2. 使用 json.dumps 进行序列化：
       - separators=(',', ':') 去除所有无关空格和换行。
       - sort_keys=True 按字典序（ASCII 码顺序）排列键。
       - ensure_ascii=True 将所有非 ASCII 字符转义为 \\uXXXX。
    3. 返回 UTF-8 编码的字节串。
    """
    
    # 预处理：值归一化
    normalized_obj = _normalize_nfc(json_obj)

    # JCS 序列化
    json_str = json.dumps(
        normalized_obj,
        separators=(',', ':'),
        sort_keys=True,
        ensure_ascii=True
    )
    return json_str

def serialize_JSON_to_JCS_bytes(json_obj: dict) -> bytes:
    """
    json -> 字符串 -> 字节流
    """
    # 获取 JCS 序列化的字符串
    json_str = serialize_JSON_to_JCS(json_obj)
    
    # 转换为字节串
    return json_str.encode('utf-8')

def check_JCS_isvalid(json_str: str) -> bool:
    """
    检查 `原始输入 → NFC 归一化 → 作为JSON相应字段的值 → JCS 序列化`
    """

    try:
        # 尝试解析 JSON 字符串
        parsed_obj = json.loads(json_str)
    except json.JSONDecodeError:
        return False

    # 重新序列化为 JCS 格式
    jcs_serialized = serialize_JSON_to_JCS(parsed_obj)

    # 检查原始字符串是否与 JCS 序列化结果一致
    return json_str == jcs_serialized


if __name__=="__main__":
    print(serialize_JSON_to_JCS({
        "name": "Alice",
        "age": 30,
        "city": "New York",
        "hobbies": ["看书", "traveling", "coding"],
        "details": {
            "height": 175.5,
            "weight": 70.2,
            "is_student": False
        }
    }))
