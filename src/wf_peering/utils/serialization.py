import json


def dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def loads(value, default=None):
    if value is None: return default
    try: return json.loads(value)
    except (TypeError, ValueError): return default
