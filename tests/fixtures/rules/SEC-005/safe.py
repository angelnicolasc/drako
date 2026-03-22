# ok: SEC-005
# Safe data parsing without exec/eval
import ast
import json

data = '{"key": "value"}'
parsed = json.loads(data)
literal = ast.literal_eval("{'a': 1}")
