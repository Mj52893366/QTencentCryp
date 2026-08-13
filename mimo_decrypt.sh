
KEY="${1:?用法: sh decrypt.sh <密钥>}"

# 内嵌固定密文 token（base64url，无 padding）
TOKEN='eyJjaXBoZXJ0ZXh0IjpbeyJhZWFkIjoiYWVzLTI1Ni1nY20iLCJjaXBoZXJ0ZXh0IjoiN192dENXal8wR1VxSGxlMFlCQXpKV19KZGg2VnpCVENzR3VNV1Z5NHhnaW5QRjdFcDNoeXowYUJHQXZNIiwia2RmIjoiYXJnb24yaWQiLCJrZGZfcGFyYW1zIjp7Im1lbW9yeV9jb3N0X2tpYiI6NjU1MzYsInBhcmFsbGVsaXNtIjoyLCJ0aW1lX2Nvc3QiOjN9LCJub25jZSI6IjEyT3BIaGNCSmFibEVKTGIiLCJzYWx0IjoiQV9UeTNOaC03ZVhPOEJhWDdiaDkydz09In0seyJhZWFkIjoiYWVzLTI1Ni1nY20iLCJjaXBoZXJ0ZXh0IjoiaGl6Wnl4YlhyQnRVRHR1MDFkQU5hTmN4dHVJV2EyWDdzNXFZSjRVc2J0SHhiWXJwUG11YTk1ZC1uMWpxQVlmZFRVbGpfaTlnOGpXSFZIREIxWk4tS3MxQ2dEeWVMdk1kUWxua1lhQzZnZlhia1RmY1p0QVJ2VVdfSFQtZHJHN2FNTGc9Iiwia2RmIjoiYXJnb24yaWQiLCJrZGZfcGFyYW1zIjp7Im1lbW9yeV9jb3N0X2tpYiI6NjU1MzYsInBhcmFsbGVsaXNtIjoyLCJ0aW1lX2Nvc3QiOjN9LCJub25jZSI6IlFEcHFCY3hqNFJsLXhudWQiLCJzYWx0IjoiaUZYUzFaTGtwZ0hBNXRzTFdJUDdGUT09In1dLCJmb3JtYXQiOiJkdWFsLWtleS1kZW5pYWJsZS12YXVsdCIsInZlcnNpb24iOjF9'
RESULT=$(python3 - "$KEY" <<'PYEOF'
import base64, json, sys
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64d(t):
    t += "=" * (-len(t) % 4)
    return base64.urlsafe_b64decode(t)

token = "eyJjaXBoZXJ0ZXh0IjpbeyJhZWFkIjoiYWVzLTI1Ni1nY20iLCJjaXBoZXJ0ZXh0IjoiN192dENXal8wR1VxSGxlMFlCQXpKV19KZGg2VnpCVENzR3VNV1Z5NHhnaW5QRjdFcDNoeXowYUJHQXZNIiwia2RmIjoiYXJnb24yaWQiLCJrZGZfcGFyYW1zIjp7Im1lbW9yeV9jb3N0X2tpYiI6NjU1MzYsInBhcmFsbGVsaXNtIjoyLCJ0aW1lX2Nvc3QiOjN9LCJub25jZSI6IjEyT3BIaGNCSmFibEVKTGIiLCJzYWx0IjoiQV9UeTNOaC03ZVhPOEJhWDdiaDkydz09In0seyJhZWFkIjoiYWVzLTI1Ni1nY20iLCJjaXBoZXJ0ZXh0IjoiaGl6Wnl4YlhyQnRVRHR1MDFkQU5hTmN4dHVJV2EyWDdzNXFZSjRVc2J0SHhiWXJwUG11YTk1ZC1uMWpxQVlmZFRVbGpfaTlnOGpXSFZIREIxWk4tS3MxQ2dEeWVMdk1kUWxua1lhQzZnZlhia1RmY1p0QVJ2VVdfSFQtZHJHN2FNTGc9Iiwia2RmIjoiYXJnb24yaWQiLCJrZGZfcGFyYW1zIjp7Im1lbW9yeV9jb3N0X2tpYiI6NjU1MzYsInBhcmFsbGVsaXNtIjoyLCJ0aW1lX2Nvc3QiOjN9LCJub25jZSI6IlFEcHFCY3hqNFJsLXhudWQiLCJzYWx0IjoiaUZYUzFaTGtwZ0hBNXRzTFdJUDdGUT09In1dLCJmb3JtYXQiOiJkdWFsLWtleS1kZW5pYWJsZS12YXVsdCIsInZlcnNpb24iOjF9"

vault = json.loads(b64d(token).decode("utf-8"))
password = sys.argv[1]

for slot in vault.get("ciphertext", []):
    try:
        salt   = b64d(slot["salt"])
        nonce  = b64d(slot["nonce"])
        ct     = b64d(slot["ciphertext"])
        params = slot.get("kdf_params", {})
        key = hash_secret_raw(
            password.encode("utf-8"), salt,
            time_cost=int(params.get("time_cost", 3)),
            memory_cost=int(params.get("memory_cost_kib", 65536)),
            parallelism=int(params.get("parallelism", 2)),
            hash_len=32, type=Type.ID,
        )
        pt = AESGCM(key).decrypt(nonce, ct, None)
        data = json.loads(pt.decode("utf-8"))
        if data.get("version") == 1:
            print(data["data"])
            sys.exit(0)
    except Exception:
        continue

print("解密失败：密钥错误", file=sys.stderr)
sys.exit(1)
PYEOF
)

if [ $? -eq 0 ]; then
    eval "echo \"$RESULT\""
else
    echo "$RESULT" >&2
    exit 1
fi
