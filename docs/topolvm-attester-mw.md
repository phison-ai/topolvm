# topolvm-attester MW 串接指南

> 2026-11-24

MW 每次呼叫 attester 都帶自己 Pod 的 ServiceAccount token 和一個新的 nonce，拿回 `result` + `attestation` 後用 TokenReview 驗證，驗過才信任結果。

## 1. 連線資訊

預設 namespace 是 `phison-system`；若不同，前兩列跟著換，建議做成 MW 的設定值。

| 項目 | 值 |
|------|-----|
| attester URL | `https://topolvm-attester.phison-system.svc:443` |
| attester 的 ServiceAccount username（驗證用） | `system:serviceaccount:phison-system:topolvm-attester` |
| kube-apiserver（送 TokenReview 用） | 免設定，Python 用 `config.load_incluster_config()`（`kubernetes` 套件）；curl 用 `https://kubernetes.default.svc` + `--cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt` |
| TLS | cert-manager 自簽憑證；client 可略過驗證，信任來源是 attestation 不是憑證 |
| nonce | 每次請求新產生，16–256 字元，hex 或 base64url |

## 2. 五個端點

五個都是 `GET`，呼叫方式一樣，只差在路徑。檢查端點不用傳裝置：attester 會從 token 認出呼叫的 Pod、找到它的節點，對組成 `vg_aidaptiv` 的實體 NVMe（md RAID0 會展開）執行 Sails。

| 端點 | 用途 | result.`use` | result.`fn` |
|------|------|--------------|-------------|
| `GET /handshake?nonce=` | 確認 token 有效，且對面是真的 attester | `handshake` | （無） |
| `GET /support_inference?nonce=` | 裝置是否支援 Inference | `result` | `support_inference` |
| `GET /support_finetune?nonce=` | 裝置是否支援 Finetune | `result` | `support_finetune` |
| `GET /mem_buf_set?nonce=` | 對裝置執行 Sails `mem_buf_set` | `result` | `mem_buf_set` |
| `GET /mem_buf_cpy?nonce=` | 對裝置執行 Sails `mem_buf_cpy` | `result` | `mem_buf_cpy` |

每個請求：

- Header：`Authorization: Bearer <token>`，token 讀 `/var/run/secrets/kubernetes.io/serviceaccount/token`，**每次呼叫都重新讀檔**（會自動輪替）
- Query：`nonce=<這次新產生的亂數>`（必帶）

```sh
URL=https://topolvm-attester.phison-system.svc
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

for fn in handshake support_inference support_finetune mem_buf_set mem_buf_cpy; do
  curl -sk -G "$URL/$fn" \
    -H "Authorization: Bearer $TOKEN" \
    --data-urlencode "nonce=$(openssl rand -hex 32)"
  echo
done
```

## 3. 回應格式

成功時回 JSON，兩個欄位都是**字串**：

```json
{
  "result": "{\"use\":\"result\",\"nonce\":\"...\",\"iat\":1763500000,\"pod\":\"team/web-0\",\"fn\":\"support_inference\",\"node\":\"gpu-node-1\",\"disks\":[\"/dev/nvme0n1\"],\"results\":[{\"nvme0n1\":\"1\"}]}",
  "attestation": "eyJhbGciOiJSUzI1NiIs..."
}
```

- `result`：內容是 JSON 的字串。**先對收到的原始 bytes 算 SHA-256 並驗證，再 parse**。不要 parse 後重新序列化再算，欄位順序或空白不同 hash 就對不上。
- `attestation`：kube-apiserver 簽給 `topolvm-attester` 的 token，audience = `sha256:<result 的 SHA-256 小寫 hex>`，有效 10 分鐘。MW 不要自己解 JWT，交給 TokenReview。
- `/handshake` 另外帶 `"token": "valid"`。
- 失敗時回 `{"error": "<message>"}`，狀態碼見第 5 節。

result 解開後的欄位：

| 欄位 | handshake | 檢查端點 | 說明 |
|------|-----------|----------|------|
| `use` | `handshake` | `result` | 兩種回應不可互換 |
| `nonce` | ✓ | ✓ | MW 送來的 nonce 原樣回傳 |
| `iat` | ✓ | ✓ | 產生時間（Unix 秒） |
| `pod` | | ✓ | 呼叫者 `<namespace>/<pod name>` |
| `fn` | | ✓ | 執行的 Sails 函式 |
| `node` | | ✓ | 裝置所在節點 |
| `disks` | | ✓ | 實際執行的裝置，如 `["/dev/nvme0n1","/dev/nvme1n1"]` |
| `results` | | ✓ | 每顆裝置一個物件，值是 Sails 輸出，如 `[{"nvme0n1":"1"}]`；例外時是 `error: <message>` |

四個檢查端點的成功值都是 `1`：`support_inference` / `support_finetune` 的 `1` = 支援、`0` = 不支援；`mem_buf_set` / `mem_buf_cpy` 的 `1` = 執行成功。

## 4. MW 的驗證步驟

每一個回應都要走完，任何一步失敗就視為沒有通過。HTTP 狀態碼、TLS 憑證、URL 都不是信任依據，只有 TokenReview 的回答是。

1. 每次請求前產生新的 nonce（例如 32 bytes 亂數轉 hex），並重新讀 token 檔。
2. 回應是 JSON，且有字串欄位 `result` 和 `attestation`。
3. `audience = "sha256:" + hex(SHA-256(result 的原始 bytes))`。
4. 對 kube-apiserver 建立 TokenReview：`spec.token = attestation`、`spec.audiences = [audience]`。
5. 檢查 TokenReview 的 `status`：
   - `authenticated` 是 `true`
   - `audiences` 包含 `audience`（空的也要視為失敗）
   - `user.username` 等於 `system:serviceaccount:<attester namespace>:topolvm-attester`
6. parse `result`：`use` 是該端點該有的值（`handshake` 或 `result`），`nonce` 等於**這一次**送出的 nonce。
7. 檢查端點另外檢查：
   - `fn` 等於呼叫的端點
   - `pod` 等於 MW **自己**的 `<namespace>/<pod name>`（namespace 讀 `/var/run/secrets/kubernetes.io/serviceaccount/namespace`；pod name 用 downward API `metadata.name`，或未設 `spec.hostname` 時的 hostname）
   - `results` 不為空，且每個值都是 `1`

為什麼要檢查 `pod`：否則攻擊者可以在有 Phison SSD 的節點開一個 Pod，拿 MW 的 nonce 去問真的 attester，再把這份真的回應交給跑在普通 SSD 上的 MW。

TokenReview 請求範例：

```json
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "spec": {
    "token": "<attestation>",
    "audiences": ["sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
  }
}
```

## 5. 錯誤碼

| HTTP | 意思 | MW 該怎麼處理 |
|------|------|---------------|
| `200` | 成功，含 `result` 和 `attestation` | 照第 4 節驗證 |
| `400` | `nonce` 缺少、< 16 或 > 256 字元、或含 hex / base64url 以外的字元 | MW 的 bug |
| `401` | token 遺失、TokenReview 不通過（過期、audience 不對、Pod 已刪除），或不是綁定 Pod 的 token | 確認每次重讀 token 檔 |
| `403` | Pod 沒有 `aidaptiv-cache` 的 volume | 部署設定錯誤 |
| `404` | token 對應的 Pod 不存在、UID 不符或正在刪除 | 不重試 |
| `409` | Pod 尚未排程到節點 | 稍後重試 |
| `500` | attester 申請 attestation token 失敗 | 重試 |
| `502` | agent 回報錯誤（節點沒有 `vg_aidaptiv`、Sails 執行失敗、agent report 驗不過） | 視為未通過 |
| `503` | 節點沒有運作中的 attester-agent，或 kube-apiserver 暫時無法回答 | 稍後重試 |

不管狀態碼為何，只要沒有通過第 4 節的驗證，就不能啟動。重試時要換新的 nonce。

## 6. 參考實作

Python（`pip install kubernetes requests`）：

```python
import hashlib, json, os, socket, requests
from kubernetes import client, config

NS = os.environ.get("ATTESTER_NAMESPACE", "phison-system")
ATTESTER_URL = f"https://topolvm-attester.{NS}.svc:443"
ATTESTER_USER = f"system:serviceaccount:{NS}:topolvm-attester"
SA = "/var/run/secrets/kubernetes.io/serviceaccount"

config.load_incluster_config()
auth = client.AuthenticationV1Api()
SELF = open(f"{SA}/namespace").read().strip() + "/" + socket.gethostname()

def call(fn):
    nonce = os.urandom(32).hex()
    token = open(f"{SA}/token").read().strip()      # 每次重讀
    r = requests.get(f"{ATTESTER_URL}/{fn}", params={"nonce": nonce},
                     headers={"Authorization": f"Bearer {token}"}, verify=False)
    r.raise_for_status()
    body = r.json()
    raw, attestation = body["result"], body["attestation"]

    # 先驗證，再 parse
    audience = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    st = auth.create_token_review(client.V1TokenReview(
        spec=client.V1TokenReviewSpec(token=attestation, audiences=[audience]))).status
    if not st.authenticated or audience not in (st.audiences or []) or st.user.username != ATTESTER_USER:
        raise ValueError("attestation rejected")

    res = json.loads(raw)
    use = "handshake" if fn == "handshake" else "result"
    if res["use"] != use or res["nonce"] != nonce:
        raise ValueError("result mismatch")
    if fn != "handshake":
        if res["fn"] != fn or res["pod"] != SELF:
            raise ValueError("fn/pod mismatch")
        if not res["results"] or not all(v == "1" for d in res["results"] for v in d.values()):
            raise ValueError(f"check failed: {res['results']}")
    return res

for fn in ["handshake", "support_inference", "support_finetune", "mem_buf_set", "mem_buf_cpy"]:
    print(fn, call(fn))
```

## 7. MW Pod 要怎麼設定

可直接套用的範例在 [`example/attester-mw-pod.yaml`](../example/attester-mw-pod.yaml)（ServiceAccount + ClusterRoleBinding + PVC + Pod），把 `mw` container 的 image 和 command 換成 MW 自己的程式即可：

```sh
kubectl apply -f example/attester-mw-pod.yaml
```

Pod 必須滿足四件事，缺一個就會被擋下來：

| 要求 | 為什麼 | 沒做到的後果 |
|------|--------|--------------|
| 不要設 `automountServiceAccountToken: false` | 呼叫 attester 的身分就是 kubelet 掛的 `/var/run/secrets/kubernetes.io/serviceaccount/token` | 沒有 token 可帶，`401` |
| MW 的 ServiceAccount 綁 ClusterRole `topolvm-attester-reviewer` | MW 自己要呼叫 TokenReview 驗 attestation（ClusterRole 由 TopoLVM chart 建立，binding 由 MW 的 chart 建立） | TokenReview 被 `403`，驗不了就不能信任結果 |
| 任一 volume 是 `aidaptiv-cache` StorageClass 的 PVC 或 generic ephemeral volume | attester 只服務真的在用 aiDAPTIV cache 的 Pod；這個 volume 也把 Pod 排到有 `vg_aidaptiv` 的節點 | 檢查端點回 `403` |
| 用 downward API 取 `metadata.name` / `metadata.namespace` | 驗證第 4 節第 7 步要比對 result 的 `pod` 等於自己的 `<namespace>/<pod name>` | 設了 `spec.hostname` 或在 StatefulSet / Deployment 裡時，hostname 不等於 pod name，會誤判失敗 |

部署成 Deployment、StatefulSet 或 KServe 的 `LLMInferenceServiceConfig` 時，把範例 Pod 的 `spec`（serviceAccountName、env、volumes、volumeMounts）搬進 Pod template 即可，其餘不變。

Pod 跑起來後可以先做連線煙霧測試，確認 token 和路由沒問題（還不含 TokenReview 驗證）：

```sh
kubectl exec -n default mw -- sh -c '
  curl -sk -G https://topolvm-attester.phison-system.svc/handshake \
    -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    --data-urlencode "nonce=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n")"'
```

回 `{"result":"...","attestation":"...","token":"valid"}` 就代表 attester 收下了 MW 的 token；接著照第 4 節驗證，再把四個檢查端點接起來。
