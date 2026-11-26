# topolvm-attester API 使用說明

topolvm-attester 提供一組 HTTPS REST API,供使用 `aidaptiv-cache` StorageClass 的工作負載 Pod(以下稱 MW,aiDAPTIV middleware)對 Pod 所在節點上組成 `vg_aidaptiv` 的 Phison SSD 執行 Sails 檢查。

**整套機制不使用任何自己的公私鑰。** 兩個方向都用 Kubernetes ServiceAccount token,簽章私鑰只在 kube-apiserver 裡:

| 方向 | 怎麼做 | 證明什麼 |
|---|---|---|
| MW → attester | MW 帶 Pod 預設掛載的 ServiceAccount token,attester 用 **TokenReview** 驗 | 呼叫者是哪個 namespace 的哪個 Pod |
| attester → MW | attester 用 **TokenRequest** 替自己的 ServiceAccount 申請 token,綁定自己的 Pod,**audience 設為回應內容的 SHA-256**;MW 用 **TokenReview** 驗 | 這份 result 是 attester 產生的,而且一個 byte 都沒被改過 |

HTTP 狀態碼、TLS 憑證、attester 的 URL 本身都不是信任依據;信任來源是 cluster 的 kube-apiserver 對 TokenReview 的回答。

端點名稱與 cache-operator 相同,但認證與回應格式不同,舊 client 需要改寫。

---

## MW 需要準備的東西

### 1. 呼叫 attester 用的 token:不用設定

每個 Pod 都有 kubelet 自動掛載的 ServiceAccount token:`/var/run/secrets/kubernetes.io/serviceaccount/token`。它由 kubelet 向 kube-apiserver 申請、綁定這個 Pod、自動輪替。MW 什麼都不用加,**每次呼叫都重新讀檔**即可。Pod 沒指定 `serviceAccountName` 時用的是 namespace 的 `default`。

唯一的條件是 Pod 不能設 `automountServiceAccountToken: false`。

同一個 token 也是 MW 呼叫 TokenReview 時的身分,所以 MW 只需要這一個 token。

> 這個 token 的 audience 是 kube-apiserver,送給 attester 等於讓 attester 拿到 MW 的 cluster 權限。MW 的 ServiceAccount 權限應該只有下面的 `tokenreviews create`。
>
> 要避免這點,可以在 Pod template(例如 `LLMInferenceServiceConfig` 的 `spec.template`)另加一個 projected volume,audience 設 `topolvm-attester`,MW 呼叫 attester 時改帶那個檔案。attester 兩種 token 都接受。
>
> ```yaml
> volumes:
>   - name: attester-token
>     projected:
>       sources:
>         - serviceAccountToken:
>             audience: topolvm-attester
>             expirationSeconds: 3600
>             path: token
> ```

### 2. 建立 TokenReview 的權限

attester 的 manifest 附了 ClusterRole `topolvm-attester-reviewer`(只有 `tokenreviews` `create`)。MW 的 chart 把它綁到 MW 的 ServiceAccount:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: mw-topolvm-attester-reviewer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: topolvm-attester-reviewer
subjects:
  - kind: ServiceAccount
    name: mw
    namespace: <MW 的 namespace>
```

內建的 `system:auth-delegator` 也可以,但多給了 SubjectAccessReview。

### 3. 寫死在 MW 裡的值

| 值 | 內容 |
|---|---|
| attester 的 URL | `https://topolvm-attester.topolvm-system.svc:443` |
| attester 的 ServiceAccount username | `system:serviceaccount:topolvm-system:topolvm-attester` |
| kube-apiserver | in-cluster config(`KUBERNETES_SERVICE_HOST` + ServiceAccount 掛載的 `ca.crt`) |

### 4. 呼叫的 Pod 必須使用 `aidaptiv-cache`

Pod 的任一 volume 是以下兩種之一,且 StorageClass 為 `aidaptiv-cache`(`--storage-class`),否則檢查端點回 `403`:

- `persistentVolumeClaim`(PVC 沒指定 class 時以 cluster 的 default StorageClass 判斷)
- `ephemeral.volumeClaimTemplate`(generic ephemeral volume)

不需要 webhook、不需要 `PHISON_TOKEN` 環境變數,也不需要宣告 `phison.com/ai100` resource。

---

## 連線資訊

| 項目 | 說明 |
|------|------|
| 預設位址 | `https://topolvm-attester.topolvm-system.svc:443` |
| 傳輸加密 | TLS(cert-manager 自簽憑證;client 可略過驗證,信任來源是 attestation 不是憑證) |
| 認證方式 | `Authorization: Bearer <Pod 的 ServiceAccount token>`(預設 token,或 aud=`topolvm-attester` 的 projected token) |
| 每次請求必帶 | `nonce` query 參數:MW 當次隨機產生,16 到 256 字元,hex 或 base64url |

---

## API 端點一覽

| 路徑 | 說明 |
|------|------|
| `GET /handshake?nonce=` | 確認 token 有效,且對面是真的 attester |
| `GET /mem_buf_set?nonce=` | 對裝置執行 Sails `mem_buf_set` |
| `GET /mem_buf_cpy?nonce=` | 對裝置執行 Sails `mem_buf_cpy` |
| `GET /support_finetune?nonce=` | 查詢裝置是否支援 Finetune |
| `GET /support_inference?nonce=` | 查詢裝置是否支援 Inference |

四個檢查端點都不需要 `devices` 參數。attester 從 TokenReview 拿到呼叫的 Pod(`user.extra` 的 `authentication.kubernetes.io/pod-name` / `pod-uid`),取得它所在的節點,請該節點的 attester agent 列出 `vg_aidaptiv` 的 physical volume、沿 sysfs 解析到底層的實體 NVMe(md RAID0 會展開成所有成員),再對這些裝置執行 Sails。

`devices` 參數仍然接受:有給時 result 裡只包含名單內裝置的結果(`/dev/` 前綴可有可無)。

---

## 回應格式

成功時回 JSON 物件:

```json
{
  "result": "{\"use\":\"result\",\"nonce\":\"...\",\"iat\":1763500000,\"pod\":\"team/web-0\",\"fn\":\"support_inference\",\"node\":\"gpu-node-1\",\"disks\":[\"/dev/nvme0n1\"],\"results\":[{\"nvme0n1\":\"1\"}]}",
  "attestation": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9.eyJhdWQiOlsic2hhMjU2Oi4uLiJdLCJleHAiOi4uLn0.sig"
}
```

- **`result` 是字串**,內容是 JSON。MW 必須對**收到的這個字串的原始 bytes**(UTF-8)算 SHA-256,**先驗證、再 parse**。不要 parse 後重新序列化再算 hash,欄位順序或空白不同就對不上。
- **`attestation`** 是 kube-apiserver 簽發給 `topolvm-attester` ServiceAccount 的 token:audience 是 `sha256:<result 的 SHA-256,小寫 hex,64 字元>`,綁定 attester 的 Pod,有效 10 分鐘(TokenRequest 的下限)。MW 不需要、也不應該自己解 JWT:交給 TokenReview。
- `/handshake` 另外帶 `"token":"valid"`,與 cache-operator 相同。

**result 欄位**

| 欄位 | handshake | 檢查端點 | 說明 |
|---|---|---|---|
| `use` | `handshake` | `result` | 兩種回應不可互換 |
| `nonce` | ✓ | ✓ | MW 送來的 nonce 原樣回傳 |
| `iat` | ✓ | ✓ | attester 產生 result 的時間(Unix 秒) |
| `pod` | | ✓ | 呼叫者,`<namespace>/<name>` |
| `fn` | | ✓ | 執行的 Sails 函式 |
| `node` | | ✓ | 裝置所在節點 |
| `disks` | | ✓ | Sails 實際執行的裝置,如 `["/dev/nvme0n1","/dev/nvme1n1"]` |
| `results` | | ✓ | 每顆裝置一個物件,值是 Sails 輸出:`[{"nvme0n1":"1"},{"nvme1n1":"1"}]` |

Sails 對某顆裝置拋出例外時,該裝置的值是 `error: <message>`。

錯誤時回:

```json
{"error": "<error message>"}
```

---

## MW 的驗證步驟

每一個回應都要走完下列步驟,任何一步失敗就視為沒有通過檢查:

1. 回應是 JSON,且有字串欄位 `result` 和 `attestation`。
2. `audience = "sha256:" + hex(SHA-256(result 的原始 bytes))`。
3. 對 kube-apiserver 建立 TokenReview:`spec.token = attestation`、`spec.audiences = [audience]`。
4. 檢查 TokenReview 的 `status`:
   - `authenticated` 是 `true`;
   - `audiences` 包含 `audience`(authenticator 沒有確認 audience 時這裡是空的,必須視為失敗);
   - `user.username` 等於 `system:serviceaccount:topolvm-system:topolvm-attester`。
5. parse `result`:`use` 是這個端點該有的值(`handshake` 或 `result`),`nonce` 等於 MW **這一次請求**送出的 nonce。每次請求都要換新的 nonce,否則錄下來的回應可以重播。
6. 檢查端點:`fn` 等於呼叫的端點,`pod` 等於 MW **自己**的 `<namespace>/<pod 名稱>`,`results` 不為空且每個值都是 `1`。

   `pod` 不檢查的話,攻擊者可以在有 Phison SSD 的節點上開一個 Pod,拿 MW 的 nonce 去問真的 attester,再把這份(真的、簽過的)回應交給跑在普通 SSD 上的 MW。`pod` 是 attester 從呼叫者 token 的 TokenReview 得到的,攻擊者改不了。MW 的 namespace 在 `/var/run/secrets/kubernetes.io/serviceaccount/namespace`;Pod 名稱用 downward API 的 `metadata.name`,或 hostname(沒設 `spec.hostname` 時等於 Pod 名稱)。

TokenReview 的範例(MW 送出的):

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

kube-apiserver 回的 `status`(驗過時):

```json
{
  "authenticated": true,
  "audiences": ["sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
  "user": {
    "username": "system:serviceaccount:topolvm-system:topolvm-attester",
    "uid": "...",
    "groups": ["system:serviceaccounts", "system:serviceaccounts:topolvm-system", "system:authenticated"],
    "extra": {
      "authentication.kubernetes.io/pod-name": ["topolvm-attester-7d9c6b5f4-x2x8q"],
      "authentication.kubernetes.io/pod-uid": ["..."]
    }
  }
}
```

以 Python 為例(`pip install kubernetes requests`):

```python
import hashlib, json, os, socket, requests
from kubernetes import client, config

MAAT_URL = "https://topolvm-attester.topolvm-system.svc:443"
MAAT_USER = "system:serviceaccount:topolvm-system:topolvm-attester"
TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token"

config.load_incluster_config()
auth = client.AuthenticationV1Api()

def call(fn, use):
    nonce = os.urandom(32).hex()
    token = open(TOKEN_FILE).read().strip()          # 每次重讀,kubelet 會輪替
    r = requests.get(f"{MAAT_URL}/{fn}", params={"nonce": nonce},
                     headers={"Authorization": f"Bearer {token}"}, verify=False)
    r.raise_for_status()
    body = r.json()
    raw, attestation = body["result"], body["attestation"]

    audience = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    review = auth.create_token_review(client.V1TokenReview(
        spec=client.V1TokenReviewSpec(token=attestation, audiences=[audience])))
    st = review.status
    if not st.authenticated or audience not in (st.audiences or []) or st.user.username != MAAT_USER:
        raise ValueError("attestation rejected")

    res = json.loads(raw)
    if res["use"] != use or res["nonce"] != nonce:
        raise ValueError("result mismatch")
    return res

call("handshake", "handshake")
res = call("support_inference", "result")
SELF = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read().strip() + "/" + socket.gethostname()
assert res["fn"] == "support_inference"
assert res["pod"] == SELF                      # 防止別的 Pod 轉送 nonce
assert res["results"] and all(v == "1" for d in res["results"] for v in d.values())
```

---

## 端點範例

### `GET /handshake`

```sh
NONCE=$(openssl rand -hex 32)
curl -k -G "https://topolvm-attester.topolvm-system.svc/handshake" \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  --data-urlencode "nonce=$NONCE"
```

```json
{"token": "valid", "result": "{\"use\":\"handshake\",\"nonce\":\"<NONCE>\",\"iat\":1763500000}", "attestation": "eyJhbGciOiJSUzI1NiIs..."}
```

### `GET /support_inference`

```sh
NONCE=$(openssl rand -hex 32)
curl -k -G "https://topolvm-attester.topolvm-system.svc/support_inference" \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  --data-urlencode "nonce=$NONCE"
```

`result` 解開後:

```json
{
  "use": "result", "nonce": "<NONCE>", "iat": 1763500000,
  "pod": "team/web-0", "fn": "support_inference", "node": "gpu-node-1",
  "disks": ["/dev/nvme0n1", "/dev/nvme1n1"],
  "results": [{"nvme0n1": "1"}, {"nvme1n1": "1"}]
}
```

`1` 表示支援,`0` 表示不支援(與 TopoLVM lvmd 的 `nvme-check-command` 讀的是同一個輸出)。

`/support_finetune`、`/mem_buf_set`、`/mem_buf_cpy` 用法相同,只有 `fn` 不同。

### 只看特定裝置(相容參數)

```sh
curl -k -G "https://topolvm-attester.topolvm-system.svc/support_inference" \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "devices=nvme0n1"
```

result 的 `results` 會是 `[{"nvme0n1": "1"}]`。

---

## 認證與信任流程

```
MW Pod(PVC / ephemeral volume 使用 aidaptiv-cache;kubelet 掛好預設 ServiceAccount token)
  │
  └─ MW 產生 nonce,呼叫檢查端點  Authorization: Bearer <MW 的 token>
       attester:  TokenReview(token)→ ns + pod-name + pod-uid
              → 讀 Pod(比對 UID)→ 確認用了 aidaptiv-cache → nodeName
              → 找該節點的 topolvm-attester-agent Pod
              → TokenRequest(topolvm-attester, aud=topolvm-attester-agent)→ 呼叫 agent(帶 attester 自己的 nonce)
       agent: TokenReview(token, aud=topolvm-attester-agent)→ 必須是 topolvm-attester
              pvs --select vg_name=vg_aidaptiv → sysfs 解析 backing disks
              → /shared/Sails <fn> nvme0n1,nvme1n1
              → report = JSON{nonce, node, fn, disks, results}
              → TokenRequest(topolvm-attester-agent, aud="sha256:"+SHA-256(report), 綁定 agent Pod)
       attester:  TokenReview(agent attestation)→ 必須是 topolvm-attester-agent、綁定剛呼叫的 agent Pod
              → nonce、fn、node 符合才採用
       attester:  result = JSON{use, nonce, iat, pod, fn, node, disks, results}
              TokenRequest(topolvm-attester, aud="sha256:"+SHA-256(result), 綁定 attester Pod, 10 分鐘)
              → {"result": result, "attestation": token}
       MW:    TokenReview(attestation, aud="sha256:"+SHA-256(result))
              → authenticated、audience 符合、username = topolvm-attester
              → nonce、fn 符合,pod 是自己,results 全為 1 → 才啟動
```

### 為什麼偽造不了

- 改 result 的任何一個 byte,hash 就變了;原本的 token 對新的 audience 驗不過。
- 要對新的 audience 拿到 token,必須能替 `topolvm-system/topolvm-attester` 建立 `serviceaccounts/token`。這個權限只有 attester 自己(Role `topolvm-attester-token`,`resourceNames: [topolvm-attester]`)和 cluster 管理者有。
- 拿別的 ServiceAccount 申請的 token,TokenReview 回的 username 不是 `topolvm-attester`。
- 錄下來的舊回應,nonce 對不上;把 nonce 改掉,hash 就變了。
- 把 MW 的 nonce 轉給另一個(在 Phison SSD 節點上的)Pod 去問 attester,result 的 `pod` 是那個 Pod,不是 MW。
- 在 agent 和 attester 之間(純 HTTP)改 agent 的回應:agent 的 report 也附 attestation(`topolvm-attester-agent`、綁定 agent Pod、aud = report 的 hash),attester 驗不過就回 `502`,不會替它簽 attestation。
- attester 的 Pod 刪掉後,綁在它身上的 token 就驗不過(kube-apiserver 會快取成功的 review 約 10 秒)。

### 這套機制的極限

擋得住的是「假的 attester」、「竄改結果」和「重播舊回應」。擋**不住**的是 cluster 管理者或任何能做到下列其中一件事的人:

- 在 `topolvm-system` 建立 `serviceaccounts/token`(例如 `kubectl create token topolvm-attester -n topolvm-system --audience sha256:...`);
- 在 `topolvm-system` 用 `topolvm-attester` ServiceAccount 建 Pod,或 exec 進 attester 的 Pod;
- 讓 MW 連到假的 kube-apiserver(改 MW 的 kubeconfig / `KUBERNETES_SERVICE_HOST` / CA)。

所以 `topolvm-system` namespace 的權限要收緊。和先前把 private key 編進 image 的做法相比,這裡完全沒有 key 要保管、外洩或輪替;代價是信任錨點從「Phison 的 key」換成「客戶 cluster 的 kube-apiserver」,cluster 管理者用一行 `kubectl create token` 就能偽造,比從 image 抽出 key 更容易。要連 cluster 管理者都擋,簽章必須由 SSD 韌體產生,這不在 attester 的範圍內。

---

## 錯誤碼對照

| HTTP 狀態碼 | 說明 |
|-------------|------|
| `200 OK` | 請求成功,回應含 `result` 和 `attestation` |
| `400 Bad Request` | `nonce` 缺少、太短(< 16)、太長(> 256)或含 hex / base64url 以外的字元 |
| `401 Unauthorized` | Bearer token 遺失、TokenReview 不通過(過期、audience 不對、Pod 已刪除),或 token 不是綁定 Pod 的 ServiceAccount token |
| `403 Forbidden` | 呼叫的 Pod 沒有 `aidaptiv-cache` StorageClass 的 volume |
| `404 Not Found` | token 對應的 Pod 不存在、UID 不符(同名 Pod 被重建)或正在刪除 |
| `409 Conflict` | Pod 尚未排程到節點 |
| `500 Internal Server Error` | attester 申請 attestation token 失敗 |
| `502 Bad Gateway` | agent 回報錯誤(例如節點上沒有 `vg_aidaptiv`、Sails 執行失敗) |
| `503 Service Unavailable` | Pod 所在節點沒有在執行的 topolvm-attester-agent,或 kube-apiserver 暫時無法回答 TokenReview |
