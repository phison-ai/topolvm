# topolvm-attester

`topolvm-attester`:TopoLVM 的一個元件,負責 aiDAPTIV cache 的 SSD 驗證。把 cache-operator 的「開 API 用 Sails 驗 SSD」搬到 TopoLVM + `aidaptiv-cache` StorageClass 的環境:Pod 不再申請 `phison.com/ai100` device,而是掛一個 `aidaptiv-cache` 的 PVC。

**不使用任何自己的公私鑰,也沒有 webhook。** 所有憑證都是 Kubernetes ServiceAccount token,簽章私鑰在 kube-apiserver:

- **API**(`/handshake`、`/mem_buf_set`、`/mem_buf_cpy`、`/support_finetune`、`/support_inference`):呼叫者(aiDAPTIV middleware,MW)帶 Pod 預設掛載的 ServiceAccount token(不用改 Pod 設定;也接受 audience `topolvm-attester` 的 projected token),attester 用 **TokenReview** 驗、得知呼叫的 Pod 和它所在的節點,請該節點的 agent 對組成 `vg_aidaptiv` 的所有 Phison SSD 跑 Sails。
- **防偽造**:attester 把結果編成 JSON 字串 `result`,用 **TokenRequest** 替自己的 ServiceAccount `topolvm-attester` 申請 token,綁定自己的 Pod,**audience 設為 `sha256:<result 的 hash>`**,一起回傳為 `attestation`。MW 對收到的 `result` 算 hash,用 TokenReview 驗 `attestation` 對這個 audience 有效、且屬於 `topolvm-attester`,才採信。改一個 byte 就驗不過。細節見 [topolvm-attester-api.md](topolvm-attester-api.md)。
- **topolvm-attester-agent**(DaemonSet,只排在 `otterscale.io/aidaptiv=true` 的節點):`pvs` 列出 volume group 的 PV,沿 sysfs 的 `slaves/` 展開到底層實體 NVMe(md RAID0 會展開成所有成員,和 TopoLVM `nvmecheck.go` 同一套邏輯),再執行 `/shared/Sails`。Sails 由 `ghcr.io/phison-ai/sails` init container 複製進來,和 TopoLVM lvmd 的做法一樣。attester → agent 也是 TokenRequest(audience `topolvm-attester-agent`)+ TokenReview;agent 的回應則和 API 一樣附 attestation(`topolvm-attester-agent` 的 token,綁定 agent Pod,aud = sha256(report)),attester 驗過才採用,所以 agent 和 attester 之間的 HTTP 也改不了結果。

## 架構

```
MW Pod(PVC: aidaptiv-cache;kubelet 掛好的預設 ServiceAccount token)
  │  GET /support_inference?nonce=<隨機>  Authorization: Bearer <MW 的 token>
  ▼
topolvm-attester(Service topolvm-attester:443 → 9443,cert-manager 憑證)
  │  TokenReview(MW token)→ ns / pod-name / pod-uid → 讀 Pod、確認 aidaptiv-cache → nodeName
  │  TokenRequest(topolvm-attester, aud=topolvm-attester-agent)
  │  GET http://<agent>:9449/v1/check/support_inference?vg=vg_aidaptiv&nonce=<attester 的隨機值>
  ▼
topolvm-attester-agent(privileged, hostPID)
     TokenReview(aud=topolvm-attester-agent)→ 必須是 topolvm-attester
     nsenter -t 1 … pvs --select vg_name=vg_aidaptiv --reportformat json   → /dev/md127
     /sys/class/block/md127/slaves/                                          → nvme0n1, nvme1n1
     LD_LIBRARY_PATH=/shared/lib /shared/Sails support_inference nvme0n1,nvme1n1
     → [{"nvme0n1":"1"},{"nvme1n1":"1"}]
     report = JSON{use:agent-result, nonce, node, fn, disks, results}
     TokenRequest(topolvm-attester-agent, aud="sha256:"+SHA-256(report), 綁定 agent Pod) → {result, attestation}
  ▲
topolvm-attester:TokenReview(agent attestation)→ username = topolvm-attester-agent、綁定的是剛呼叫的 agent Pod
               → nonce、fn、node 符合才採用
topolvm-attester:result = JSON{use, nonce, iat, pod, fn, node, disks, results}
               TokenRequest(topolvm-attester, aud="sha256:"+SHA-256(result), 綁定 attester Pod)
               → {"result": "<JSON 字串>", "attestation": "<token>"}
  ▲
MW:TokenReview(attestation, aud="sha256:"+SHA-256(result))
    → authenticated、audience 符合、username = system:serviceaccount:topolvm-system:topolvm-attester
    → nonce、fn 符合,pod 是自己,results 全為 1 → 才啟動
```

以 release 名稱 `topolvm`、namespace `topolvm-system` 安裝時(`<fullname>` = `topolvm`):

| 物件 | 名稱 | 說明 |
|---|---|---|
| Deployment | `<fullname>-attester` | API;每個 replica 都服務,沒有 leader election |
| DaemonSet | `<fullname>-attester-agent` | 節點 agent,privileged、hostPID |
| ServiceAccount | `topolvm-attester`、`topolvm-attester-agent` | 固定名稱(`attester.serviceAccountName`、`attester.agent.serviceAccountName`),MW 寫死前者 |
| Service | `topolvm-attester` | 固定名稱(`attester.serviceName`),MW 呼叫 `https://topolvm-attester.topolvm-system.svc` |
| Role | `<fullname>-attester-token`、`<fullname>-attester-agent-token` | 只能替**自己的** ServiceAccount 建 `serviceaccounts/token`(`resourceNames`) |
| ClusterRole | `<fullname>-attester`、`<fullname>-attester-agent` | TokenReview;attester 另可讀 Pod、PVC、StorageClass |
| ClusterRole | `topolvm-attester-reviewer` | `tokenreviews create`;由 MW 的 chart 綁到 MW 的 ServiceAccount |
| Certificate、Issuer | `<fullname>-attester`、`<fullname>-attester-selfsign` | API 的 serving certificate(`attester.certManager`) |
| StorageClass `aidaptiv-cache`、`vg_aidaptiv` | — | TopoLVM chart 和 aidpx 建立,不由 attester 管理 |

### 為什麼不從 TopoLVM 拿驗證結果

TopoLVM fork 的 commit `f2005a9`(`internal/lvmd/nvmecheck.go`)只在 lvmd 執行 `CreateLV` / `ResizeLV` / `CreateLVSnapshot` 時跑 `Sails support_inference`,結果放在 lvmd 行程內的 in-memory cache,沒有 gRPC、annotation 或 CR 欄位對外。所以 attester 直接對 host 上組成 `vg_aidaptiv` 的 SSD 驗證,並沿用它解析 PV → backing disk 的方法。

### 安全邊界

- 沒有 admission webhook:attester 掛掉不會影響任何 Pod 的建立,只是 API 呼叫失敗。
- MW 的 token 是 kubelet 掛的 ServiceAccount token(預設的那個,或 audience `topolvm-attester` 的 projected token;都會自動輪替),不是 attester 簽的。用預設 token 時 attester 會拿到 MW 的 cluster 權限,所以 MW 的 ServiceAccount 只該有 `tokenreviews create`;attester 只接受綁定 Pod 的 ServiceAccount token,並用 `pod-uid` 比對,同名 Pod 重建後舊 token 對不上。
- 呼叫的 Pod 必須有 `aidaptiv-cache` 的 volume(`--storage-class`),否則 `403`。
- agent 只接受 `topolvm-attester` 的 token(audience `topolvm-attester-agent`,10 分鐘,attester 快取重用)。
- agent 的回應走純 HTTP,但每份 report 都附 `topolvm-attester-agent` 的 attestation:attester 確認簽發對象是剛呼叫的那個 agent Pod(名稱 + UID)、nonce 是這次的、`node` 是 MW 的節點,才採用。改內容、重播舊 report、拿別台節點的 report 頂替都會 `502`。
- attester 不需要 `pods/exec`,也不是 privileged;privileged 只在 agent。
- attestation 擋得住假的 attester、竄改結果和重播;擋不住能在 `topolvm-system` 替 `topolvm-attester` 申請 token 的人(cluster 管理者一行 `kubectl create token` 就能做到)或能讓 MW 連到假 kube-apiserver 的人。信任錨點是客戶 cluster 的 kube-apiserver,`topolvm-system` 的權限要收緊。要連管理者都擋,簽章得由 SSD 韌體產生,不在 attester 範圍內。

## 部署

由 TopoLVM 的 chart 部署,預設關閉。打開 `attester.enabled` 即可:

```yaml
# values.yaml
attester:
  enabled: true
```

- 兩個元件都用 TopoLVM 本身的 image(`image.repository` / `image.reference`):`hypertopolvm` 依 `/topolvm-attester`、`/topolvm-attester-agent` 這兩個 symlink 分派,不另外出 image,也沒有任何 key。
- chart 的 template 在 `charts/topolvm/templates/attester/`,所有值在 `values.yaml` 的 `attester:` 底下(見 chart README)。
- `attester.serviceAccountName`(預設 `topolvm-attester`)和 `attester.serviceName`(預設 `topolvm-attester`)不跟 release name 走:MW 寫死 `system:serviceaccount:<namespace>:topolvm-attester` 和 `https://topolvm-attester.<namespace>.svc`。chart 要裝在 `topolvm-system`,改這兩個值或 namespace 都要重新發布 MW。
- serving certificate 預設由 cert-manager 簽(`attester.certManager`);關掉時用 `attester.tlsSecretName` 指定現有的 Secret。
- agent 是 privileged DaemonSet(和 lvmd / topolvm-node 一樣),只排在 `attester.agent.nodeSelector`(預設 `otterscale.io/aidaptiv=true`)的節點。Sails image 是 `attester.agent.sails.image`,要和 lvmd values 的 Sails 版本同步。

MW 那邊要做的事(綁 `topolvm-attester-reviewer`;projected token volume 可選)見 [topolvm-attester-api.md](topolvm-attester-api.md)「MW 需要準備的東西」。

### 參數

attester(`cmd/topolvm-attester`):

| flag | 預設 | 說明 |
|---|---|---|
| `--namespace` | `POD_NAMESPACE`,再來是 ServiceAccount 的 namespace | attester 和 agent 所在 namespace |
| `--service-account` | `POD_SERVICE_ACCOUNT`,再來是 `topolvm-attester` | attestation 用的 ServiceAccount(attester 自己的) |
| `--pod-name` / `--pod-uid` | `POD_NAME` / `POD_UID` | attestation 綁定的 Pod(attester 自己);沒給時不綁定並印 WARNING |
| `--storage-class` | `aidaptiv-cache` | 呼叫的 Pod 必須使用的 StorageClass;空字串表示不檢查 |
| `--volume-group` | `vg_aidaptiv` | agent 要驗證的 volume group |
| `--agent-port` | `9449` | agent 的 port |
| `--agent-service-account` | `topolvm-attester-agent` | 只採用這個 ServiceAccount attest 的 agent report |

agent(`cmd/topolvm-attester-agent`):

| flag | 預設 | 說明 |
|---|---|---|
| `--sails` | `/shared/Sails` | Sails 路徑 |
| `--lvm-command-prefix` | `nsenter --target 1 --mount --uts --ipc --net --pid --` | LVM 命令的前綴;預設進 host namespace 執行 host 的 lvm2 |
| `--attester-namespace` | `POD_NAMESPACE`,再來是 `topolvm-system` | attester ServiceAccount 的 namespace |
| `--attester-service-account` | `topolvm-attester` | 唯一接受的呼叫者 |
| `--service-account` | `POD_SERVICE_ACCOUNT`,再來是 `topolvm-attester-agent` | 簽 report attestation 的 ServiceAccount(agent 自己的) |
| `--pod-name` / `--pod-uid` / `--node-name` | `POD_NAME` / `POD_UID` / `NODE_NAME` | report 綁定的 Pod 和節點;缺任何一個 agent 不啟動 |
| `--check-timeout` | `2m` | 一次檢查(pvs + Sails)的上限 |

## 開發

程式碼在 TopoLVM 的 module 裡,`make test` / `make lint` 一起跑:

```sh
make test       # 包含 internal/attester;attestation 的完整流程(TokenRequest → TokenReview)跑在 envtest 的真實 kube-apiserver 上
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./internal/attester/... ./cmd/topolvm-attester/... ./cmd/topolvm-attester-agent/...
```

目錄:

```
cmd/topolvm-attester/          attester(API)
cmd/topolvm-attester-agent/    節點 agent
cmd/hypertopolvm/              依 argv[0] 分派到上面兩個
internal/attester/config/      audience、label、預設值
internal/attester/kubeauth/    TokenReview、TokenRequest、token 快取
internal/attester/attest/      result 格式、audience = sha256(result)、MW 端驗證邏輯
internal/attester/api/         MW 呼叫的 API(跑在 controller-runtime 的 webhook server 上,只當 HTTPS server 用)
internal/attester/agent/       pvs → backing disks → Sails,以及 agent 的 HTTP API
charts/topolvm/templates/attester/   chart template
```

RBAC 寫在 chart template,**不要**在 attester 的程式碼加 `+kubebuilder:rbac` marker:TopoLVM 的 `make manifests` 會把它們併進 topolvm-controller 的 ClusterRole。
