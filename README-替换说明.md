# global-tcp-scan：官方 CloudflareSpeedTest 版本

## 替换文件
1. 用 `scanner.py` 覆盖仓库根目录的 `scanner.py`。
2. 用 `.github/workflows/tcp-scan.yml` 覆盖仓库对应工作流。
3. 提交并推送到 GitHub。
4. 在 Settings → Actions → General → Workflow permissions 中启用 Read and write permissions。

## 测速与发布
- 官方工具：XIU2/CloudflareSpeedTest 最新 Linux x86-64 release。
- 默认 TCPing；每个 IP 测 4 次，不启用下载测速。
- JP/HK/KR/CN/US/SG/DE 七地区，来源 API 返回的全部有效 IPv4:port 均参与测速。
- 按原始端口分组调用 CFST，避免不同端口候选被错误地统一测 443。
- 每 30 分钟由 GitHub Actions 调度。
- 某地区来源失败或没有成功测速结果时，该地区现存 TXT/JSON 不会被覆盖。

## TXT 端点
每个地区同时发布四种结果，按延迟升序：
- `public/kr.txt`：默认前 20 名，可通过工作流环境变量 `TOP_N` 自定义。
- `public/kr-.txt`：前 30 名。
- `public/kr-top100.txt`：前 100 名。
- `public/kr-all.txt`：全部成功测速的候选节点。

其他六个地区同理，例如 `hk-top100.txt`、`jp-all.txt`。如果成功节点少于指定数量，则输出所有成功节点。`-all` 表示全部成功测速节点，不包括连接失败的候选。

`public/data/<region>.json` 保存本轮全部成功节点的延迟详情，`public/index.html` 提供链接。

## 注意
CFST 的 `-tp` 对一次运行中的所有 IP 使用同一个端口，所以脚本按源数据中的端口分组调用。当前适配器接受 IPv4:port，不会把 IPv6 候选默默按 IPv4 处理。GitHub Actions 的网络路径与用户本地不同，延迟数值不保证和本地 CFST 一致。
