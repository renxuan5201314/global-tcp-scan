# GitHub-only 全球 IP:端口 TCP 延迟测速与 TXT 发布

本项目只用 GitHub Actions 运行测速并发布七个地区的 TXT；不调用、不修改 Cloudflare Worker，也不需要 Cloudflare Token/KV。

## 重要边界

- 现有 Cloudflare 域名、主页、KV、`/jp.txt` 等接口完全不动，因此不会覆盖或丢失旧数据。
- GitHub 生成的是**另一套新地址**（GitHub Pages），不会自动更新 `https://wyx.renxuan520.dpdns.org/jp.txt`。如果要求原域名内容也跟着 GitHub 测速更新，就必须另做数据同步/路由调整；这与“只用 GitHub、Cloudflare 完全不改”无法同时实现。
- GitHub Pages 只负责发布生成文件，不会接管现有自定义域名。不要在仓库里设置 `CNAME` 指向现有域名，也不要修改 DNS。
- 测速来自 GitHub Actions Runner 的网络出口；TCP 成功只代表端口接受 TCP 连接，不证明代理协议可用，也不代表用户本地延迟。

## 上传到 GitHub

1. 下载 ZIP 并解压。
2. 在 GitHub 新建仓库，建议 Private。
3. 使用 Add file → Upload files 上传解压目录中的**所有内容**，包括隐藏的 `.github` 目录及 `.github/workflows/tcp-scan.yml`。
4. Commit changes。

## 开启 GitHub Pages（首次只需一次）

1. 仓库 Settings → Pages。
2. Build and deployment 的 Source 选择 **GitHub Actions**。
3. 仓库 Settings → Actions → General → Workflow permissions，确认工作流可写入仓库内容（`contents: write` 已在 YAML 声明；组织策略若禁止仍需管理员允许）。
4. 打开 Actions → `Global TCP scan and publish TXT` → Run workflow，手动运行一次。
5. 等待工作流完成；仓库 Settings → Pages 会显示 `https://你的用户名.github.io/仓库名/`。

## TXT 地址

将用户名和仓库名替换为你的实际值：

- `https://你的用户名.github.io/仓库名/jp.txt`
- `https://你的用户名.github.io/仓库名/hk.txt`
- `https://你的用户名.github.io/仓库名/kr.txt`
- `https://你的用户名.github.io/仓库名/cn.txt`
- `https://你的用户名.github.io/仓库名/us.txt`
- `https://你的用户名.github.io/仓库名/sg.txt`
- `https://你的用户名.github.io/仓库名/de.txt`

首页：`https://你的用户名.github.io/仓库名/`。格式示例：`1.2.3.4:443#JP-01-18ms`。只有 TCP 测试成功的节点会写入 TXT；最多保留 500 条成功结果，按测得延迟排序。失败复测不会删掉之前的成功记录。

## 运行规则

- 每 5 分钟调度一次，每次轮换一个地区：JP、HK、KR、CN、US、SG、DE。GitHub Actions 的计划任务并非精确准点，繁忙时可能延迟。
- 每次最多测 25 个候选，连接超时 5 秒，最多 5 个并发。
- 每次结果提交到 `public/` 并发布 Pages。文件夹 `public/data/` 存每地区 JSON 详细结果。
- 数据源默认 `https://proxy.seeck.cn/api/nodes?region=XX`。若 API 格式变更，日志会报错，需要检查 `scanner.py` 的解析逻辑。

## 常见问题

- Actions 失败：打开该次 run 查看日志；常见原因是源 API 不可用或 JSON 格式变化。
- Pages 404：确认 Settings → Pages → Source 为 GitHub Actions，并等待部署完成。
- 原来的 `wyx.renxuan520.dpdns.org`：本方案完全不改它；原站仍由现有 Cloudflare Worker 提供，内容不自动混入 GitHub 新测速结果。
