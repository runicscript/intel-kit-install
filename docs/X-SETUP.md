# X 取数配置

默认关闭 X。用户要跟踪 X 时，先问账号或关键词，再检查宿主是否提供可用的 X 读取工具。

- **宿主已有 X 工具**。将 `sources.x.enabled` 设为 `true`，`sources.x.via` 设为 `host_agent`。照已安装版的 `RUN.md` 使用宿主工具，先选一个账号试拉，把原始响应交给采集器处理。
- **使用 X 官方 API**。先检查已安装版的 `RUN.md` 是否明确说明 `intel run` 会执行 X 官方 Recent Search，且 schema 支持 `sources.x.max_results`。旧版缺少该能力时，展示原因并继续配置其他信源。支持后，再请用户在 X Developer Console 开通访问并设置支出上限，通过宿主安全变量或安装目录的本机 `.env` 配置 `X_BEARER_TOKEN`。聊天、任务提示词和 `answers.json` 只写环境变量名。

官方 API 配置使用 `sources.x.enabled: true`、`sources.x.via: official_api`，以及用户确认的 `budget.monthly_usd_cap`。第一次仅填一个 `sources.x.accounts` 账号或一个 `sources.x.keywords` 关键词，账号列表为空时写 `accounts: []`，并设 `sources.x.max_results: 10`。应用后先运行 `intel validate`，经用户确认接受接口费用后再运行 `intel run` 试拉。项目中的月预算是配置值，API 实际支出受 X 账户设置约束。

按实际结果说明已找到的公开帖子、链接及是否生成证据卡。无结果时尝试用户确认的活跃来源。遇到凭据、余额、权限或限流问题，报告后停止当轮的 X 请求。验收通过且用户确认频率后，再登记定时任务。

[官方 Recent Search 文档](https://docs.x.com/x-api/posts/search-recent-posts)
