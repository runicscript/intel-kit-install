# SETUP.md — 给 AI 助手的安装剧本

面向：Grok Bot、WorkBuddy。Claude Code / Cursor：**未实测**。

按章节顺序执行。不要跳步。

---

## 0) 你是谁 / 规则

你是安装助手，不是社交机器人。

- 严格按本文件步骤顺序做；不要跳过任何需要用户确认的步骤。
- 永远不要把激活码或任何密钥粘贴回聊天。
- 不要在任何平台点赞、关注或发帖。
- 任何花钱的操作（例如开通 X 付费接口）必须先得到用户明确同意。

---

## 1) 环境检查

确认：

1. 系统有 `python3`，版本 **≥ 3.9**（可运行 `python3 -V`）。
2. 你能执行 shell 命令。
3. 文件落在哪里：
   - **Grok Bot**：在它自己的 Linux 环境里。
   - **WorkBuddy**：优先用**本地任务**并申请完全访问权限；云端任务读不到用户本机文件。WorkBuddy 云沙箱能否跑 python：**未实测**。

默认安装目录：`~/.intel-kit`（可用环境变量 `INTEL_KIT_HOME` 覆盖）。

---

## 2) 安装

1. 向用户索取**激活码**（说明：购买后收到的激活码，形如 `IK-…`）。不要回显完整密钥。
2. 从本公开仓库下载安装脚本并运行。激活码用环境变量传入，不要写进文件，也不要贴回聊天：

```bash
curl -fsSL https://raw.githubusercontent.com/runicscript/intel-kit-install/main/bootstrap.py -o bootstrap.py
INTEL_KIT_LICENSE_KEY='用户的激活码' python3 bootstrap.py
```

3. 按退出码处理（向用户用中文说明）：

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 2 | 激活码无效或已吊销 |
| 3 | 设备数量已达上限 |
| 4 | 今日下载次数已达上限 |
| 5 | 网络错误 |
| 6 | 软件包校验失败（未安装） |
| 7 | 依赖安装失败（需要 python3 的 venv 和 pip，可联网安装依赖；未切换 current） |

成功后脚本会提示：安装完成，进入第 3 步采访。

可用 `python3 bootstrap.py --check` 对比已安装版本与可用版本。

---

## 3) 采访

一次只问 **1～2** 个问题。每个问题都有默认值；用户回答「默认」即采用默认。

### 问题 1 — 想追哪方面

先运行：

```bash
~/.intel-kit/bin/intel presets
```

把结果列给用户。预设只有：`ai-builder`（默认）、`design-ui`、`blank`。

- 默认：`ai-builder`

### 问题 2 — 你是做什么的、拿来干嘛

- 默认：`AI 产品团队负责人，用来做产品和技术决定`

### 问题 3 — 信息从哪来

预设会自带来源；用户可粘贴链接/账号补充。

- **X（Twitter）默认关闭。**
- 若用户要开 X：先说明费用——
  - Grok Bot：可用自带读取工具；
  - 其他平台：需要 X 官方付费接口（按读取条数收费，账号越多越贵），必须用户自己充值并明确同意后才开。

### 问题 4 — 什么算有用

展示该预设的维度；让用户去掉不需要的；可增加 1～2 条 `must_keep` / `must_drop`；可选贴示例链接。

### 问题 5 — 结果放哪

- 文件夹（默认） / Notion / GitHub / 只要摘要

### 问题 6 — 频率和时间、每次最多几条

- 默认：每天 `08:00`、最多 `12` 条

### 问题 7 — 摘要语言

- 默认：中文

### 问题 8 — 每月预算、用哪个模型

- 默认：预算 `0` = 只用免费源 + 你（agent）自己的模型额度（`host_agent`）

### 问题 9 — 知识库

要不要把每天的卡片整理成一本按主题分页的知识库？

- 默认：要；放在 `~/.intel-kit/wiki`，Obsidian 能直接打开
- 新页默认先写到 `review.md` 提议；用户说「自动建页」才改为自动创建

**9a** 分几个库、每个库收什么、不收什么  
- 默认：一个库，按问题 1 的主题

**9b** 先放几个你最关心的主题当起始页  
- 默认：不填，让它自己提议

**9c** 有没有不想写进知识库的内容  
- 默认：融资金额、估值、定价、财报、单纯的新品发布

**9d** 每次最多让模型干多少活  
- 默认：每次最多 20 次模型调用；超出的留到下次

---

## 4) 复述与写入

1. 用短列表复述全部答案（含知识库：是否开启、路径、库、起始页、禁写、建页方式、预算），等待用户说「对」或「可以」。
2. 写入 `answers.json`（放在用户指定的工作目录或 `~/.intel-kit/` 旁，路径告知用户）。其中 `wiki` 段字段：`enabled`、`path`、`libraries`（每项 `id`/`name`/`covers`/`excludes`）、`seed_pages`、`never_write`、`new_pages`（`propose`|`auto`）、`budget.max_model_calls_per_run`。
3. 运行：

```bash
~/.intel-kit/bin/intel init --preset <id> --answers answers.json
~/.intel-kit/bin/intel validate
```

4. 若有错误，与用户一起修到通过为止。
5. 若 `wiki.enabled`：再运行 `~/.intel-kit/bin/intel wiki init`。

---

## 5) 离线试跑

```bash
~/.intel-kit/bin/intel run --dry-run --fixtures ~/.intel-kit/app/current/examples/fixtures
```

确认生成了卡片/摘要类文件后再继续。

---

## 6) 真跑一次

1. 按 `~/.intel-kit/app/current/RUN.md` 执行（通常覆盖约 24 小时窗口）。
2. 若 `wiki.enabled`：再跑 `~/.intel-kit/bin/intel wiki compile`。若退出码 **10**：按 RUN.md 同样方式处理——读 `wiki-requests.jsonl`、写回 `wiki-responses.jsonl`，再 `intel wiki compile --resume <run_id>`。完成后给用户看 **一页** 有改动的知识库页面。
3. 给用户看 **3 张样例卡片**和当天摘要。
4. 问：「这样的可以吗？哪条不该收？」
5. 把反馈写进 `intel.yaml` 的 `must_keep` / `must_drop`，再 `intel validate`。

---

## 7) 定时

**只有用户明确说可以 / OK 之后**才安排定时。

1. 运行 `~/.intel-kit/bin/intel schedule`，拿到提示词/说明（routine：`run` → `digest` → `wiki compile`）。
2. **Grok Bot**：用该提示词创建 routine。
3. **WorkBuddy**：创建**本地**定时任务（完全访问权限），内容为该提示词；告知用户触发时间。
4. 用户未点头前，绝不创建定时。

---

## 8) 以后

- 每月可运行：`~/.intel-kit/bin/intel update`（或 `--check` 只检查）。
- 改答案：直接改配置，或让助手按第 3 步重新采访。
- 支持联系：【待定：支持邮箱或工单地址】

---

许可协议见仓库根目录 `EULA.md`。API 契约见 `docs/API.md`。
