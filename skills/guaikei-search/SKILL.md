---
name: guaikei-search
description: 用户明确要求时，通过怪可检索抖音公开视频或小红书公开笔记。需要用户自行开通 Token 和批准付费请求。
---

# 怪可社媒检索

适用于用户点名的平台。询问搜索关键词、结果数量、时间范围，并说明按量计费。待用户确认后，再运行一条查询。只有播客需求时跳过本 Skill。

## 接入

1. 请用户打开 [怪可官网](https://www.guaikei.com/) 自行登录，核对当前价格和账户余额，再按需开通私有 Token。充值由用户自行完成。怪可是第三方数据服务。
2. 检查 Node.js 版本至少为 16.14。按用户选择接入一个上游 Skill：抖音使用 [guaikei/dy-feedback](https://github.com/guaikei/dy-feedback)，小红书使用 [guaikei/xhs-feedback](https://github.com/guaikei/xhs-feedback)。使用经过核对的上游版本，按其说明配置到用户选择的工作区。先阅读上游代码和配置说明，遇到宿主授权提示则等待用户确认。
3. 请用户在宿主的安全变量配置界面设置 `GUAIKEI_API_TOKEN`。执行前只检查该变量是否存在。Token 仅用于怪可的 API 请求，避免写入提示词、日志、命令行参数和代码仓库。

## 关键词搜索

进入相应上游 Skill 的根目录。首次运行用用户确认的公开主题，限制为 1 条结果。

```bash
node src/douyin/search-cli.js --keyword "AI 教程" --limit 1
node src/xiaohongshu/search-cli.js --keyword "AI 教程" --limit 1
```

按用户选择只执行对应平台的一条命令。搜索关键词会发给怪可。首次验收检查退出码、JSON 状态与公开来源链接；空结果单独说明。出现 `AUTH_REQUIRED` 时停止并引导检查密钥。余额不足、限额或网络失败时报告原因并停止，避免重复付费请求。默认按次检索；需要定时监测时，另行确认关键词、频率和费用预算。

只输出用户指定范围内的公开内容及其来源链接。默认采用本次会话输出，用户明确要求时再摘要归档。
