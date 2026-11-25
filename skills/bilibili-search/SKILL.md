---
name: bilibili-search
description: 用户明确要求时，使用 OpenCLI 按关键词检索 B 站公开视频。仅装播客时跳过。
---

# B 站视频检索

仅处理用户选定范围内的公开视频。先确认搜索关键词和结果数量。默认只在当前会话返回结果。

1. 查看 [OpenCLI](https://github.com/jackwener/opencli) 的安装和浏览器连接说明。已有 OpenCLI 时先运行 `opencli list`，确认存在 `bilibili search`。需要浏览器连接或授权时按宿主提示完成。
2. 首次验证使用用户确认的公开关键词，按当前版本的命令帮助限制结果数量。

```bash
opencli bilibili search --help
opencli bilibili search "AI 教程" --limit 1 --format json
```

检查退出码、返回标题以及可核对的 B 站链接或 BV 号。浏览器连接失败、授权未完成或结果为空时，分别说明。该接入使用 OpenCLI，无需配置怪可 Token。
