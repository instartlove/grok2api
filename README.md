# Grok API Gateway

## 与原版差异

本 fork 版本相较于原版增加了以下功能：

0. **基本全部重写了...**
1. **自动获取 x-statsig-id** - 使用 Playwright 自动获取并管理认证头
2. **流模式标签过滤** - 自动移除响应中的 `<xaiArtifact` 等标签
3. **增强统计功能** - 改进的令牌使用统计和监控
4. **Grok4支持** - 反正我能用.jpg

## 环境变量配置

### 必需配置

| 环境变量 | 描述 | 默认值 | 示例 |
|---------|------|--------|------|
| `API_KEY` | API 访问密钥 | `sk-123456` | `sk-your-api-key` |
| `SSO` | Grok SSO 令牌（普通） | - | `token1,token2,token3` |
| `SSO_SUPER` | Grok SSO 令牌（超级） | - | `super_token1,super_token2` |

### 可选配置

| 环境变量 | 描述 | 默认值 | 有效值 | 示例 |
|---------|------|--------|--------|------|
| `IS_CUSTOM_SSO` | 允许动态 SSO 令牌 | `false` | `true/false` | `true` |
| `IS_TEMP_CONVERSATION` | 临时对话模式 | `true` | `true/false` | `false` |
| `SHOW_THINKING` | 显示推理过程 | `false` | `true/false` | `true` |
| `USE_REASONING_FORMAT` | 思维链格式：`false`=`<think>`标签，`true`=分离的`reasoning_content`字段（类似 OpenAI o1）| `false` | `true/false` | `true` |
| `SHOW_SEARCH_RESULTS` | 显示搜索结果 | `true` | `true/false` | `false` |
| `IS_SUPER_GROK` | 启用超级 Grok 功能 | `false` | `true/false` | `true` |
| `MANAGER_SWITCH` | 启用 Web 管理界面 | - | `true/false` | `true` |
| `ADMINPASSWORD` | 管理界面密码 | - | 任意字符串 | `admin123` |
| `PORT` | 服务端口 | `5200` | 数字 | `8080` |
| `PROXY` | 代理服务器 | - | HTTP/SOCKS5 URL | `http://127.0.0.1:1080` |
| `DYNAMIC_PROXY_API` | 动态获取代理的 API | - | URL（返回纯文本或 JSON） | `http://127.0.0.1:8080/proxy` |
| `PROXY_RETRY_LIMIT` | 动态代理获取/验证重试次数 | `20` | 数字 | `30` |
| `PROXY_VALIDATE_URL` | 代理可用性验证地址 | `https://grok.com/` | URL | `https://grok.com/` |
| `PROXY_VALIDATE_TIMEOUT` | 验证请求超时（秒） | `15` | 数字 | `10` |
| `CF_CLEARANCE` | Cloudflare 令牌 | - | CF 令牌字符串 | `cf_clearance_token` |
| `DISABLE_DYNAMIC_HEADERS` | 禁用动态头部获取（禁用 Playwright 自动获取 x-statsig-id） | `false` | `true/false` | `true` |
| `FILTERED_TAGS` | 过滤标签列表 | `xaiartifact,xai:tool_usage_card,grok:render,details,summary` | 逗号分隔 | `tag1,tag2,tag3` |
| `TAG_CONFIG` | 过滤标签配置 | `{"xaiartifact":{"behavior":"preserve_content"},"xai:tool_usage_card":{"behavior":"remove_all"},"grok:render":{"behavior":"remove_all"},"details":{"behavior":"preserve_content"},"summary":{"behavior":"preserve_content"}}` | json | `{"xaiartifact":{"behavior":"preserve_content"},"xai:tool_usage_card":{"behavior":"remove_all"},"grok:render":{"behavior":"remove_all"},"details":{"behavior":"preserve_content"},"summary":{"behavior":"preserve_content"}}` |
| `CONTENT_TYPE_MAPPINGS` | 过滤标签重写配置 | 太长了,看源码 | json | {"text/plain":{"stag":"```","etag":"```"},"text/python":{"stag":"```python\n","etag":"\n```"}} |

### 思维链格式配置说明

`USE_REASONING_FORMAT` 环境变量控制推理过程的输出格式：

**默认模式（`USE_REASONING_FORMAT=false`）**：
- 思考内容包含在 `<think>` 标签中
- 所有内容（思考+答案）都在 `content` 字段
- 客户端需要解析标签来分离思考和答案
- 适合支持自定义标签的客户端

**OpenAI o1 风格（`USE_REASONING_FORMAT=true`）**：
- 思考内容在独立的 `reasoning_content` 字段
- 最终答案在 `content` 字段
- 自动移除 `<think>` 标签
- 更好的客户端兼容性，推荐使用

**注意**：
- 两种格式都需要配合 `SHOW_THINKING=true` 才会输出思考内容
- 当 `SHOW_SEARCH_RESULTS=true` 时，网页搜索结果也会包含在思维链中（`<think>` 标签内或 `reasoning_content` 字段）

### 标签过滤配置

添加了高级标签过滤功能，可在流式响应中自动处理特定的 XML/HTML 标签。

注意配置错误会直接破坏输出!!!

#### FILTERED_TAGS

**描述**：标签过滤列表, 当遇到不在列表中的标签时会立即放弃后续重写

**格式**：逗号分隔的标签名称，小写

**默认值**：`xaiartifact,xai:tool_usage_card,grok:render,details,summary`

**示例**：
```bash
FILTERED_TAGS=xaiartifact,grok:render,grok:thinking
```

#### TAG_CONFIG

**描述**：高级标签行为配置，支持为不同标签设置不同的处理策略。

**格式**：JSON 对象，键为标签名称（小写），值为配置对象

**配置选项**：
- `behavior`: 标签行为
  - `"preserve_content"`: 保留内容，添加格式化标记
  - `"remove_all"`: 完全移除标签和内容

**默认值**：基于 FILTERED_TAGS 自动生成

**示例**：
```json
{
  "xaiartifact": {"behavior": "preserve_content"},
  "xai:tool_usage_card": {"behavior": "remove_all"},
  "grok:render": {"behavior": "remove_all"},
  "details": {"behavior": "preserve_content"},
  "summary": {"behavior": "preserve_content"}
}
```

**在 docker-compose.yml 中配置**：
```yaml
environment:
  TAG_CONFIG: '{"xaiartifact":{"behavior":"preserve_content"},"xai:tool_usage_card":{"behavior":"remove_all"},"grok:render":{"behavior":"remove_all"},"details":{"behavior":"preserve_content"},"summary":{"behavior":"preserve_content"}}'
```

#### CONTENT_TYPE_MAPPINGS

**描述**：内容类型映射配置，定义不同 contentType 的格式化标记。

**格式**：JSON 对象，键为 MIME 类型，值为包含 stag（开始标记）和 etag（结束标记）的对象

**默认映射**：
```json
{
  "text/plain": {"stag": "```", "etag": "```"},
  "text/markdown": {"stag": "", "etag": ""},
  "application/json": {"stag": "```json\n", "etag": "\n```"}
}
```

**示例配置**：
```yaml
environment:
  CONTENT_TYPE_MAPPINGS: '{"text/plain":{"stag":"```","etag":"```"},"text/python":{"stag":"```python\n","etag":"\n```"}}'
```

**工作原理**：
1. 当遇到 `preserve_content` 行为的标签时，会查找标签的 `contentType` 属性
2. 根据 `contentType` 在映射表中查找对应的格式化标记
3. 用 `stag` + 内容 + `etag` 替换原始标签和对应的封闭标签


## 快速开始

### Docker Compose 示例

```yaml
services:
  grok2api:
    image: verofess/grok2api
    container_name: grok2api
    ports:
      - "5200:5200"
    environment:
      - API_KEY=sk-your-api-key
      - SSO=your-sso-token
      - IS_TEMP_CONVERSATION=true
      - SHOW_THINKING=false
      # 动态代理配置（可选）
      - DYNAMIC_PROXY_API=http://your-proxy-api/next
      - PROXY_RETRY_LIMIT=20
      - PROXY_VALIDATE_URL=https://grok.com/
      - PROXY_VALIDATE_TIMEOUT=15
    restart: unless-stopped
```

### Python 直接运行

适合本地开发与快速测试。

1) 准备环境（Python 3.9+）
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate
pip install -r requirements.txt
# 可选（启用动态头时需要）：安装 Playwright 浏览器
# python -m playwright install
```

2) 准备配置
```bash
cp .env.example .env
# 编辑 .env，至少填写：
# API_KEY=sk-your-api-key       # 访问本服务用的密钥（客户端需以 Bearer 传入）
# SSO=your-sso-token            # Grok 的 SSO Token，多个用英文逗号分隔
# ADMINPASSWORD=your-password   # 管理面板密码（启用面板时必填）

# 为了最快启动，建议关闭动态头：
echo "DISABLE_DYNAMIC_HEADERS=true" >> .env

# 注意：程序会把 token_status.json 写到 /data 下，首次本地运行请创建该目录：
sudo mkdir -p /data  # Windows 可忽略
```

3) 启动
```bash
python app.py
# 默认端口 5201（可在 .env 里设置 PORT 覆盖）
```

4) 调用示例
```bash
curl -s http://127.0.0.1:5201/v1/chat/completions \
  -H "Authorization: Bearer sk-your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "grok-3",
    "messages": [{"role":"user","content":"Hello"}],
    "stream": false
  }'
```

5) 管理面板（可选）
- .env 增加：
```
MANAGER_SWITCH=true
ADMINPASSWORD=your-password
```
- 浏览器访问：http://127.0.0.1:5201/manager（先登录 /manager/login）

提示
- 已实现"积分额度"规则：初始 80 积分；-expert/-imageGen 每次 4 分，其他 1 分；每天（美国时间）刷新。
- 每次模型请求后会调用官方 rate-limits，同步 remainingTokens 并据此计算各模式可用次数（向下取整）。

## 致谢

感谢 [@VeroFess](https://github.com/VeroFess/grok2api) 提供的原始项目，本项目基于其实现并进行了扩展和改进。

原项目地址：[https://github.com/VeroFess/grok2api](https://github.com/VeroFess/grok2api)
