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

### 使用 Docker Hub 镜像

现在可以直接从 Docker Hub 拉取预构建的镜像：

```bash
# 拉取镜像
docker pull verofess/grok2api

# 运行容器
docker run -d \
  --name grok2api \
  -p 5200:5200 \
  -e API_KEY=sk-your-api-key \
  -e SSO=your-sso-token \
  verofess/grok2api

# 或者使用 docker-compose
docker-compose up -d
```

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
