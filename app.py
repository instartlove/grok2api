from __future__ import annotations

import os
import json
import uuid
import time
import base64
import sys
import inspect
import secrets
import asyncio
import contextvars
import functools
import re
import threading
from dataclasses import dataclass, field
import math
from typing import List, Optional, Any, Dict, Union, Tuple, Iterator
from pathlib import Path
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from datetime import datetime, timedelta
import pytz

import requests
from flask import (
    Flask,
    request,
    Response,
    jsonify,
    stream_with_context,
    render_template,
    redirect,
    session,
)
from curl_cffi import requests as curl_requests
from dotenv import load_dotenv

# 提前加载本地 .env 环境变量，便于 ConfigurationManager 从 os.environ 读取。
load_dotenv()
from werkzeug.middleware.proxy_fix import ProxyFix
from playwright.async_api import async_playwright, Browser, BrowserContext

############################################################
# 动态代理管理器（Dynamic Proxy Manager）
#
# - 从外部 API 获取代理
# - 访问指定校验 URL（默认 https://grok.com/）验证是否可用
# - 缓存可用代理；验证失败时继续轮换新代理
# - 通过自动轮换出口 IP，尽量绕过 Cloudflare 挑战
############################################################
class DynamicProxyManager:
    """从外部 API 获取并管理动态代理。"""

    def __init__(self, config: "ConfigurationManager"):
        self._config = config
        self._api_url: Optional[str] = config.get("API.DYNAMIC_PROXY_API")
        # 默认重试上限 20（用户需求）
        self._retry_limit: int = int(config.get("API.PROXY_RETRY_LIMIT", 20))
        self._validate_url: str = config.get(
            "API.PROXY_VALIDATE_URL", "https://grok.com/"
        )
        self._validate_timeout: int = int(config.get("API.PROXY_VALIDATE_TIMEOUT", 15))
        self._cached_proxy: Optional[str] = None
        self._lock = threading.Lock()

    def _normalize_proxy(self, candidate: str) -> Optional[str]:
        """规范化代理地址；若无协议前缀则补为 http://。"""
        if not candidate:
            return None
        proxy = candidate.strip()
        if "://" not in proxy:
            proxy = f"http://{proxy}"
        return proxy

    def _fetch_proxy_from_api(self) -> Optional[str]:
        """从动态代理 API 拉取代理。

        支持纯文本或 JSON 返回；若为 JSON，则按常见键名提取：proxy、url、http、https、server。
        """
        if not self._api_url:
            return None
        try:
            resp = requests.get(self._api_url, timeout=10)
            if resp.status_code != 200:
                print(
                    f"Dynamic proxy API returned status {resp.status_code}",
                    "DynamicProxy",
                )
                return None

            text = (resp.text or "").strip()
            if not text:
                return None

            # 优先尝试按 JSON 解析
            proxy_candidate: Optional[str] = None
            if text.startswith("{"):
                try:
                    data = resp.json()
                    for key in ("proxy", "url", "http", "https", "server"):
                        val = data.get(key)
                        if isinstance(val, str) and val.strip():
                            proxy_candidate = val.strip()
                            break
                except Exception:
                    # 解析失败则回退到纯文本
                    pass

            if not proxy_candidate:
                proxy_candidate = text

            proxy = self._normalize_proxy(proxy_candidate)
            return proxy
        except Exception as e:
            print(f"Failed to fetch proxy from API: {e}", "DynamicProxy")
            return None

    def _is_cf_challenge(self, status_code: int, headers: Dict[str, str], body: str) -> bool:
        try:
            if headers.get("cf-mitigated", "").lower() == "challenge":
                return True
            if status_code in (403, 503):
                lower = (body or "").lower()
                if "just a moment" in lower or "__cf_chl_" in lower:
                    return True
        except Exception:
            pass
        return False

    def _validate_proxy(self, proxy_url: str) -> bool:
        """访问验证 URL 并判断是否触发 CF 挑战，用于验证代理是否可用。"""
        try:
            proxy_cfg = UtilityFunctions.get_proxy_configuration(proxy_url)

            headers = {
                "User-Agent": BASE_HEADERS.get("User-Agent", ""),
                "Accept": "*/*",
                "Accept-Language": BASE_HEADERS.get("Accept-Language", "zh-CN,zh;q=0.9"),
                "Referer": "https://grok.com/",
            }

            # 若用户提供了 cf_clearance，则附加到 Cookie 提高通过率
            cf_clearance = self._config.get("SERVER.CF_CLEARANCE", "")
            cookie_header = cf_clearance if cf_clearance else None

            resp = curl_requests.get(
                self._validate_url,
                headers=(headers if not cookie_header else {**headers, "Cookie": cookie_header}),
                impersonate="chrome133a",
                timeout=self._validate_timeout,
                **proxy_cfg,
            )

            body_preview = ""
            try:
                body_preview = resp.text[:600]
            except Exception:
                pass

            if self._is_cf_challenge(resp.status_code, resp.headers, body_preview):
                print("Proxy validation failed due to CF challenge", "DynamicProxy")
                return False

            # 2xx/3xx 认为有效
            if 200 <= resp.status_code < 400:
                return True

            # 其他状态码视为无效
            print(f"Proxy validation received status {resp.status_code}", "DynamicProxy")
            return False
        except Exception as e:
            print(f"Proxy validation error: {e}", "DynamicProxy")
            return False

    def get_working_proxy(self) -> Optional[str]:
        """获取可用代理：优先用缓存；否则从 API 轮换直至达到重试上限。"""
        if not self._api_url:
            return None

        with self._lock:
            # 快速复验缓存代理
            if self._cached_proxy and self._validate_proxy(self._cached_proxy):
                return self._cached_proxy

            last_err = None
            for attempt in range(1, int(self._retry_limit) + 1):
                candidate = self._fetch_proxy_from_api()
                if not candidate:
                    last_err = f"No proxy returned by API (attempt {attempt})"
                    continue
                if self._validate_proxy(candidate):
                    self._cached_proxy = candidate
                    print(f"Using dynamic proxy: {candidate}", "DynamicProxy")
                    return candidate
                else:
                    last_err = f"Proxy invalid: {candidate}"

            print(
                f"Exhausted dynamic proxy attempts ({self._retry_limit}). Last error: {last_err}",
                "DynamicProxy",
            )
            return None


    def invalidate_current(self, proxy_url: Optional[str]) -> None:
        with self._lock:
            if proxy_url and self._cached_proxy == proxy_url:
                self._cached_proxy = None


_global_proxy_manager: Optional[DynamicProxyManager] = None


def get_proxy_manager(config: "ConfigurationManager") -> DynamicProxyManager:
    global _global_proxy_manager
    if _global_proxy_manager is None:
        _global_proxy_manager = DynamicProxyManager(config)
    return _global_proxy_manager


class PlaywrightStatsigManager:
    """
    使用 Playwright 抓取真实的 x-statsig-id（改造自 Grok3API 的 driver.py）：
    1) 在页面内覆盖 window.fetch 拦截对 grok.com 的请求；
    2) 触发一次真实访问以生成真实请求头；
    3) 抓取并缓存 x-statsig-id 以复用。
    """

    def __init__(self, proxy_url: Optional[str] = None):
        self._cached_statsig_id: Optional[str] = None
        self._cache_timestamp: Optional[int] = None
        self._cache_duration = 300
        self._context: Optional[BrowserContext] = None
        self._playwright = None
        self._lock = threading.Lock()
        self._base_url = "https://grok.com/"
        self._proxy_url = proxy_url

    def _run_async(self, coro):
        """线程安全地运行异步函数。"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(asyncio.run, coro)
                    return future.result(timeout=300)
            else:
                return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    async def _ensure_browser(self):
        """确保浏览器上下文可用并初始化。"""
        if not self._context:
            self._playwright = await async_playwright().start()

            context_options = {
                "viewport": {"width": 1920, "height": 1080},
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            }

            if self._proxy_url:
                context_options["proxy"] = {"server": self._proxy_url}

            # 按既定方案使用 Google Chrome 渠道
            self._context = await self._playwright.chromium.launch_persistent_context(
                user_data_dir="./data/chrome",
                headless=True,
                no_viewport=True,
                channel="chrome",
                args=[
                    "--no-first-run",
                    "--force-color-profile=srgb",
                    "--metrics-recording-only",
                    "--password-store=basic",
                    "--no-default-browser-check",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-web-security",
                    "--disable-features=VizDisplayCompositor",
                    "--user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                ],
                **context_options,
            )

    async def check_real_ip(self) -> str:
        """通过 Playwright 检测当前出口真实 IP。"""
        try:
            await self._ensure_browser()
            page = await self._context.new_page()  # type: ignore

            try:
                print("Checking real IP address via ipify API")
                await page.goto("https://api.ipify.org?format=json", timeout=30000)

                content = await page.content()

                ip_info = await page.evaluate(
                    """
                    () => {
                        try {
                            const bodyText = document.body.textContent || document.body.innerText;
                            return JSON.parse(bodyText);
                        } catch (e) {
                            return null;
                        }
                    }
                """
                )

                if ip_info and ip_info.get("ip"):
                    ip_address = ip_info["ip"]
                    print(f"Playwright real IP address: {ip_address}")
                    return ip_address
                else:
                    print("Failed to parse IP from ipify response")
                    return "unknown"

            except Exception as e:
                print(f"Error checking IP address: {e}")
                return "error"
            finally:
                await page.close()

        except Exception as e:
            print(f"Failed to check real IP address: {e}")
            return "failed"

    async def _cleanup(self):
        """清理浏览器资源。"""
        if self._context:
            await self._context.close()
            self._context = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    def cleanup(self):
        """同步封装的清理函数。"""
        if self._context:
            self._run_async(self._cleanup())

    async def _patch_fetch_for_statsig(self, page):
        """在页面内覆盖 window.fetch 以拦截 x-statsig-id 请求头。"""
        result = await page.evaluate(
            """
            (() => {
                if (window.__fetchPatched) {
                    return "fetch already patched";
                }

                window.__fetchPatched = false;
                const originalFetch = window.fetch;
                window.__xStatsigId = null;

                window.fetch = async function(...args) {
                    console.log("Intercepted fetch call with args:", args);

                    const response = await originalFetch.apply(this, args);

                    try {
                        const req = args[0];
                        const opts = args[1] || {};
                        const url = typeof req === 'string' ? req : req.url;
                        const headers = opts.headers || {};

                        const targetUrl = "https://grok.com/rest/app-chat/conversations/new";

                        if (url === targetUrl) {
                            let id = null;
                            if (headers["x-statsig-id"]) {
                                id = headers["x-statsig-id"];
                            } else if (typeof opts.headers?.get === "function") {
                                id = opts.headers.get("x-statsig-id");
                            }

                            if (id) {
                                window.__xStatsigId = id;
                                console.log("Captured x-statsig-id:", id);
                            } else {
                                console.warn("x-statsig-id not found in headers");
                            }
                        } else {
                            console.log("Skipped fetch, URL doesn't match target:", url);
                        }
                    } catch (e) {
                        console.warn("Error capturing x-statsig-id:", e);
                    }

                    return response;
                };

                window.__fetchPatched = true;
                return "fetch successfully patched";
            })()
        """
        )
        print(f"Fetch patching result: {result}")

    async def _initiate_answer(self, page):
        """触发一次对 grok.com 的真实请求以捕获 x-statsig-id。"""
        try:

            await page.wait_for_selector("div.relative.z-10 textarea", timeout=30000)

            import random
            import string

            random_char = random.choice(string.ascii_lowercase)

            await page.fill("div.relative.z-10 textarea", random_char)
            await page.press("div.relative.z-10 textarea", "Enter")

            print(f"Triggered request with character: {random_char}")

        except Exception as e:
            print(f"Error triggering answer: {e}")
            title = await page.title()
            url = page.url
            print(f"Page title: {title}, URL: {url}")

            raise

    async def _capture_statsig_id_async(
        self, restart_session: bool = False
    ) -> Optional[str]:
        """通过与 grok.com 的真实交互获取 x-statsig-id。"""
        try:
            await self._ensure_browser()
            page = await self._context.new_page()  # type: ignore

            try:

                print("Navigating to grok.com")
                await page.goto(
                    self._base_url, wait_until="domcontentloaded", timeout=30000
                )

                await self._patch_fetch_for_statsig(page)

                captcha_visible = await page.evaluate(
                    """
                    (() => {
                        const elements = document.querySelectorAll("p");
                        for (const el of elements) {
                            if (el.textContent.includes("Making sure you're human")) {
                                const style = window.getComputedStyle(el);
                                if (style.visibility !== 'hidden' && style.display !== 'none') {
                                    return true;
                                }
                            }
                        }
                        return false;
                    })()
                """
                )

                if captcha_visible:
                    print("Captcha detected, cannot capture x-statsig-id")
                    return None

                await self._initiate_answer(page)

                try:
                    await page.locator("div.message-bubble p[dir='auto']").or_(
                        page.locator("div.w-full.max-w-\\[48rem\\]")
                    ).or_(
                        page.locator("p", has_text="Making sure you're human")
                    ).wait_for(
                        timeout=20000
                    )
                except:
                    print("No response elements found within timeout")

                error_elements = await page.query_selector_all(
                    "div.w-full.max-w-\\[48rem\\]"
                )
                if error_elements:
                    print("Authentication error detected")
                    return None

                captcha_elements = await page.query_selector_all(
                    "p:has-text('Making sure you\\'re human')"
                )
                if captcha_elements:
                    print("Captcha appeared during request")
                    return None

                statsig_id = await page.evaluate("window.__xStatsigId")

                if statsig_id:
                    print(f"Successfully captured x-statsig-id: {statsig_id[:30]}...")
                    return statsig_id
                else:
                    print("No x-statsig-id was captured")
                    return None

            finally:
                await page.close()

        except Exception as e:
            print(f"Error capturing x-statsig-id: {e}")
            return None

    def capture_statsig_id(self, restart_session: bool = False) -> Optional[str]:
        """抓取 x-statsig-id（同步封装）。"""
        with self._lock:
            return self._run_async(self._capture_statsig_id_async(restart_session))

    def check_real_ip_sync(self) -> str:
        """检测真实 IP（同步封装）。"""
        with self._lock:
            return self._run_async(self.check_real_ip())

    def generate_xai_request_id(self) -> str:
        """生成 x-xai-request-id（UUID）。"""
        return str(uuid.uuid4())

    def get_dynamic_headers(
        self, method: str = "POST", pathname: str = "/rest/app-chat/conversations/new"
    ) -> Dict[str, str]:
        """获取动态请求头，包含抓取到的 x-statsig-id 与 x-xai-request-id。"""
        headers = {}

        current_time = int(time.time())
        if (
            self._cached_statsig_id
            and self._cache_timestamp
            and (current_time - self._cache_timestamp) < self._cache_duration
        ):
            print("Using cached x-statsig-id")
            headers["x-statsig-id"] = self._cached_statsig_id
        else:

            print("Capturing fresh x-statsig-id")
            statsig_id = self.capture_statsig_id()
            if statsig_id:
                self._cached_statsig_id = statsig_id
                self._cache_timestamp = current_time
                headers["x-statsig-id"] = statsig_id
            else:
                print("Failed to capture x-statsig-id, using fallback")
                headers["x-statsig-id"] = (
                    "ZTpUeXBlRXJyb3I6IENhbm5vdCByZWFkIHByb3BlcnRpZXMgb2YgdW5kZWZpbmVkIChyZWFkaW5nICdjaGlsZE5vZGVzJyk="
                )

        headers["x-xai-request-id"] = self.generate_xai_request_id()

        
        return headers


_global_statsig_manager: Optional[PlaywrightStatsigManager] = None


def initialize_statsig_manager(proxy_url: Optional[str] = None) -> None:
    """按配置初始化全局 StatsigManager 实例。"""
    global _global_statsig_manager
    if _global_statsig_manager is None:
        _global_statsig_manager = PlaywrightStatsigManager(proxy_url=proxy_url)


def get_statsig_manager() -> PlaywrightStatsigManager:
    """获取（或创建）全局 StatsigManager 实例。"""
    global _global_statsig_manager
    if _global_statsig_manager is None:
        _global_statsig_manager = PlaywrightStatsigManager()
    return _global_statsig_manager


class ModelType(Enum):
    """支持的 Grok 模型类型（重定义）。"""

    # 保留
    GROK_3 = "grok-3"
    GROK_3_SEARCH = "grok-3-search"
    GROK_4 = "grok-4"
    GROK_4_FAST = "grok-4-fast"
    GROK_4_IMAGEGEN = "grok-4-imageGen"
    GROK_3_IMAGEGEN = "grok-3-imageGen"

    # 增加 expert 变体
    GROK_4_EXPERT = "grok-4-expert"
    GROK_4_FAST_EXPERT = "grok-4-fast-expert"



class TokenType(Enum):
    """Token 权限级别。"""

    NORMAL = "normal"
    SUPER = "super"


class ResponseState(Enum):
    """响应处理状态。"""

    IDLE = "idle"
    THINKING = "thinking"
    GENERATING_IMAGE = "generating_image"
    COMPLETE = "complete"


MESSAGE_LENGTH_LIMIT = 40000
MAX_FILE_ATTACHMENTS = 4
DEFAULT_REQUEST_TIMEOUT = 120000
MAX_RETRY_ATTEMPTS = 10
BASE_RETRY_DELAY = 1.0


BASE_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "text/plain;charset=UTF-8",
    "Connection": "keep-alive",
    "Origin": "https://grok.com",
    "Priority": "u=1, i",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Sec-Ch-Ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Baggage": "sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c",
}


def build_cookie(auth_token: str, cf_clearance: str = "") -> str:
    """构建完整的 Cookie 字符串，包含语言设置。
    
    Args:
        auth_token: 认证 token (sso-rw=xxx;sso=xxx)
        cf_clearance: Cloudflare clearance token (可选)
    
    Returns:
        完整的 Cookie 字符串
    """
    cookie_parts = [auth_token]
    
    # 添加 Cloudflare clearance
    if cf_clearance:
        cookie_parts.append(cf_clearance)
    
    # 添加语言设置，影响 Grok 的时区和语言响应
    cookie_parts.append("i18nextLng=zh")
    
    return ";".join(cookie_parts)


def get_dynamic_headers(
    method: str = "POST",
    pathname: str = "/rest/app-chat/conversations/new",
    config: Optional["ConfigurationManager"] = None,
) -> Dict[str, str]:
    """
    生成请求头：优先使用动态头（x-statsig-id + x-xai-request-id），否则回退到静态头。

    参数：
      - method: HTTP 方法
      - pathname: 参与生成 statsig 的请求路径
      - config: 配置（用于判断是否禁用动态请求头）

    返回：包含所有必要字段的请求头字典。
    """
    try:
        headers = BASE_HEADERS.copy()

        # 若禁用动态请求头，则直接返回回退头
        if config and config.get("API.DISABLE_DYNAMIC_HEADERS", False):
            
            headers["x-xai-request-id"] = str(uuid.uuid4())
            headers["x-statsig-id"] = (
                "ZTpUeXBlRXJyb3I6IENhbm5vdCByZWFkIHByb3BlcnRpZXMgb2YgdW5kZWZpbmVkIChyZWFkaW5nICdjaGlsZE5vZGVzJyk="
            )
            return headers

        statsig_manager = get_statsig_manager()
        dynamic_headers = statsig_manager.get_dynamic_headers(method, pathname)

        headers.update(dynamic_headers)

        
        return headers

    except Exception as e:
        print(f"Error generating dynamic headers: {e}")

        headers = BASE_HEADERS.copy()
        headers["x-xai-request-id"] = str(uuid.uuid4())

        headers["x-statsig-id"] = (
            "ZTpUeXBlRXJyb3I6IENhbm5vdCByZWFkIHByb3BlcnRpZXMgb2YgdW5kZWZpbmVkIChyZWFkaW5nICdjaGlsZE5vZGVzJyk="
        )
        return headers


class GrokApiException(Exception):
    """Grok API 相关的基础异常类型。"""

    def __init__(self, message: str, error_code: str = "UNKNOWN_ERROR"):
        super().__init__(message)
        self.error_code = error_code


class TokenException(GrokApiException):
    """Token 相关异常。"""

    pass


class ValidationException(GrokApiException):
    """输入校验异常。"""

    pass


class RateLimitException(GrokApiException):
    """限流相关异常。"""

    pass


@dataclass
class TokenCredential:
    """带格式校验的 Token 凭据。"""

    sso_token: str
    token_type: TokenType

    def __post_init__(self):
        """校验 token 格式。"""
        if not self.sso_token or not self.sso_token.strip():
            raise ValidationException("SSO token cannot be empty")
        if "sso=" not in self.sso_token:
            raise ValidationException("Invalid SSO token format")
        try:
            parts = self.sso_token.split("sso=")
            if len(parts) < 2 or not parts[1]:
                raise ValidationException(
                    "Invalid SSO token format: missing value after 'sso='"
                )
        except Exception as e:
            raise ValidationException(f"Invalid SSO token format: {e}")

    @classmethod
    def from_raw_token(
        cls, raw_token: str, token_type: TokenType = TokenType.NORMAL
    ) -> "TokenCredential":
        """根据原始 SSO 值创建 TokenCredential。"""
        if not raw_token or not raw_token.strip():
            raise ValidationException("Raw token cannot be empty")

        sanitized_token = raw_token.strip()
        if ";" in sanitized_token:
            raise ValidationException("Raw token contains invalid character (';')")

        formatted_token = f"sso-rw={sanitized_token};sso={sanitized_token}"
        return cls(formatted_token, token_type)

    def extract_sso_value(self) -> str:
        """从 token 中提取 SSO 值。"""
        try:
            return self.sso_token.split("sso=")[1].split(";")[0]
        except (IndexError, AttributeError) as e:
            raise TokenException(f"Failed to parse SSO token: {self.sso_token}") from e


@dataclass
class GeneratedImage:
    """带元数据的生成图片。"""

    url: str
    base_url: str = "https://assets.grok.com"
    cookies: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        """校验图片数据。"""
        if not self.url:
            raise ValidationException("Image URL cannot be empty")


@dataclass
class ProcessingState:
    """响应处理用的不可变状态。"""

    is_thinking: bool = False
    is_generating_image: bool = False
    image_generation_phase: int = 0
    # 已经输出过第一个 </think>；之后的 isThinking/webSearchResults 都会被忽略
    is_thinking_end: bool = False

    def with_thinking(self, thinking: bool) -> "ProcessingState":
        """返回带更新思考标记的新状态。"""
        return ProcessingState(
            thinking,
            self.is_generating_image,
            self.image_generation_phase,
            self.is_thinking_end,
        )

    def with_image_generation(
        self, generating: bool, phase: int = 0
    ) -> "ProcessingState":
        """返回带更新图片生成状态的新状态。"""
        return ProcessingState(
            self.is_thinking,
            generating,
            phase,
            self.is_thinking_end,
        )

    def with_thinking_end(self, thinking_end: bool = True) -> "ProcessingState":
        """返回带更新“思考结束”标记的新状态。"""
        return ProcessingState(
            self.is_thinking,
            self.is_generating_image,
            self.image_generation_phase,
            thinking_end,
        )


@dataclass
class ModelResponse:
    """带校验与转换的模型响应对象。"""

    response_id: str
    message: str
    sender: str
    create_time: str
    parent_response_id: str
    manual: bool
    partial: bool
    shared: bool
    query: str
    query_type: str
    web_search_results: List[Any] = field(default_factory=list)
    xpost_ids: List[Any] = field(default_factory=list)
    xposts: List[Any] = field(default_factory=list)
    generated_images: List[GeneratedImage] = field(default_factory=list)
    image_attachments: List[Any] = field(default_factory=list)
    file_attachments: List[Any] = field(default_factory=list)
    card_attachments_json: List[Any] = field(default_factory=list)
    file_uris: List[Any] = field(default_factory=list)
    file_attachments_metadata: List[Any] = field(default_factory=list)
    is_control: bool = False
    steps: List[Any] = field(default_factory=list)
    media_types: List[Any] = field(default_factory=list)

    @classmethod
    def from_api_response(
        cls, data: Dict[str, Any], enable_artifact_files: bool = False
    ) -> "ModelResponse":
        """根据 API 响应数据构建 ModelResponse，并做必要校验。"""
        try:
            response_id = str(data.get("responseId", ""))
            sender = str(data.get("sender", ""))
            create_time = str(data.get("createTime", ""))
            parent_response_id = str(data.get("parentResponseId", ""))
            query = str(data.get("query", ""))
            query_type = str(data.get("queryType", ""))

            manual = bool(data.get("manual", False))
            partial = bool(data.get("partial", False))
            shared = bool(data.get("shared", False))
            is_control = bool(data.get("isControl", False))

            raw_message = data.get("message", "")
            processed_message = cls._transform_xai_artifacts(str(raw_message))

            generated_images = []
            for image_url in data.get("generatedImageUrls", []):
                if image_url:
                    generated_images.append(GeneratedImage(url=str(image_url)))

            return cls(
                response_id=response_id,
                message=processed_message,
                sender=sender,
                create_time=create_time,
                parent_response_id=parent_response_id,
                manual=manual,
                partial=partial,
                shared=shared,
                query=query,
                query_type=query_type,
                web_search_results=data.get("webSearchResults", []),
                xpost_ids=data.get("xpostIds", []),
                xposts=data.get("xposts", []),
                generated_images=generated_images,
                image_attachments=data.get("imageAttachments", []),
                file_attachments=data.get("fileAttachments", []),
                card_attachments_json=data.get("cardAttachmentsJson", []),
                file_uris=data.get("fileUris", []),
                file_attachments_metadata=data.get("fileAttachmentsMetadata", []),
                is_control=is_control,
                steps=data.get("steps", []),
                media_types=data.get("mediaTypes", []),
            )
        except Exception as e:
            print(f"Failed to create ModelResponse: {e}")
            return cls(
                response_id="",
                message="Error processing response",
                sender="system",
                create_time=str(int(time.time())),
                parent_response_id="",
                manual=False,
                partial=False,
                shared=False,
                query="",
                query_type="",
            )

    @staticmethod
    def _transform_xai_artifacts(text: str) -> str:
        """
        将 xaiArtifact 标签转换为合适的 Markdown 代码块。
        覆盖所有常见格式：
        1. <xaiArtifact contentType="text/..."> … → ```<lang>\ncode\n```
        2. ```x-<lang>src → ```<lang>
        3. ```x-<lang> → ```<lang>
        4. 包含 artifact_id、title 等属性的标签
        5. 自闭合的 xaiArtifact 标签
        """
        if not text:
            return text

        def replace_artifact_with_content(match):
            full_match = match.group(0)
            content = match.group(1).strip() if match.group(1) else ""

            content_type_match = re.search(r'contentType="([^"]+)"', full_match)
            if content_type_match:
                content_type = content_type_match.group(1).strip()
                if "/" in content_type:
                    lang = content_type.split("/")[-1]
                else:
                    lang = content_type

                if content:
                    return f"```{lang}\n{content}\n```"
                else:
                    return ""
            else:
                return content

        text = re.sub(
            r"<xaiArtifact[^>]*?>(.*?)</xaiArtifact>",
            replace_artifact_with_content,
            text,
            flags=re.DOTALL,
        )

        text = re.sub(r"<xaiArtifact[^>]*?/>", "", text)

        text = re.sub(r"<xaiArtifact[^>]*>", "", text)
        text = re.sub(r"</xaiArtifact>", "", text)

        text = re.sub(
            r"```x-([a-zA-Z0-9_+-]+)src\b", lambda m: f"```{m.group(1)}", text
        )

        text = re.sub(
            r"```x-([a-zA-Z0-9_+-]+)\b(?![a-zA-Z0-9_-]*src)",
            lambda m: f"```{m.group(1)}",
            text,
        )

        return text


@dataclass
class GrokResponse:
    """Grok API 响应的完整封装。"""

    model_response: ModelResponse
    is_thinking: bool = False
    is_soft_stop: bool = False
    response_id: str = ""
    conversation_id: Optional[str] = None
    title: Optional[str] = None
    conversation_create_time: Optional[str] = None
    conversation_modify_time: Optional[str] = None
    temporary: Optional[bool] = None
    error: Optional[str] = None
    error_code: Optional[Union[int, str]] = None

    @classmethod
    def from_api_response(
        cls, data: Dict[str, Any], enable_artifact_files: bool = False
    ) -> "GrokResponse":
        """根据 API 响应数据构建 GrokResponse。"""
        try:
            error = data.get("error")
            error_code = data.get("error_code")
            result = data.get("result", {})
            response_data = result.get("response", {})

            model_response = ModelResponse.from_api_response(
                response_data.get("modelResponse", {}), enable_artifact_files
            )

            is_thinking = bool(response_data.get("isThinking", False))
            is_soft_stop = bool(response_data.get("isSoftStop", False))
            response_id = str(response_data.get("responseId", ""))

            conversation_id = response_data.get("conversationId")
            new_title = result.get("newTitle") or result.get("title")
            title = new_title if new_title else None
            conversation_create_time = response_data.get("createTime")
            conversation_modify_time = response_data.get("modifyTime")
            temporary = response_data.get("temporary")

            return cls(
                model_response=model_response,
                is_thinking=is_thinking,
                is_soft_stop=is_soft_stop,
                response_id=response_id,
                conversation_id=conversation_id,
                title=title,
                conversation_create_time=conversation_create_time,
                conversation_modify_time=conversation_modify_time,
                temporary=temporary,
                error=error,
                error_code=error_code,
            )
        except Exception as e:
            error_msg = str(e)
            return cls(
                model_response=ModelResponse.from_api_response({}),
                error=error_msg,
                error_code="RESPONSE_PARSING_ERROR",
            )


class ConfigurationManager:
    """集中式配置管理，包含校验逻辑。"""

    def __init__(self):
        """从环境变量初始化配置。"""
        self.data_dir = Path("./data")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self._config = self._load_configuration()
        self._validate_configuration()

    def _load_configuration(self) -> Dict[str, Any]:
        """从环境变量构建配置字典。"""
        return {
            "MODELS": {
                model.value: model.value.split("-")[0] + "-" + model.value.split("-")[1]
                for model in ModelType
            },
            "API": {
                "IS_TEMP_CONVERSATION": self._get_bool_env(
                    "IS_TEMP_CONVERSATION", True
                ),
                "IS_CUSTOM_SSO": self._get_bool_env("IS_CUSTOM_SSO", False),
                "BASE_URL": "https://grok.com",
                "API_KEY": os.environ.get("API_KEY", "sk-123456"),
                "RETRY_TIME": 1000,
                "PROXY": os.environ.get("PROXY"),
                # 动态代理设置
                "DYNAMIC_PROXY_API": os.environ.get("DYNAMIC_PROXY_API"),
                "PROXY_RETRY_LIMIT": int(os.environ.get("PROXY_RETRY_LIMIT", "20")),
                "PROXY_VALIDATE_URL": os.environ.get(
                    "PROXY_VALIDATE_URL", "https://grok.com/"
                ),
                "PROXY_VALIDATE_TIMEOUT": int(
                    os.environ.get("PROXY_VALIDATE_TIMEOUT", "15")
                ),
                "DISABLE_DYNAMIC_HEADERS": self._get_bool_env(
                    "DISABLE_DYNAMIC_HEADERS", False
                ),
                # 请求超时（秒）
                # REQUEST_TIMEOUT：非流式整体超时
                # STREAM_TIMEOUT：流式整体超时/低速窗口
                "REQUEST_TIMEOUT": int(os.environ.get("REQUEST_TIMEOUT", "120")),
                "STREAM_TIMEOUT": int(os.environ.get("STREAM_TIMEOUT", "600")),
            },
            "ADMIN": {
                "MANAGER_SWITCH": os.environ.get("MANAGER_SWITCH"),
                "PASSWORD": os.environ.get("ADMINPASSWORD"),
            },
            "SERVER": {
                "CF_CLEARANCE": os.environ.get("CF_CLEARANCE"),
                "PORT": int(os.environ.get("PORT", 5200)),
            },
            "RETRY": {
                "RETRYSWITCH": False,
                "MAX_ATTEMPTS": MAX_RETRY_ATTEMPTS,
            },
            "TOKEN_STATUS_FILE": str(self.data_dir / "token_status.json"),
            "SHOW_THINKING": self._get_bool_env("SHOW_THINKING", False),
            "SHOW_SEARCH_RESULTS": self._get_bool_env("SHOW_SEARCH_RESULTS", True),
            # 思维链格式：false=<think>标签，true=OpenAI o1风格的reasoning_content
            "USE_REASONING_FORMAT": self._get_bool_env("USE_REASONING_FORMAT", False),
            # 是否将多个 <think> 片段合并为一个“思考”区域
            "COALESCE_THINKING": self._get_bool_env("COALESCE_THINKING", True),
            "IS_SUPER_GROK": self._get_bool_env("IS_SUPER_GROK", False),
            "FILTERED_TAGS": self._get_list_env(
                "FILTERED_TAGS",
                [
                    "xaiartifact",
                    "xai:tool_usage_card",
                    "xai:toolusagecard",
                    "grok:render",
                    "details",
                    "summary",
                ],
            ),
            "TAG_CONFIG": self._get_tag_config(),
            "CONTENT_TYPE_MAPPINGS": self._get_content_type_mappings(),
        }

    def _get_bool_env(self, key: str, default: bool = False) -> bool:
        """读取布尔型环境变量。"""
        return os.environ.get(key, str(default)).lower() == "true"

    def _get_list_env(self, key: str, default: List[str]) -> List[str]:
        """读取逗号分隔的列表型环境变量。"""
        value = os.environ.get(key)
        if not value:
            return default
        return [tag.strip() for tag in value.split(",") if tag.strip()]

    def _get_content_type_mappings(self) -> Dict[str, Dict[str, str]]:
        """读取内容类型到代码块包裹符的映射（来自环境变量或默认值）。"""
        mappings_env = os.environ.get("CONTENT_TYPE_MAPPINGS")
        if mappings_env:
            try:
                return json.loads(mappings_env)
            except json.JSONDecodeError:
                print("Invalid CONTENT_TYPE_MAPPINGS JSON, using defaults")

        return {
            "text/plain": {"stag": "```", "etag": "```"},
            "text/markdown": {"stag": "", "etag": ""},
            "application/json": {"stag": "```json\n", "etag": "\n```"},
            "text/javascript": {"stag": "```javascript\n", "etag": "\n```"},
            "text/python": {"stag": "```python\n", "etag": "\n```"},
            "text/html": {"stag": "```html\n", "etag": "\n```"},
            "text/css": {"stag": "```css\n", "etag": "\n```"},
            "text/xml": {"stag": "```xml\n", "etag": "\n```"},
            "application/xml": {"stag": "```xml\n", "etag": "\n```"},
            "text/yaml": {"stag": "```yaml\n", "etag": "\n```"},
            "application/yaml": {"stag": "```yaml\n", "etag": "\n```"},
            "text/x-yaml": {"stag": "```yaml\n", "etag": "\n```"},
            "text/sql": {"stag": "```sql\n", "etag": "\n```"},
            "application/sql": {"stag": "```sql\n", "etag": "\n```"},
            "text/x-sql": {"stag": "```sql\n", "etag": "\n```"},
            "text/typescript": {"stag": "```typescript\n", "etag": "\n```"},
            "application/typescript": {"stag": "```typescript\n", "etag": "\n```"},
            "text/x-typescript": {"stag": "```typescript\n", "etag": "\n```"},
            "text/jsx": {"stag": "```jsx\n", "etag": "\n```"},
            "text/x-jsx": {"stag": "```jsx\n", "etag": "\n```"},
            "text/tsx": {"stag": "```tsx\n", "etag": "\n```"},
            "text/x-tsx": {"stag": "```tsx\n", "etag": "\n```"},
            "text/java": {"stag": "```java\n", "etag": "\n```"},
            "application/java": {"stag": "```java\n", "etag": "\n```"},
            "text/x-java": {"stag": "```java\n", "etag": "\n```"},
            "text/csharp": {"stag": "```csharp\n", "etag": "\n```"},
            "text/x-csharp": {"stag": "```csharp\n", "etag": "\n```"},
            "application/x-csharp": {"stag": "```csharp\n", "etag": "\n```"},
            "text/cpp": {"stag": "```cpp\n", "etag": "\n```"},
            "text/x-c++": {"stag": "```cpp\n", "etag": "\n```"},
            "application/x-cpp": {"stag": "```cpp\n", "etag": "\n```"},
            "text/c": {"stag": "```c\n", "etag": "\n```"},
            "text/x-c": {"stag": "```c\n", "etag": "\n```"},
            "text/go": {"stag": "```go\n", "etag": "\n```"},
            "text/x-go": {"stag": "```go\n", "etag": "\n```"},
            "application/x-go": {"stag": "```go\n", "etag": "\n```"},
            "text/rust": {"stag": "```rust\n", "etag": "\n```"},
            "text/x-rust": {"stag": "```rust\n", "etag": "\n```"},
            "application/x-rust": {"stag": "```rust\n", "etag": "\n```"},
            "text/php": {"stag": "```php\n", "etag": "\n```"},
            "application/x-php": {"stag": "```php\n", "etag": "\n```"},
            "text/ruby": {"stag": "```ruby\n", "etag": "\n```"},
            "application/x-ruby": {"stag": "```ruby\n", "etag": "\n```"},
            "text/swift": {"stag": "```swift\n", "etag": "\n```"},
            "text/x-swift": {"stag": "```swift\n", "etag": "\n```"},
            "text/kotlin": {"stag": "```kotlin\n", "etag": "\n```"},
            "text/x-kotlin": {"stag": "```kotlin\n", "etag": "\n```"},
            "text/scala": {"stag": "```scala\n", "etag": "\n```"},
            "text/x-scala": {"stag": "```scala\n", "etag": "\n```"},
            "text/bash": {"stag": "```bash\n", "etag": "\n```"},
            "text/x-bash": {"stag": "```bash\n", "etag": "\n```"},
            "application/x-bash": {"stag": "```bash\n", "etag": "\n```"},
            "text/shell": {"stag": "```bash\n", "etag": "\n```"},
            "text/x-shell": {"stag": "```bash\n", "etag": "\n```"},
            "application/x-shell": {"stag": "```bash\n", "etag": "\n```"},
            "text/powershell": {"stag": "```powershell\n", "etag": "\n```"},
            "text/x-powershell": {"stag": "```powershell\n", "etag": "\n```"},
            "application/x-powershell": {"stag": "```powershell\n", "etag": "\n```"},
            "text/dockerfile": {"stag": "```dockerfile\n", "etag": "\n```"},
            "text/x-dockerfile": {"stag": "```dockerfile\n", "etag": "\n```"},
            "application/x-dockerfile": {"stag": "```dockerfile\n", "etag": "\n```"},
            "text/toml": {"stag": "```toml\n", "etag": "\n```"},
            "application/toml": {"stag": "```toml\n", "etag": "\n```"},
            "text/ini": {"stag": "```ini\n", "etag": "\n```"},
            "text/x-ini": {"stag": "```ini\n", "etag": "\n```"},
            "application/x-ini": {"stag": "```ini\n", "etag": "\n```"},
            "text/properties": {"stag": "```properties\n", "etag": "\n```"},
            "text/x-properties": {"stag": "```properties\n", "etag": "\n```"},
            "text/csv": {"stag": "```csv\n", "etag": "\n```"},
            "application/csv": {"stag": "```csv\n", "etag": "\n```"},
            "text/x-csv": {"stag": "```csv\n", "etag": "\n```"},
            "text/log": {"stag": "```\n", "etag": "\n```"},
            "application/x-log": {"stag": "```\n", "etag": "\n```"},
            "text/x-log": {"stag": "```\n", "etag": "\n```"},
            "application/x-httpd-php": {"stag": "```php\n", "etag": "\n```"},
            "text/x-python": {"stag": "```python\n", "etag": "\n```"},
            "application/x-python": {"stag": "```python\n", "etag": "\n```"},
            "text/x-javascript": {"stag": "```javascript\n", "etag": "\n```"},
            "application/javascript": {"stag": "```javascript\n", "etag": "\n```"},
            "text/ecmascript": {"stag": "```javascript\n", "etag": "\n```"},
            "application/ecmascript": {"stag": "```javascript\n", "etag": "\n```"},
            "text/jscript": {"stag": "```javascript\n", "etag": "\n```"},
            "application/x-javascript": {"stag": "```javascript\n", "etag": "\n```"},
            "text/vbscript": {"stag": "```vbscript\n", "etag": "\n```"},
            "application/x-vbscript": {"stag": "```vbscript\n", "etag": "\n```"},
            "text/x-markdown": {"stag": "", "etag": ""},
            "application/x-markdown": {"stag": "", "etag": ""},
            "text/x-web-markdown": {"stag": "", "etag": ""},
            "code/python": {"stag": "```python\n", "etag": "\n```"},
            "code/javascript": {"stag": "```javascript\n", "etag": "\n```"},
            "code/typescript": {"stag": "```typescript\n", "etag": "\n```"},
            "code/html": {"stag": "```html\n", "etag": "\n```"},
            "code/css": {"stag": "```css\n", "etag": "\n```"},
            "code/json": {"stag": "```json\n", "etag": "\n```"},
            "code/xml": {"stag": "```xml\n", "etag": "\n```"},
            "code/yaml": {"stag": "```yaml\n", "etag": "\n```"},
            "code/sql": {"stag": "```sql\n", "etag": "\n```"},
            "code/bash": {"stag": "```bash\n", "etag": "\n```"},
            "code/shell": {"stag": "```bash\n", "etag": "\n```"},
            "code/dockerfile": {"stag": "```dockerfile\n", "etag": "\n```"},
            "text/code": {"stag": "```\n", "etag": "\n```"},
            "application/code": {"stag": "```\n", "etag": "\n```"},
            "text/source": {"stag": "```\n", "etag": "\n```"},
            "application/source": {"stag": "```\n", "etag": "\n```"},
        }

    def _get_tag_config(self) -> Dict[str, Dict[str, Any]]:
        """读取被过滤标签配置（来自环境变量或默认值）。"""
        tag_config_env = os.environ.get("TAG_CONFIG")
        if tag_config_env:
            try:
                return json.loads(tag_config_env)
            except json.JSONDecodeError:
                print("Invalid TAG_CONFIG JSON, using defaults")

        filtered_tags = self._get_list_env(
            "FILTERED_TAGS",
            ["xaiartifact", "xai:tool_usage_card", "xai:toolusagecard", "grok:render", "details", "summary"],
        )
        default_config = {}

        for tag in filtered_tags:
            if tag.lower() in ["xai:tool_usage_card", "xai:toolusagecard", "grok:render"]:
                default_config[tag.lower()] = {"behavior": "remove_all"}
            else:
                default_config[tag.lower()] = {"behavior": "preserve_content"}

        if not default_config:
            default_config = {
                "xaiartifact": {"behavior": "preserve_content"},
                "xai:tool_usage_card": {"behavior": "remove_all"},
                "xai:toolusagecard": {"behavior": "remove_all"},
                "grok:render": {"behavior": "remove_all"},
                "details": {"behavior": "preserve_content"},
                "summary": {"behavior": "preserve_content"},
            }

        return default_config

    def _validate_configuration(self) -> None:
        """校验配置项的有效性。"""
        issues = []

        if not os.environ.get("API_KEY"):
            issues.append("Missing required environment variable: API_KEY")

        if not self._config["API"]["IS_CUSTOM_SSO"]:
            sso_env = os.environ.get("SSO", "")
            sso_super_env = os.environ.get("SSO_SUPER", "")
            if not sso_env and not sso_super_env:
                issues.append(
                    "No SSO tokens configured. Set SSO or SSO_SUPER environment variables."
                )

        proxy = self._config["API"]["PROXY"]
        if proxy and not any(
            proxy.startswith(p) for p in ["http://", "https://", "socks5://"]
        ):
            issues.append(f"Invalid proxy format: {proxy}")

        if issues:
            for issue in issues:
                print(f"Configuration issue: {issue}")
        else:
            print("Configuration validation passed")

    def get(self, key_path: str, default: Any = None) -> Any:
        """用点号路径读取配置值。"""
        keys = key_path.split(".")
        value = self._config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, key_path: str, value: Any) -> None:
        """用点号路径写入配置值。"""
        keys = key_path.split(".")
        config = self._config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value

    @property
    def models(self) -> Dict[str, str]:
        """返回受支持模型的映射表。"""
        return self._config["MODELS"]

    @property
    def data_directory(self) -> Path:
        """返回 data 目录路径。"""
        return self.data_dir


class UtilityFunctions:
    """常用工具函数集合。"""

    @staticmethod
    def get_proxy_configuration(proxy_url: Optional[str]) -> Dict[str, Any]:
        """构造 requests/curl_cffi 可接受的代理配置。"""
        if not proxy_url:
            return {}

        

        if proxy_url.startswith("socks5://"):
            proxy_config: Dict[str, Any] = {"proxy": proxy_url}

            if "@" in proxy_url:
                auth_part = proxy_url.split("@")[0].split("://")[1]
                if ":" in auth_part:
                    username, password = auth_part.split(":", 1)
                    proxy_config["proxy_auth"] = (username, password)

            return proxy_config
        else:
            return {"proxies": {"https": proxy_url, "http": proxy_url}}

    @staticmethod  
    def organize_search_results(search_results: Dict[str, Any]) -> str:  
        """格式化搜索结果用于展示。"""  
        if not search_results or "results" not in search_results:  
            return ""  

        results = search_results["results"]  
        formatted_results = []  

        for index, result in enumerate(results):  
            title = result.get("title", "未知标题")  
            url = result.get("url", "#")  
            preview = result.get("preview", "无预览内容")  
            
            # 清理preview内容
            cleaned_preview = UtilityFunctions.clean_markdown(preview)
            
            # 使用方案二的格式：- **[标题](链接)**  + 换行 + 内容
            formatted_result = f"- **[{title}]({url})**  \n  {cleaned_preview}"
            formatted_results.append(formatted_result)  

        # 在最后追加换行
        return "\n\n".join(formatted_results) + "\n"

    @staticmethod  
    def clean_markdown(text):
        # 移除Markdown格式
        # 移除标题 (# ## ### 等)
        text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
        
        # 移除粗体和斜体 (**text** *text* __text__ _text_)
        text = re.sub(r'\*{1,2}([^*]+)\*{1,2}', r'\1', text)
        text = re.sub(r'_{1,2}([^_]+)_{1,2}', r'\1', text)
        
        # 移除删除线 (~~text~~)
        text = re.sub(r'~~([^~]+)~~', r'\1', text)
        
        # 移除链接 [text](url)
        text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
        
        # 移除图片 ![alt](url)
        text = re.sub(r'!\[([^\]]*)\]\([^)]+\)', r'\1', text)
        
        # 移除代码块 ```code```
        text = re.sub(r'```[^`]*```', '', text, flags=re.DOTALL)
        
        # 移除行内代码 `code`
        text = re.sub(r'`([^`]+)`', r'\1', text)
        
        # 移除列表标记 (- * + 开头的行)
        text = re.sub(r'^[\s]*[-*+]\s+', '', text, flags=re.MULTILINE)
        
        # 移除有序列表 (1. 2. 等)
        text = re.sub(r'^\s*\d+\.\s+', '', text, flags=re.MULTILINE)
        
        # 移除引用 (> 开头的行)
        text = re.sub(r'^>\s*', '', text, flags=re.MULTILINE)
        
        # 移除水平分割线
        text = re.sub(r'^[-*_]{3,}$', '', text, flags=re.MULTILINE)
        
        # 移除表格分隔符
        text = re.sub(r'\|', ' ', text)
        
        # 移除多余的换行（保留段落之间的单个换行）
        text = re.sub(r'\n{3,}', '\n\n', text)  # 将3个及以上的换行替换为2个
        text = re.sub(r'\n+', ' ', text)  # 将所有换行替换为空格
        
        # 移除多余的空格
        text = re.sub(r'\s{2,}', ' ', text)
        
        return text.strip()


    @staticmethod
    def parse_error_response(response_text: str) -> Dict[str, Any]:
        """解析错误响应，返回结构化信息。"""
        if not response_text or not response_text.strip():
            return {
                "error_code": "EMPTY_RESPONSE",
                "error": "Empty or invalid response received",
                "details": [],
            }

        try:
            try:
                response = json.loads(response_text)
                if isinstance(response, dict):
                    if "error" in response:
                        error = response["error"]
                        if isinstance(error, dict):
                            return {
                                "error_code": error.get("code"),
                                "error": error.get("message") or response_text,
                                "details": (
                                    error.get("details", [])
                                    if isinstance(error.get("details"), list)
                                    else []
                                ),
                            }
                        else:
                            return {
                                "error_code": "Unknown",
                                "error": str(error),
                                "details": [],
                            }
                    elif "message" in response:
                        return {
                            "error_code": response.get("code"),
                            "error": response.get("message") or response_text,
                            "details": (
                                response.get("details", [])
                                if isinstance(response.get("details"), list)
                                else []
                            ),
                        }
                    else:
                        return {
                            "error_code": "Unknown",
                            "error": response_text,
                            "details": [],
                        }
            except json.JSONDecodeError:
                pass

            if " - " in response_text:
                json_str = response_text.split(" - ", 1)[1]
                response = json.loads(json_str)

                if isinstance(response, dict):
                    if "error" in response:
                        error = response["error"]
                        if isinstance(error, dict):
                            return {
                                "error_code": error.get("code"),
                                "error": error.get("message") or response_text,
                                "details": (
                                    error.get("details", [])
                                    if isinstance(error.get("details"), list)
                                    else []
                                ),
                            }
                        else:
                            return {
                                "error_code": "Unknown",
                                "error": str(error),
                                "details": [],
                            }
                    elif "message" in response:
                        return {
                            "error_code": response.get("code"),
                            "error": response.get("message") or response_text,
                            "details": (
                                response.get("details", [])
                                if isinstance(response.get("details"), list)
                                else []
                            ),
                        }

        except (json.JSONDecodeError, KeyError, AttributeError) as e:
            print(f"Error parsing error response: {e}")

        return {
            "error_code": "Unknown",
            "error": response_text or "Unknown error occurred",
            "details": [],
        }

    @staticmethod
    def create_retry_decorator(
        max_attempts: int = MAX_RETRY_ATTEMPTS, base_delay: float = BASE_RETRY_DELAY
    ):
        """生成带指数退避的重试装饰器。"""

        def retry_decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                attempts = 0
                last_error = None

                while attempts < max_attempts:
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        attempts += 1
                        last_error = e

                        if attempts >= max_attempts:
                            print(
                                f"All retries failed ({max_attempts} attempts): {e}",
                                "RetryMechanism",
                            )
                            raise e

                        delay = min(base_delay * (2 ** (attempts - 1)), 60)
                        print(
                            f"Retry {attempts}/{max_attempts}, delay {delay}s: {e}",
                            "RetryMechanism",
                        )
                        time.sleep(delay)

                raise last_error or Exception("Retry mechanism failed unexpectedly")

            return wrapper

        return retry_decorator

    @staticmethod
    async def run_in_thread_pool(func, *args, **kwargs):
        """在线程池运行同步函数，兼容异步调用。"""
        try:
            loop = asyncio.get_running_loop()
            ctx = contextvars.copy_context()
            func_call = functools.partial(ctx.run, func, *args, **kwargs)
            return await loop.run_in_executor(None, func_call)
        except RuntimeError:
            with ThreadPoolExecutor() as executor:
                future = executor.submit(func, *args, **kwargs)
                return future.result()

    @staticmethod
    def create_structured_error_response(
        error_data: Union[str, Dict[str, Any]], status_code: int = 500
    ) -> Tuple[Dict[str, Any], int]:
        """创建结构化错误响应。"""
        if isinstance(error_data, str):
            error_data = UtilityFunctions.parse_error_response(error_data)

        error_message = error_data.get("error", "Unknown error")
        error_code = error_data.get("error_code")
        error_details = error_data.get("details", [])

        if not error_message or error_message.strip() == "":
            error_message = "An error occurred while processing the request"

        return {
            "error": {
                "message": str(error_message),
                "type": "server_error",
                "code": str(error_code),
                "details": list(error_details) if error_details else [],
            }
        }, status_code


@dataclass
class TokenEntry:
    """单个 Token 条目，包含用量跟踪。"""

    credential: TokenCredential
    max_request_count: int
    request_count: int
    added_time: int
    start_call_time: Optional[int] = None

    def is_available(self) -> bool:
        """判断是否仍可使用。"""
        return self.request_count < self.max_request_count

    def can_be_reset(self, expiration_time_ms: int, current_time_ms: int) -> bool:
        """根据过期时间判断是否可重置。"""
        if not self.start_call_time:
            return False
        return current_time_ms - self.start_call_time >= expiration_time_ms

    def use_token(self) -> None:
        """标记一次使用。"""
        if not self.start_call_time:
            self.start_call_time = int(time.time() * 1000)
        self.request_count += 1

    def reset_usage(self) -> None:
        """重置使用计数。"""
        self.request_count = 0
        self.start_call_time = None


@dataclass
class ModelLimits:
    """模型请求限额配置。"""

    request_frequency: int
    expiration_time_ms: int


class ThreadSafeTokenManager:
    """线程安全的 Token 管理器（含同步机制）。"""

    def __init__(self, config: ConfigurationManager):
        """用配置初始化 Token 管理器。"""
        self.config = config
        self._lock = threading.RLock()
        self._token_storage: Dict[str, List[TokenEntry]] = {}
        self._token_status: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._expiredTokens: List[Tuple[str, str, int, TokenType]] = []

        self._reset_timer_started = False
        self._load_token_status()

    def _normalize_model_name(self, model: str) -> str:
        """标准化模型名，便于统一查找。

        规则：
        - 若存在外部别名，通过 config.models 映射到内部 id；
        - 将基础族（如 grok-4-mini-*、grok-4-*、grok-3-*）折叠为 'grok-4' 或 'grok-3'。
        """
        try:
            # 将外部别名映射为内部 id（例如 gpt-4-fast -> grok-4-mini-thinking-tahoe）
            mapped = self.config.models.get(model, model) if hasattr(self, 'config') else model
        except Exception:
            mapped = model

        if mapped.startswith("grok-"):
            parts = mapped.split("-")
            return f"{parts[0]}-{parts[1]}" if len(parts) >= 2 else mapped
        return mapped

    def _save_token_status(self) -> None:
        """将 token 状态写入持久化存储。"""
        try:
            status_file = Path(self.config.get("TOKEN_STATUS_FILE"))
            with open(status_file, "w", encoding="utf-8") as f:
                json.dump(self._token_status, f, indent=2, ensure_ascii=False)
            print(f"Token status saved to file: {status_file}")
        except Exception as e:
            print(f"Failed to save token status: {e}")
            import traceback
            traceback.print_exc()

    def _load_token_status(self) -> None:
        """从持久化存储加载 token 状态，并重建内存结构。"""
        try:
            status_file = Path(self.config.get("TOKEN_STATUS_FILE"))  # ./data/token_status.json 路径
            fallback_file = Path("data/token_status.json")            # 兼容旧路径 ./data/token_status.json
            load_path = None

            if status_file.exists():
                load_path = status_file
            elif fallback_file.exists():
                load_path = fallback_file
                print(f"Primary token status file not found, using fallback: {fallback_file}")

            if load_path:
                with open(load_path, "r", encoding="utf-8") as f:
                    self._token_status = json.load(f)
                print(f"Token status loaded from file: {load_path}")

                self._reconstruct_token_storage()
        except Exception as e:
            print(f"Failed to load token status: {e}")
            self._token_status = {}

    def _reconstruct_token_storage(self) -> None:
        """根据 _token_status 重建 _token_storage。

        说明：在新的“配额制”方案中，_token_storage 基本不再使用，此方法仅为兼容保留。
        """
        try:
            reconstructed_count = 0
            for sso_value, token_data in self._token_status.items():
                # 新结构下，token 信息存于顶层；采用配额制后无需逐模型重建

                # 若结构不合法则跳过
                if not isinstance(token_data, dict) or "quota" not in token_data:
                    continue

                # 为兼容旧版，保留对按模型存储的处理；但新系统以配额制为准
                reconstructed_count += 1

            if reconstructed_count > 0:
                print(f"Reconstructed {reconstructed_count} token entries using quota-based system")
        except Exception as e:
            print(f"Failed to reconstruct token storage: {e}")
            import traceback
            traceback.print_exc()

    def _ensure_quota_defaults_for_all(self) -> None:
        """为所有 token 补齐默认配额/计数（兼容旧版 token_status.json）。"""
        try:
            changed = False
            for sso_value, token_data in self._token_status.items():
                # 确保结构为有效的 dict
                if not isinstance(token_data, dict):
                    print(f"Invalid token data structure for {sso_value}")
                    continue

                quota = token_data.get("quota")
                counts = token_data.get("counts")

                if quota is None or counts is None:
                    # 默认：80 总额度/剩余额度
                    remaining = 80
                    total = 80
                    fast_counts = int(math.floor(remaining / 1))
                    expert_counts = int(math.floor(remaining / 4))
                    imagegen_counts = int(math.floor(remaining / 4))

                    self._token_status[sso_value]["quota"] = {
                        "windowSizeSeconds": None,
                        "totalTokens": total,
                        "remainingTokens": remaining,
                        "updatedAt": int(time.time() * 1000),
                    }
                    self._token_status[sso_value]["counts"] = {
                        "fast": fast_counts,
                        "expert": expert_counts,
                        "imageGen": imagegen_counts,
                    }

                    # 初始化 modelStats（若不存在）
                    if "modelStats" not in self._token_status[sso_value]:
                        self._token_status[sso_value]["modelStats"] = {}
                        for model_type in ModelType:
                            self._token_status[sso_value]["modelStats"][model_type.value] = {
                                "lastCallTime": None,
                                "requestCount": 0,
                                "failureCount": 0,
                                "lastFailureTime": None,
                                "lastFailureResponse": None
                            }

                    # 确保基础状态字段存在
                    if "isSuper" not in self._token_status[sso_value]:
                        self._token_status[sso_value]["isSuper"] = False
                    if "isExpired" not in self._token_status[sso_value]:
                        self._token_status[sso_value]["isExpired"] = False
                    if "isValid" not in self._token_status[sso_value]:
                        self._token_status[sso_value]["isValid"] = True

                    changed = True

            if changed:
                self._save_token_status()
        except Exception as e:
            print(f"Failed to ensure default quotas: {e}")
            import traceback
            traceback.print_exc()

    def record_token_failure(
        self, model: str, token_string: str, failure_reason: str, status_code: int
    ) -> None:
        """记录一次 token 失败，并在必要时标记为过期。"""
        with self._lock:
            try:
                credential = TokenCredential(token_string, TokenType.NORMAL)
                sso_value = credential.extract_sso_value()

                if sso_value not in self._token_status:
                    return

                token_data = self._token_status[sso_value]

                # 更新modelStats统计 - 使用原始模型名
                if "modelStats" not in token_data:
                    token_data["modelStats"] = {}

                model_stats = token_data["modelStats"]
                if model not in model_stats:
                    model_stats[model] = {
                        "lastCallTime": None,
                        "requestCount": 0,
                        "failureCount": 0,
                        "lastFailureTime": None,
                        "lastFailureResponse": None
                    }

                model_stats[model]["failureCount"] += 1
                model_stats[model]["lastFailureTime"] = int(time.time() * 1000)
                model_stats[model]["lastFailureResponse"] = f"{status_code}: {failure_reason}"

                # 检查失败阈值，基于modelStats数据
                failure_threshold = 3
                if model_stats[model]["failureCount"] >= failure_threshold and status_code in [401, 403]:
                    token_data["isExpired"] = True
                    token_data["isValid"] = False
                    print(
                        f"Token marked as expired after {model_stats[model]['failureCount']} failures: {failure_reason}",
                        "TokenManager",
                    )

                self._save_token_status()
                print(
                    f"Recorded token failure for {model}: {failure_reason} (total failures: {model_stats[model]['failureCount']})",
                    "TokenManager",
                )

            except Exception as e:
                print(f"Failed to record token failure: {e}")

    def _is_token_expired(self, token_entry: TokenEntry, model: str) -> bool:
        """检查 token 是否被标记为过期。"""
        try:
            sso_value = token_entry.credential.extract_sso_value()
            if (
                sso_value in self._token_status
                and model in self._token_status[sso_value]
            ):
                status = self._token_status[sso_value][model]
                return status.get("isExpired", False)
            return False
        except Exception as e:
            print(f"Failed to check token expiration: {e}")
            return False

    def add_token(
        self, credential: TokenCredential, is_initialization: bool = False
    ) -> bool:
        """向系统添加 token。"""
        with self._lock:
            try:
                sso_value = credential.extract_sso_value()

                # 初始化 token 状态桶（配额 + modelStats）
                if sso_value not in self._token_status:
                    self._token_status[sso_value] = {}

                    # 初始化共享配额（积分制）
                    self._token_status[sso_value]["quota"] = {
                        "windowSizeSeconds": None,
                        "totalTokens": 80,
                        "remainingTokens": 80,
                        "updatedAt": int(time.time() * 1000),
                    }

                    # 为不同模型类型初始化计数
                    self._token_status[sso_value]["counts"] = {
                        "fast": 80,
                        "expert": 20,
                        "imageGen": 20,
                    }

                    # 初始化基础状态字段
                    self._token_status[sso_value]["isSuper"] = credential.token_type == TokenType.SUPER
                    self._token_status[sso_value]["isExpired"] = False
                    self._token_status[sso_value]["isValid"] = True

                    # 为所有可用模型初始化 modelStats
                    self._token_status[sso_value]["modelStats"] = {}
                    for model_type in ModelType:
                        self._token_status[sso_value]["modelStats"][model_type.value] = {
                            "lastCallTime": None,
                            "requestCount": 0,
                            "failureCount": 0,
                            "lastFailureTime": None,
                            "lastFailureResponse": None
                        }

                if not is_initialization:
                    self._save_token_status()

                print(
                    f"Token added successfully for type: {credential.token_type.value}",
                    "TokenManager",
                )
                return True

            except Exception as e:
                print(f"Failed to add token: {e}")
                return False

    def _is_token_valid_for_model(self, token_entry: TokenEntry, model: str) -> bool:
        """综合限流与配额判断 token 是否可用于指定模型。

        新校验逻辑：
        - 检查是否过期（旧逻辑）
        - 检查是否被限流（旧逻辑）
        - 检查配额是否满足该模型需求（新逻辑）
        """
        try:
            # 检查是否已过期
            if self._is_token_expired(token_entry, model):
                return False

            sso_value = token_entry.credential.extract_sso_value()
            if sso_value not in self._token_status:
                return False

            # 检查模型层面的限流（旧逻辑）
            if model in self._token_status[sso_value]:
                model_status = self._token_status[sso_value][model]
                if not model_status.get("isValid", True):
                    return False

            # 检查基于配额的可用性（新逻辑）
            quota_data = self._token_status[sso_value].get("quota", {})
            remaining_tokens = quota_data.get("remainingTokens", 0)

            # 计算该模型所需配额
            required_tokens = 4 if model.endswith(("-expert", "-imageGen")) else 1

            # 配额不足则视为不可用
            if remaining_tokens < required_tokens:
                return False

            return True

        except Exception as e:
            print(f"Error checking token validity: {e}")
            return False

    def get_token_for_model(self, model: str) -> Optional[str]:
        """基于配额规则，获取该模型可用的 token。"""
        with self._lock:
        # 新的配额制：直接在可用 token 中选择
            for sso_value, token_data in self._token_status.items():
                if not isinstance(token_data, dict):
                    continue

                # 检查是否已过期/无效
                if token_data.get("isExpired", False) or not token_data.get("isValid", True):
                    continue

                # 检查该模型类型的剩余额度
                quota_data = token_data.get("quota", {})
                remaining_tokens = quota_data.get("remainingTokens", 0)

                # 计算所需配额（按原始模型名判断 expert/imageGen）
                if model.endswith(("-expert", "-imageGen")):
                    required_tokens = 4
                else:
                    required_tokens = 1

                # 不足则跳过
                if remaining_tokens < required_tokens:
                    continue

                # 找到可用 token，构造 token 字符串
                token_string = f"sso-rw={sso_value};sso={sso_value}"

                return token_string

            print(f"No available tokens found for model: {model}")
            return None

    def remove_token_from_model(self, model: str, token_string: str) -> bool:
        """从模型移除指定 token。"""
        with self._lock:
            normalized_model = self._normalize_model_name(model)

            if normalized_model not in self._token_storage:
                return False

            tokens = self._token_storage[normalized_model]
            for i, token_entry in enumerate(tokens):
                if token_entry.credential.sso_token == token_string:
                    removed_entry = tokens.pop(i)

                    self._expiredTokens.append(
                        (
                            token_string,
                            normalized_model,
                            int(time.time() * 1000),
                            removed_entry.credential.token_type,
                        )
                    )

                    print(f"Token removed from model {model}")
                    return True

            return False

    def get_token_count_for_model(self, model: str) -> int:
        """按配额规则统计该模型可用的 token 数量。"""
        with self._lock:
            count = 0

            # 计算所需配额（按原始模型名判断 expert/imageGen）
            if model.endswith(("-expert", "-imageGen")):
                required_tokens = 4
            else:
                required_tokens = 1

            for sso_value, token_data in self._token_status.items():
                if not isinstance(token_data, dict):
                    continue

                # 检查是否有效且未过期
                if token_data.get("isExpired", False) or not token_data.get("isValid", True):
                    continue

                # 检查配额是否充足
                quota_data = token_data.get("quota", {})
                remaining_tokens = quota_data.get("remainingTokens", 0)

                if remaining_tokens >= required_tokens:
                    count += 1

            return count

    def rotate_token(self, model: str, token_string: str) -> None:
        """在配额制下标记该 token 出现问题（收到 429 时使用，作为失败统计）。"""
        with self._lock:
            try:
                # 从 token 字符串中提取 SSO 值
                if "sso=" in token_string:
                    sso_value = token_string.split("sso=")[1].split(";")[0]
                else:
                    print(f"Invalid token format for rotation: {token_string}")
                    return

                if sso_value not in self._token_status:
                    return

                token_data = self._token_status[sso_value]

                # 作为软失败（限流）记入模型统计，使用原始模型名
                model_stats = token_data.get("modelStats", {})
                if model not in model_stats:
                    model_stats[model] = {
                        "lastCallTime": None,
                        "requestCount": 0,
                        "failureCount": 0,
                        "lastFailureTime": None,
                        "lastFailureResponse": None
                    }

                model_stats[model]["failureCount"] += 1
                model_stats[model]["lastFailureTime"] = int(time.time() * 1000)
                model_stats[model]["lastFailureResponse"] = "429: Rate limited"

                self._save_token_status()
                print(f"Marked token for potential rate limiting on {model}", "TokenManager")

            except Exception as e:
                print(f"Failed to rotate token: {e}")

    def get_remaining_capacity(self) -> Dict[str, int]:
        """获取每个模型的剩余请求容量。"""
        with self._lock:
            capacity_map = {}

            for model, tokens in self._token_storage.items():
                total_capacity = sum(entry.max_request_count for entry in tokens)
                used_requests = sum(entry.request_count for entry in tokens)
                capacity_map[model] = max(0, total_capacity - used_requests)

            return capacity_map

    # --- 管理端：配额重置辅助 ---
    def reset_token_quota(
        self, sso_value: str, remaining: Optional[int] = None, total: Optional[int] = None
    ) -> bool:
        """重置单个 token 的配额并持久化。

        说明：
        - remaining 省略时重置为 total（或原有 total，默认 80）；
        - total 省略时保留原有 total（默认 80）；
        - 同时重置 isExpired 与 isValid 状态。
        """
        try:
            with self._lock:
                if sso_value not in self._token_status:
                    return False

                models_data = self._token_status[sso_value]
                quota = models_data.get("quota", {})
                cur_total = int(quota.get("totalTokens", 80) or 80)
                new_total = int(total) if total is not None else cur_total
                new_remaining = (
                    int(remaining)
                    if remaining is not None
                    else new_total
                )
                new_remaining = max(0, new_remaining)

                # 计算各模式可用次数
                fast_counts = int(math.floor(new_remaining / 1))
                expert_counts = int(math.floor(new_remaining / 4))
                imagegen_counts = int(math.floor(new_remaining / 4))

                models_data["quota"] = {
                    "windowSizeSeconds": quota.get("windowSizeSeconds"),
                    "totalTokens": new_total,
                    "remainingTokens": new_remaining,
                    "updatedAt": int(time.time() * 1000),
                }
                models_data["counts"] = {
                    "fast": fast_counts,
                    "expert": expert_counts,
                    "imageGen": imagegen_counts,
                }

                # 重置所有模型的状态
                for model, model_data in models_data.items():
                    if isinstance(model_data, dict) and not model.startswith("__"):
                        model_data["isExpired"] = False
                        model_data["isValid"] = True  # 重置为有效状态
                        model_data["failed_request_count"] = 0
                        model_data["last_failure_time"] = None
                        model_data["last_failure_reason"] = None

                self._save_token_status()
                return True
        except Exception as e:
            print(f"Failed to reset token quota: {e}")
            return False

    def reset_all_quotas(
        self, remaining: Optional[int] = None, total: Optional[int] = None
    ) -> int:
        """重置所有 token 的配额，返回更新数量。"""
        try:
            updated = 0
            with self._lock:
                for sso_value in list(self._token_status.keys()):
                    try:
                        models_data = self._token_status[sso_value]
                        quota = models_data.get("quota", {})
                        cur_total = int(quota.get("totalTokens", 80) or 80)
                        new_total = int(total) if total is not None else cur_total
                        new_remaining = (
                            int(remaining)
                            if remaining is not None
                            else new_total
                        )
                        new_remaining = max(0, new_remaining)

                        # 计算各模式可用次数
                        fast_counts = int(math.floor(new_remaining / 1))
                        expert_counts = int(math.floor(new_remaining / 4))
                        imagegen_counts = int(math.floor(new_remaining / 4))

                        models_data["quota"] = {
                            "windowSizeSeconds": quota.get("windowSizeSeconds"),
                            "totalTokens": new_total,
                            "remainingTokens": new_remaining,
                            "updatedAt": int(time.time() * 1000),
                        }
                        models_data["counts"] = {
                            "fast": fast_counts,
                            "expert": expert_counts,
                            "imageGen": imagegen_counts,
                        }

                        # 重置所有模型的状态
                        for model, model_data in models_data.items():
                            if isinstance(model_data, dict) and not model.startswith("__"):
                                model_data["isExpired"] = False
                                model_data["isValid"] = True  # 重置为有效状态
                                model_data["failed_request_count"] = 0
                                model_data["last_failure_time"] = None
                                model_data["last_failure_reason"] = None

                        updated += 1
                    except Exception as e:
                        print(f"Failed to reset quota for {sso_value}: {e}")
                        continue

                # 批量保存一次，避免频繁写入
                if updated > 0:
                    self._save_token_status()
                    print(f"Successfully reset quotas for {updated} tokens")

            return updated
        except Exception as e:
            print(f"Failed to reset all quotas: {e}")
            return 0

    def reduce_token_request_count(self, model: str, count: int) -> bool:
        """减少 token 的请求计数（用于错误恢复）。"""
        with self._lock:
            normalized_model = self._normalize_model_name(model)

            if normalized_model not in self._token_storage:
                return False

            tokens = self._token_storage[normalized_model]
            if not tokens:
                return False

            token_entry = tokens[0]
            original_count = token_entry.request_count
            token_entry.request_count = max(0, token_entry.request_count - count)
            reduction = original_count - token_entry.request_count

            try:
                sso_value = token_entry.credential.extract_sso_value()
                if (
                    sso_value in self._token_status
                    and normalized_model in self._token_status[sso_value]
                ):
                    status = self._token_status[sso_value][normalized_model]
                    status["totalRequestCount"] = max(
                        0, status["totalRequestCount"] - reduction
                    )
            except Exception as e:
                print(
                    f"Failed to update token status during reduction: {e}",
                    "TokenManager",
                )

            return True

    def _start_reset_timer(self) -> None:
        """启动两个定时器：1) 清理过期token  2) 每日重置配额。"""

        def cleanup_expired():
            while True:
                try:
                    # 每小时进行一次简单清理
                    time.sleep(3600)

                    with self._lock:
                        # 定期清理过期 token 列表
                        current_time = int(time.time() * 1000)
                        # 仅保留最近 24 小时内的过期 token
                        one_day_ms = 24 * 60 * 60 * 1000
                        self._expiredTokens = [
                            token_info for token_info in self._expiredTokens
                            if current_time - token_info[2] < one_day_ms
                        ]

                        # 配额制会自动处理 token 的可用性
                        # 无需再进行复杂的按模型重置
                        self._save_token_status()

                except Exception as e:
                    print(f"Error in cleanup timer: {e}")

        def daily_quota_reset():
            """每日美国时间凌晨重置所有 token 的配额和状态。"""
            last_reset_date = None
            
            while True:
                try:
                    # 获取美国东部时间（ET）
                    us_tz = pytz.timezone('America/New_York')
                    now_us = datetime.now(us_tz)
                    
                    current_date = now_us.date()
                    
                    # 检查是否是新的一天且当前时间在凌晨 0:00-1:00 之间
                    if (last_reset_date != current_date and 
                        now_us.hour == 0):
                        
                        print(f"[Daily Reset] 开始执行每日配额重置 (美国时间: {now_us.strftime('%Y-%m-%d %H:%M:%S')})")
                        
                        with self._lock:
                            reset_count = 0
                            skipped_count = 0
                            for sso_value, token_data in self._token_status.items():
                                if not isinstance(token_data, dict):
                                    continue
                                
                                # 跳过已标记为过期的 token
                                if token_data.get("isExpired", False):
                                    skipped_count += 1
                                    continue
                                
                                # 重置配额为 80
                                token_data["quota"] = {
                                    "windowSizeSeconds": None,
                                    "totalTokens": 80,
                                    "remainingTokens": 80,
                                    "updatedAt": int(time.time() * 1000),
                                }
                                
                                # 重置计数
                                token_data["counts"] = {
                                    "fast": 80,
                                    "expert": 20,
                                    "imageGen": 20,
                                }
                                
                                # 重置有效状态（不修改 isExpired，因为已经在上面检查过了）
                                token_data["isValid"] = True
                                
                                reset_count += 1
                            
                            # 保存状态
                            self._save_token_status()
                            
                            print(f"[Daily Reset] 成功重置 {reset_count} 个 token 的配额，跳过 {skipped_count} 个已过期的 token")
                            last_reset_date = current_date
                    
                    # 每 30 分钟检查一次
                    time.sleep(1800)
                    
                except Exception as e:
                    print(f"[Daily Reset] 每日重置出错: {e}")
                    import traceback
                    traceback.print_exc()
                    time.sleep(1800)  # 出错后等待 30 分钟再试

        # 启动清理定时器
        cleanup_thread = threading.Thread(target=cleanup_expired, daemon=True)
        cleanup_thread.start()
        
        # 启动每日重置定时器
        reset_thread = threading.Thread(target=daily_quota_reset, daemon=True)
        reset_thread.start()
        
        self._reset_timer_started = True
        print("[Timer] 已启动定时器：1) 每小时清理过期token  2) 每日美国时间凌晨重置配额")

    def delete_token(self, token_string: str) -> bool:
        """从系统中彻底删除 token。"""
        with self._lock:
            try:
                removed = False
                credential = TokenCredential(token_string, TokenType.NORMAL)
                sso_value = credential.extract_sso_value()

                for model in self._token_storage:
                    tokens = self._token_storage[model]
                    original_length = len(tokens)
                    self._token_storage[model] = [
                        entry
                        for entry in tokens
                        if entry.credential.sso_token != token_string
                    ]
                    if len(self._token_storage[model]) < original_length:
                        removed = True

                if sso_value in self._token_status:
                    del self._token_status[sso_value]

                self._expiredTokens = [
                    token_info
                    for token_info in self._expiredTokens
                    if token_info[0] != token_string
                ]

                if removed:
                    self._save_token_status()
                    print(f"Token deleted successfully")

                return removed

            except Exception as e:
                print(f"Failed to delete token: {e}")
                return False

    def get_all_tokens(self) -> List[str]:
        """获取系统中的全部 token 字符串。"""
        with self._lock:
            all_tokens = set()
            for tokens in self._token_storage.values():
                for entry in tokens:
                    all_tokens.add(entry.credential.sso_token)
            return list(all_tokens)

    def get_token_status_map(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """获取完整的 token 状态映射。"""
        with self._lock:
            return dict(self._token_status)

    def get_token_health_summary(self) -> Dict[str, Any]:
        """按配额逻辑汇总各模型的 token 健康状态。"""
        with self._lock:
            summary = {
                "total_tokens": 0,
                "healthyTokens": 0,
                "expiredTokens": 0,
                "rateLimitedTokens": 0,
                "lowQuotaTokens": 0,  # 新增：低额度token数量
                "tokensWithFailures": 0,
                "totalFailures": 0,
                "byModel": {},
            }

            unique_tokens = set()
            token_health_status = {}

            for sso_value, token_data in self._token_status.items():
                unique_tokens.add(sso_value)

                # 确保结构为有效的字典
                if not isinstance(token_data, dict):
                    print(f"Invalid token data structure for health summary: {sso_value}")
                    continue

                isExpired = token_data.get("isExpired", False)
                isValid = token_data.get("isValid", True)
                isLowQuota = False
                hasFailures = False
                totalTokenFailures = 0

                # 检查配额状态
                quota_data = token_data.get("quota", {})
                if isinstance(quota_data, dict):
                    remaining_tokens = quota_data.get("remainingTokens", 0)
                    if remaining_tokens < 4:  # 少于4积分无法使用专家模式
                        isLowQuota = True

                # 检查模型失败统计
                model_stats = token_data.get("modelStats", {})
                if isinstance(model_stats, dict):
                    for model, stats in model_stats.items():
                        if isinstance(stats, dict):
                            failure_count = stats.get("failureCount", 0)
                            if failure_count > 0:
                                hasFailures = True
                                totalTokenFailures += failure_count

                            # 汇总到 byModel 统计
                            if model not in summary["byModel"]:
                                summary["byModel"][model] = {
                                    "total": 0,
                                    "healthy": 0,
                                    "expired": 0,
                                    "rateLimited": 0,
                                    "lowQuota": 0,
                                    "withFailures": 0,
                                }

                            summary["byModel"][model]["total"] += 1

                            if isExpired:
                                summary["byModel"][model]["expired"] += 1
                            elif isLowQuota:
                                summary["byModel"][model]["lowQuota"] += 1
                            elif not isValid:
                                summary["byModel"][model]["rateLimited"] += 1
                            else:
                                summary["byModel"][model]["healthy"] += 1

                            if failure_count > 0:
                                summary["byModel"][model]["withFailures"] += 1

                token_health_status[sso_value] = {
                    "isExpired": isExpired,
                    "isRateLimited": not isValid and not isExpired,
                    "isLowQuota": isLowQuota,
                    "hasFailures": hasFailures,
                    "totalFailures": totalTokenFailures,
                }

            summary["total_tokens"] = len(unique_tokens)

            for sso_value in unique_tokens:
                status = token_health_status[sso_value]

                if status["isExpired"]:
                    summary["expiredTokens"] += 1
                elif status["isLowQuota"]:
                    summary["lowQuotaTokens"] += 1
                elif status["isRateLimited"]:
                    summary["rateLimitedTokens"] += 1
                else:
                    summary["healthyTokens"] += 1

                if status["hasFailures"]:
                    summary["tokensWithFailures"] += 1
                    summary["totalFailures"] += status["totalFailures"]

            return summary

    # --- 新的配额记账（积分制） ---
    def _ensure_token_bucket(self, sso_value: str) -> None:
        """确保状态映射中存在该 token 的存储桶。"""
        if sso_value not in self._token_status:
            self._token_status[sso_value] = {}

    def update_token_quota(
        self,
        token_string: str,
        remaining_tokens: int,
        total_tokens: int,
        window_size_seconds: Optional[int] = None,
    ) -> None:
        """更新 token 的共享配额与派生计数。

        - remaining_tokens：上游权威的剩余积分
        - total_tokens：总积分（未知时默认 80）
        - window_size_seconds：上游窗口（可选）

        更新字段：
        - quota.remainingTokens：剩余积分
        - quota.totalTokens：总积分
        - counts：各模式可用次数（便于快速访问）
        """
        try:
            print(f"update_token_quota called with: remaining={remaining_tokens}, total={total_tokens}, window={window_size_seconds}")
            with self._lock:
                credential = TokenCredential(token_string, TokenType.NORMAL)
                sso_value = credential.extract_sso_value()
                print(f"Updating token quota for sso: {sso_value[:20]}...")
                self._ensure_token_bucket(sso_value)

                if sso_value not in self._token_status:
                    print(f"Token {sso_value[:20]}... not found in token_status")
                    return False

                models_data = self._token_status[sso_value]
                quota = models_data.get("quota", {})
                print(f"Current quota before update: {quota}")
                cur_total = int(quota.get("totalTokens", 80) or 80)
                new_total = int(total_tokens) if total_tokens is not None else cur_total
                new_remaining = (
                    int(remaining_tokens)
                    if remaining_tokens is not None
                    else new_total
                )
                new_remaining = max(0, new_remaining)

                # 计算各模式可用次数
                fast_counts = int(math.floor(new_remaining / 1))
                expert_counts = int(math.floor(new_remaining / 4))
                imagegen_counts = int(math.floor(new_remaining / 4))

                models_data["quota"] = {
                    "windowSizeSeconds": quota.get("windowSizeSeconds"),
                    "totalTokens": new_total,
                    "remainingTokens": new_remaining,
                    "updatedAt": int(time.time() * 1000),
                }

                models_data["counts"] = {
                    "fast": fast_counts,
                    "expert": expert_counts,
                    "imageGen": imagegen_counts,
                }

                self._save_token_status()
                return True

        except Exception as e:
            print(f"Failed to update token quota: {e}")
            return False

    def record_model_usage(
        self,
        token_string: str,
        model_name: str,
        success: bool = True,
        error_response: Optional[str] = None
    ) -> None:
        """记录模型使用统计（字段使用 camelCase）。

        记录项：
        - lastCallTime：最后一次调用时间
        - requestCount：请求次数
        - failureCount：失败次数
        - lastFailureTime：最后一次失败时间
        - lastFailureResponse：最后一次失败响应
        """
        try:
            with self._lock:
                credential = TokenCredential(token_string, TokenType.NORMAL)
                sso_value = credential.extract_sso_value()
                self._ensure_token_bucket(sso_value)

                # 确保 modelStats 存在
                if "modelStats" not in self._token_status[sso_value]:
                    self._token_status[sso_value]["modelStats"] = {}
                    for model_type in ModelType:
                        self._token_status[sso_value]["modelStats"][model_type.value] = {
                            "lastCallTime": None,
                            "requestCount": 0,
                            "failureCount": 0,
                            "lastFailureTime": None,
                            "lastFailureResponse": None
                        }

                model_stats = self._token_status[sso_value]["modelStats"]
                if model_name not in model_stats:
                    model_stats[model_name] = {
                        "lastCallTime": None,
                        "requestCount": 0,
                        "failureCount": 0,
                        "lastFailureTime": None,
                        "lastFailureResponse": None
                    }

                # 更新统计数据
                current_time = int(time.time() * 1000)
                model_stats[model_name]["lastCallTime"] = current_time
                model_stats[model_name]["requestCount"] += 1

                if not success:
                    model_stats[model_name]["failureCount"] += 1
                    model_stats[model_name]["lastFailureTime"] = current_time
                    if error_response:
                        model_stats[model_name]["lastFailureResponse"] = error_response

                self._save_token_status()

        except Exception as e:
            print(f"Failed to record model usage: {e}")

    def update_token_quota(
        self,
        token_string: str,
        remaining_tokens: int,
        total_tokens: int,
        window_size_seconds: Optional[int] = None,
    ) -> None:
        """更新 token 的共享配额与派生计数。

        数据结构（camelCase）：
        - quota：配额信息
        - counts：派生统计
        - modelStats：各模型的使用统计
        """
        try:
            with self._lock:
                credential = TokenCredential(token_string, TokenType.NORMAL)
                sso_value = credential.extract_sso_value()
                self._ensure_token_bucket(sso_value)

                # Costs: expert/imageGen=4, others=1
                remaining = max(0, int(remaining_tokens))
                total = max(0, int(total_tokens))

                # 计算各模式可用次数 - 直接固定值，不计算
                fast_counts = 80 if remaining >= 80 else remaining
                expert_counts = 20 if remaining >= 80 else max(0, int(remaining // 4))
                imagegen_counts = 20 if remaining >= 80 else max(0, int(remaining // 4))

                self._token_status[sso_value]["quota"] = {
                    "windowSizeSeconds": int(window_size_seconds)
                    if window_size_seconds is not None
                    else None,
                    "totalTokens": total,
                    "remainingTokens": remaining,
                    "updatedAt": int(time.time() * 1000),
                }

                self._token_status[sso_value]["counts"] = {
                    "fast": fast_counts,
                    "expert": expert_counts,
                    "imageGen": imagegen_counts,
                }

                # 初始化 modelStats（如果不存在）
                if "modelStats" not in self._token_status[sso_value]:
                    self._token_status[sso_value]["modelStats"] = {}
                    # 为每个ModelType初始化统计
                    for model_type in ModelType:
                        self._token_status[sso_value]["modelStats"][model_type.value] = {
                            "lastCallTime": None,
                            "requestCount": 0,
                            "failureCount": 0,
                            "lastFailureTime": None,
                            "lastFailureResponse": None
                        }

                # 更新token有效状态：积分少于4则无法使用专家模式和绘图模式
                for model, model_data in self._token_status[sso_value].items():
                    if isinstance(model_data, dict) and model not in ["quota", "counts", "modelStats"]:
                        # 新的isValid逻辑：除了原来的429限制外，还要检查积分
                        current_isExpired = model_data.get("isExpired", False)
                        if not current_isExpired:  # 只有未过期的token才检查积分
                            if remaining < 4:
                                model_data["isValid"] = False

                self._save_token_status()
        except Exception as e:
            print(f"Failed to update token quota: {e}")


@dataclass
class ImageTypeInfo:
    """图片类型信息。"""

    mime_type: str
    file_name: str
    extension: str


class ImageProcessor:
    """处理图片与类型识别。"""

    IMAGE_SIGNATURES = {
        b"\xff\xd8\xff": ("jpg", "image/jpeg"),
        b"\x89PNG\r\n\x1a\n": ("png", "image/png"),
        b"GIF89a": ("gif", "image/gif"),
        b"GIF87a": ("gif", "image/gif"),
    }

    @classmethod
    def is_base64_image(cls, s: str) -> bool:
        """通过二进制特征判断是否为合法的 base64 图片。"""
        try:
            decoded = base64.b64decode(s, validate=True)
            return any(decoded.startswith(sig) for sig in cls.IMAGE_SIGNATURES)
        except Exception:
            return False

    @classmethod
    def get_extension_and_mime_from_header(cls, data: bytes) -> tuple:
        """从二进制头部检测图片格式。"""
        for sig, (ext, mime) in cls.IMAGE_SIGNATURES.items():
            if data.startswith(sig):
                return ext, mime
        return "jpg", "image/jpeg"

    @classmethod
    def get_image_type_info(cls, base64_string: str) -> ImageTypeInfo:
        """基于二进制签名增强的图片类型识别。"""
        mime_type = "image/jpeg"
        extension = "jpg"

        if "data:image" in base64_string:
            matches = re.search(
                r"data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,", base64_string
            )
            if matches:
                mime_type = matches.group(1)
                extension = mime_type.split("/")[1]
        else:
            try:
                image_data = base64.b64decode(base64_string, validate=True)
                extension, mime_type = cls.get_extension_and_mime_from_header(
                    image_data
                )
            except Exception:
                pass

        file_name = f"image.{extension}"
        return ImageTypeInfo(mime_type, file_name, extension)


class FileUploadManager:
    """负责文件/图片上传。"""

    def __init__(
        self, config: ConfigurationManager, token_manager: ThreadSafeTokenManager
    ):
        """初始化上传管理器。"""
        self.config = config
        self.token_manager = token_manager

    def upload_text_file(self, content: str, model: str) -> str:
        """将文本内容作为附件上传。"""
        try:
            content_base64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
            upload_data = {
                "fileName": "message.txt",
                "fileMimeType": "text/plain",
                "content": content_base64,
            }

            print("Uploading text file")

            auth_token = self.token_manager.get_token_for_model(model)
            if not auth_token:
                raise TokenException(f"No available tokens for model: {model}")

            cf_clearance = self.config.get("SERVER.CF_CLEARANCE", "")
            cookie = build_cookie(auth_token, cf_clearance)

            # 优先使用静态 PROXY；否则在可用时使用动态代理
            dynamic_api = self.config.get("API.DYNAMIC_PROXY_API")
            proxy_url = self.config.get("API.PROXY")
            if not proxy_url and dynamic_api:
                proxy_manager = get_proxy_manager(self.config)
                proxy_url = proxy_manager.get_working_proxy()
            proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)

            attempts = 1
            max_attempts = int(self.config.get("API.PROXY_RETRY_LIMIT", 20)) if dynamic_api else 1
            last_exc: Optional[Exception] = None

            while attempts <= max_attempts:
                try:
                    response = curl_requests.post(
                        "https://grok.com/rest/app-chat/upload-file",
                        headers={
                            **get_dynamic_headers(
                                "POST", "/rest/app-chat/upload-file", self.config
                            ),
                            "Cookie": cookie,
                        },
                        json=upload_data,
                        impersonate="chrome133a",
                        timeout=60,
                        **proxy_config,
                    )

                    if response.status_code in (403, 503) and dynamic_api and not self.config.get("API.PROXY"):
                        cf_mitigated = response.headers.get("cf-mitigated", "").lower()
                        body_preview = ""
                        try:
                            body_preview = response.text[:600]
                        except Exception:
                            pass
                        is_cf = (
                            cf_mitigated == "challenge"
                            or ("just a moment" in body_preview.lower() or "__cf_chl_" in body_preview.lower())
                        )
                        if is_cf:
                            print("Detected CF challenge during file upload; rotating proxy", "DynamicProxy")
                            proxy_manager.invalidate_current(proxy_url)
                            proxy_url = proxy_manager.get_working_proxy()
                            proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)
                            attempts += 1
                            continue

                    break
                except Exception as e:
                    last_exc = e
                    if dynamic_api and not self.config.get("API.PROXY"):
                        proxy_manager.invalidate_current(proxy_url)
                        proxy_url = proxy_manager.get_working_proxy()
                        proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)
                        attempts += 1
                        continue
                    else:
                        raise

            if response.status_code != 200:
                raise GrokApiException(
                    f"File upload failed with status: {response.status_code}",
                    "UPLOAD_FAILED",
                )

            result = response.json()
            file_metadata_id = result.get("fileMetadataId", "")

            if not file_metadata_id:
                raise GrokApiException(
                    "No file metadata ID in response", "INVALID_RESPONSE"
                )

            print(f"Text file uploaded successfully: {file_metadata_id}", "FileUpload")
            return file_metadata_id

        except Exception as error:
            print(f"Text file upload failed: {error}")
            raise GrokApiException(
                f"Text file upload failed: {error}", "UPLOAD_ERROR"
            ) from error

    def upload_image(self, image_data: str, model: str) -> str:
        """上传图片（支持增强的格式识别）。"""
        try:
            if "data:image" in image_data:
                image_buffer = image_data.split(",")[1]
            else:
                image_buffer = image_data

            image_info = ImageProcessor.get_image_type_info(image_data)

            upload_data = {
                "fileName": image_info.file_name,
                "fileMimeType": image_info.mime_type,
                "content": image_buffer,
            }

            print("Uploading image file")

            auth_token = self.token_manager.get_token_for_model(model)
            if not auth_token:
                raise TokenException(f"No available tokens for model: {model}")

            cf_clearance = self.config.get("SERVER.CF_CLEARANCE", "")
            cookie = build_cookie(auth_token, cf_clearance)

            # 优先使用静态 PROXY；否则在可用时使用动态代理
            dynamic_api = self.config.get("API.DYNAMIC_PROXY_API")
            proxy_url = self.config.get("API.PROXY")
            if not proxy_url and dynamic_api:
                proxy_manager = get_proxy_manager(self.config)
                proxy_url = proxy_manager.get_working_proxy()
            proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)

            attempts = 1
            max_attempts = int(self.config.get("API.PROXY_RETRY_LIMIT", 20)) if dynamic_api else 1
            last_exc: Optional[Exception] = None

            while attempts <= max_attempts:
                try:
                    response = curl_requests.post(
                        "https://grok.com/rest/app-chat/upload-file",
                        headers={
                            **get_dynamic_headers(
                                "POST", "/rest/app-chat/upload-file", self.config
                            ),
                            "Cookie": cookie,
                        },
                        json=upload_data,
                        impersonate="chrome133a",
                        timeout=60,
                        **proxy_config,
                    )

                    if response.status_code in (403, 503) and dynamic_api and not self.config.get("API.PROXY"):
                        cf_mitigated = response.headers.get("cf-mitigated", "").lower()
                        body_preview = ""
                        try:
                            body_preview = response.text[:600]
                        except Exception:
                            pass
                        is_cf = (
                            cf_mitigated == "challenge"
                            or ("just a moment" in body_preview.lower() or "__cf_chl_" in body_preview.lower())
                        )
                        if is_cf:
                            print("Detected CF challenge during image upload; rotating proxy", "DynamicProxy")
                            proxy_manager.invalidate_current(proxy_url)
                            proxy_url = proxy_manager.get_working_proxy()
                            proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)
                            attempts += 1
                            continue

                    break
                except Exception as e:
                    last_exc = e
                    if dynamic_api and not self.config.get("API.PROXY"):
                        proxy_manager.invalidate_current(proxy_url)
                        proxy_url = proxy_manager.get_working_proxy()
                        proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)
                        attempts += 1
                        continue
                    else:
                        raise

            if response.status_code != 200:
                print(
                    f"Image upload failed with status: {response.status_code}",
                    "ImageUpload",
                )
                return ""

            result = response.json()
            file_metadata_id = result.get("fileMetadataId", "")

            if file_metadata_id:
                print(f"Image uploaded successfully: {file_metadata_id}", "ImageUpload")

            return file_metadata_id

        except Exception as error:
            print(f"Image upload failed: {error}")
            return ""


@dataclass
class ProcessedMessage:
    """消息处理结果。"""

    content: str
    file_attachments: List[str]
    requires_file_upload: bool
    upload_content: str = ""


class MessageContentProcessor:
    """处理消息内容并支持复杂格式。"""

    def __init__(self, file_upload_manager: FileUploadManager):
        """初始化消息处理器。"""
        self.file_upload_manager = file_upload_manager

    def remove_think_tags_and_images(self, text: str) -> str:
        """移除 <think> 标签与 base64 图片占位。"""
        text = re.sub(r"<think>[\s\S]*?<\/think>", "", text).strip()
        text = re.sub(r"!\[image\]\(data:.*?base64,.*?\)", "[图片]", text)
        return text

    def process_content_item(self, content_item: Any) -> str:
        """处理单个内容项（文本或图片）。"""
        if isinstance(content_item, list):
            text_parts = []
            for item in content_item:
                if isinstance(item, dict):
                    if item.get("type") == "image_url":
                        text_parts.append("[图片]")
                    elif item.get("type") == "text":
                        text_parts.append(
                            self.remove_think_tags_and_images(item.get("text", ""))
                        )
            return "\n".join(filter(None, text_parts))

        elif isinstance(content_item, dict):
            if content_item.get("type") == "image_url":
                return "[图片]"
            elif content_item.get("type") == "text":
                return self.remove_think_tags_and_images(content_item.get("text", ""))

        elif isinstance(content_item, str):
            return self.remove_think_tags_and_images(content_item)

        return ""

    def extract_image_attachments(self, content_item: Any, model: str) -> List[str]:
        """提取并上传图片附件。"""
        attachments = []

        if isinstance(content_item, list):
            for item in content_item:
                if isinstance(item, dict) and item.get("type") == "image_url":
                    image_url = item.get("image_url", {}).get("url", "")
                    if image_url:
                        file_id = self.file_upload_manager.upload_image(
                            image_url, model
                        )
                        if file_id:
                            attachments.append(file_id)

        elif isinstance(content_item, dict) and content_item.get("type") == "image_url":
            image_url = content_item.get("image_url", {}).get("url", "")
            if image_url:
                file_id = self.file_upload_manager.upload_image(image_url, model)
                if file_id:
                    attachments.append(file_id)

        return attachments

    def process_messages(
        self, messages: List[Dict[str, Any]], model: str
    ) -> ProcessedMessage:
        """将多条消息整理为一个格式化字符串。"""
        formatted_messages = ""
        all_file_attachments = []
        message_length = 0
        requires_file_upload = False
        last_role = None
        last_content = ""

        for message in messages:
            role = "assistant" if message.get("role") == "assistant" else "user"
            is_last_message = message == messages[-1]

            if is_last_message and "content" in message:
                image_attachments = self.extract_image_attachments(
                    message["content"], model
                )
                all_file_attachments.extend(image_attachments)

            text_content = self.process_content_item(message.get("content", ""))

            if text_content or (is_last_message and all_file_attachments):
                if role == last_role and text_content:
                    last_content += "\n" + text_content
                    role_header = f"{role.upper()}: "
                    last_index = formatted_messages.rindex(role_header)
                    formatted_messages = (
                        formatted_messages[:last_index]
                        + f"{role_header}{last_content}\n"
                    )
                else:
                    content_to_add = text_content or "[图片]"
                    formatted_messages += f"{role.upper()}: {content_to_add}\n"
                    last_content = text_content
                    last_role = role

            message_length += len(formatted_messages)

            if message_length >= MESSAGE_LENGTH_LIMIT:
                requires_file_upload = True

        if requires_file_upload:
            last_message = messages[-1] if messages else {}
            last_role = (
                "assistant" if last_message.get("role") == "assistant" else "user"
            )
            last_text = self.process_content_item(last_message.get("content", ""))

            final_content = f"{last_role.upper()}: {last_text or '[图片]'}"

            try:
                file_id = self.file_upload_manager.upload_text_file(
                    formatted_messages, model
                )
                if file_id:
                    all_file_attachments.insert(0, file_id)
                    formatted_messages = "基于txt文件内容进行回复："
            except Exception as e:
                print(f"Failed to upload conversation file: {e}", "MessageProcessor")
                formatted_messages = final_content

        if not formatted_messages.strip():
            if requires_file_upload:
                formatted_messages = "基于txt文件内容进行回复："
            else:
                raise ValidationException("Message content is empty after processing")

        return ProcessedMessage(
            content=formatted_messages.strip(),
            file_attachments=all_file_attachments[:MAX_FILE_ATTACHMENTS],
            requires_file_upload=requires_file_upload,
        )


@dataclass
class ChatRequestConfig:
    """聊天请求配置。"""

    model_name: str
    message: str
    file_attachments: List[str]
    enable_search: bool
    enable_image_generation: bool
    temporary_conversation: bool
    expert_mode: bool
    custom_personality: str = ""


class GrokApiClient:
    """职责清晰的 Grok API 客户端。"""

    def __init__(
        self, config: ConfigurationManager, token_manager: ThreadSafeTokenManager
    ):
        """初始化客户端。"""
        self.config = config
        self.token_manager = token_manager
        self.file_upload_manager = FileUploadManager(config, token_manager)
        self.message_processor = MessageContentProcessor(self.file_upload_manager)

    def validate_model_and_request(
        self, model: str, request_data: Dict[str, Any]
    ) -> str:
        """校验模型与请求参数。"""
        if model not in self.config.models:
            raise ValidationException(f"Unsupported model: {model}")

        return self.config.models[model]

    def determine_search_and_generation_settings(self, model: str) -> tuple:
        """依据模型确定搜索/生成功能开关。"""
        # 仅 grok-3-search 打开网页搜索
        enable_search = model not in ["grok-3", "grok-4-imageGen", "grok-3-imageGen"]
        enable_image_generation = model in ["grok-4-imageGen", "grok-3-imageGen"]

        return (enable_search, enable_image_generation)

    def validate_message_requirements(
        self, model: str, messages: List[Dict[str, Any]]
    ) -> None:
        """校验特定模型的消息要求。"""
        if model in ["grok-4-imageGen", "grok-3-imageGen"]:
            if not messages:
                raise ValidationException("Messages cannot be empty")

            last_message = messages[-1]
            if last_message.get("role") != "user":
                raise ValidationException(
                    f"Model {model} requires the last message to be from user"
                )

    def prepare_chat_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """准备聊天请求（职责分离）。"""
        try:
            model = str(request_data.get("model"))
            messages = request_data.get("messages", [])

            normalized_model = self.validate_model_and_request(model, request_data)

            self.validate_message_requirements(model, messages)

            (
                enable_search,
                enable_image_generation,
            ) = self.determine_search_and_generation_settings(model)

            # 仅当模型名以 -expert 结尾时启用专家模式
            expert_mode = model.endswith("-expert")

            # 将 system 消息提取为 customPersonality，并从对话消息中移除
            system_parts: List[str] = []
            messages_no_system: List[Dict[str, Any]] = []
            for msg in messages:
                if msg.get("role") == "system":
                    sys_text = self.message_processor.process_content_item(msg.get("content", ""))
                    if sys_text:
                        system_parts.append(sys_text)
                else:
                    messages_no_system.append(msg)

            if model in ["grok-4-imageGen", "grok-3-imageGen"]:
                messages_to_process = [messages_no_system[-1]] if messages_no_system else []
            else:
                messages_to_process = messages_no_system

            processed_message = self.message_processor.process_messages(messages_to_process, model)

            request_config = ChatRequestConfig(
                model_name=normalized_model,
                message=processed_message.content,
                file_attachments=processed_message.file_attachments,
                enable_search=enable_search,
                enable_image_generation=enable_image_generation,
                temporary_conversation=self.config.get(
                    "API.IS_TEMP_CONVERSATION", False
                ),
                expert_mode=expert_mode,
                custom_personality="\n".join(system_parts).strip(),
            )

            return self.build_request_payload(request_config)

        except Exception as e:
            print(f"Failed to prepare chat request: {e}")
            raise

    def build_request_payload(self, config: ChatRequestConfig) -> Dict[str, Any]:
        """构建最终请求负载。"""

        model_mode = "MODEL_MODE_EXPERT" if config.expert_mode else "MODEL_MODE_AUTO"

        payload = {
            "temporary": config.temporary_conversation,
            "modelName": config.model_name,
            "message": config.message,
            "fileAttachments": config.file_attachments,
            "imageAttachments": [],
            "disableSearch": not config.enable_search,
            "enableImageGeneration": config.enable_image_generation,
            "returnImageBytes": False,
            "returnRawGrokInXaiRequest": False,
            "enableImageStreaming": False,
            "imageGenerationCount": 1,
            "forceConcise": False,
            "toolOverrides": {},
            "enableSideBySide": True,
            "sendFinalMetadata": True,
            "webpageUrls": [],
            "disableTextFollowUps": True,
            "responseMetadata": {"requestModelDetails": {"modelId": config.model_name}},
            "disableMemory": False,
            "forceSideBySide": False,
            "modelMode": model_mode,
            "isAsyncChat": False,
        }

        # 如提供了自定义人格（系统提示），则附加到请求中
        if config.custom_personality:
            payload["customPersonality"] = config.custom_personality

        return payload

    def make_request(
        self, payload: Dict[str, Any], model: str, stream: bool = False
    ) -> Tuple[requests.Response, str, Optional[str]]:
        """调用 Grok API 并返回响应，同时返回使用的 token。"""
        auth_token = self.token_manager.get_token_for_model(model)
        if not auth_token:
            token_count = self.token_manager.get_token_count_for_model(model)
            if token_count == 0:
                raise TokenException(
                    f"No tokens available for model: {model}. Please add tokens or check configuration."
                )
            else:
                raise TokenException(
                    f"All tokens for model {model} are currently rate limited. Please try again later."
                )

        cf_clearance = self.config.get("SERVER.CF_CLEARANCE", "")
        cookie = build_cookie(auth_token, cf_clearance)

        # 选择代理：若配置了静态 PROXY 优先；否则使用动态代理
        dynamic_api = self.config.get("API.DYNAMIC_PROXY_API")
        proxy_url = self.config.get("API.PROXY")
        if not proxy_url and dynamic_api:
            proxy_manager = get_proxy_manager(self.config)
            proxy_url = proxy_manager.get_working_proxy()

        proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)

        print(f"Making request to Grok API for model: {model}")

        # 发起请求：若使用动态代理且遇到 CF 挑战/网络异常，则失效当前代理并在上限内重试
        attempts = 1
        max_attempts = int(self.config.get("API.PROXY_RETRY_LIMIT", 20)) if dynamic_api else 1

        last_exc: Optional[Exception] = None
        while attempts <= max_attempts:
            try:
                # 流式请求使用更长超时，避免上游缓慢导致的低速中止
                request_timeout = self.config.get("API.STREAM_TIMEOUT", 600) if stream else self.config.get("API.REQUEST_TIMEOUT", 120)
                response = curl_requests.post(
                    f"{self.config.get('API.BASE_URL')}/rest/app-chat/conversations/new",
                    headers={
                        **get_dynamic_headers(
                            "POST", "/rest/app-chat/conversations/new", self.config
                        ),
                        "Cookie": cookie,
                    },
                    data=json.dumps(payload),
                    impersonate="chrome133a",
                    # 始终以流式方式请求上游，便于逐行解析（即便外层为非流式模式）
                    stream=True,
                    timeout=request_timeout,
                    **proxy_config,
                )

                print(f"Response status: {response.status_code}")

                # 仅基于响应头判断 CF 挑战；仅在动态代理（未配置静态 PROXY）时进行代理轮换
                if dynamic_api and not self.config.get("API.PROXY") and response.status_code in (403, 503):
                    cf_mitigated = response.headers.get("cf-mitigated", "").lower()
                    if cf_mitigated == "challenge":
                        print("Detected CF challenge via headers; rotating proxy", "DynamicProxy")
                        proxy_manager.invalidate_current(proxy_url)
                        proxy_url = proxy_manager.get_working_proxy()
                        proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)
                        attempts += 1
                        continue

                return response, auth_token, proxy_url  # type: ignore

            except Exception as e:
                print(f"HTTP request failed (attempt {attempts}/{max_attempts}): {e}")
                last_exc = e
                if dynamic_api and not self.config.get("API.PROXY"):
                    # 使当前代理失效并重试
                    try:
                        proxy_manager.invalidate_current(proxy_url)
                    except Exception:
                        pass
                    proxy_url = proxy_manager.get_working_proxy()
                    proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)
                    attempts += 1
                    continue
                else:
                    # 未配置动态代理：快速失败
                    raise GrokApiException(
                        f"HTTP request failed: {e}", "REQUEST_FAILED"
                    ) from e

        # 尝试次数已耗尽
        raise GrokApiException(
            f"All proxy attempts exhausted ({max_attempts}). Last error: {last_exc}",
            "PROXY_EXHAUSTED",
        )


@dataclass
class ProcessingResult:
    """模型响应处理结果。"""

    token: Optional[str] = None
    image_url: Optional[str] = None
    new_state: Optional[ProcessingState] = None
    should_skip: bool = False


class ModelResponseProcessor:
    """无状态的响应处理器，适配不同模型类型。"""

    def __init__(self, config: ConfigurationManager):
        """初始化处理器。"""
        self.config = config

    def process_response(
        self, response_data: Dict[str, Any], model: str, current_state: ProcessingState
    ) -> ProcessingResult:
        """按模型类型与当前状态处理响应。"""
        try:
            streaming_image_response = response_data.get(
                "streamingImageGenerationResponse"
            )
            if streaming_image_response:
                progress = streaming_image_response.get("progress", 0)
                image_url = streaming_image_response.get("imageUrl")

                if progress == 100 and image_url:
                    new_state = current_state.with_image_generation(True, 1)
                    return ProcessingResult(image_url=image_url, new_state=new_state)
                else:
                    new_state = current_state.with_image_generation(True)
                    return ProcessingResult(new_state=new_state)

            if response_data.get("doImgGen") or response_data.get(
                "imageAttachmentInfo"
            ):
                new_state = current_state.with_image_generation(True)
                return ProcessingResult(new_state=new_state)

            if current_state.is_generating_image:
                cached_response = response_data.get("cachedImageGenerationResponse")
                if cached_response and not current_state.image_generation_phase:
                    image_url = cached_response.get("imageUrl")
                    if image_url:
                        new_state = current_state.with_image_generation(True, 1)
                        return ProcessingResult(
                            image_url=image_url, new_state=new_state
                        )

            model_response = response_data.get("modelResponse")
            if model_response:
                generated_image_urls = model_response.get("generatedImageUrls", [])
                if generated_image_urls and not current_state.image_generation_phase:
                    image_url = generated_image_urls[0]
                    new_state = current_state.with_image_generation(True, 1)
                    return ProcessingResult(image_url=image_url, new_state=new_state)

            # 所有模型统一使用 Grok 的处理方式
            return self._process_grok_response(response_data, current_state)

        except Exception as e:
            print(f"Error processing {model} response: {e}", "ResponseProcessor")
            token = response_data.get("token")
            processed_token = self._transform_artifacts(token) if token else None
            return ProcessingResult(token=processed_token)

    
    def _process_grok_response(
        self, response_data: Dict[str, Any], current_state: ProcessingState
    ) -> ProcessingResult:
        """统一的 Grok 模型响应处理（适用于 grok-3、grok-4 及所有变体）：
        - 只要 isThinking 为真或携带 webSearchResults，就视为处于 <think> 阶段；
        - 第一次关闭 </think> 之后，后续的思考/搜索内容一律忽略；
        - 通过 SHOW_THINKING 配置控制是否展示思考内容。"""
        show_thinking = self.config.get("SHOW_THINKING", False)
        is_thinking = bool(response_data.get("isThinking", False))
        has_search = bool(response_data.get("webSearchResults"))
        
        # 有搜索结果且允许展示思考时，渲染为 Markdown
        search_md: str = ""
        if has_search and show_thinking:
            try:
                search_md = UtilityFunctions.organize_search_results(
                    response_data.get("webSearchResults", {})
                ) or ""
            except Exception:
                search_md = ""

        # 只要满足任一条件（isThinking 或 has_search）即判定为 <think> 帧
        frame_is_think = is_thinking or has_search

        # 如果已经输出过第一个 </think>，忽略后续所有思考/搜索帧
        if current_state.is_thinking_end and frame_is_think:
            return ProcessingResult(should_skip=True, new_state=current_state)

        # SHOW_THINKING 关闭时，跳过所有思考相关输出
        if frame_is_think and not show_thinking:
            return ProcessingResult(should_skip=True, new_state=current_state)

        # 组装正文：token 文本 +（可选）搜索结果
        # 注意：为保留最终 Markdown 格式，这里不要清洗 token 文本
        token_text = response_data.get("token", "") or ""
        inner = token_text
        if search_md:
            if inner and not inner.endswith("\n"):
                inner += "\n"
            inner += search_md

        # 需要时打开 <think>
        if frame_is_think and not current_state.is_thinking:
            out = "<think>" + inner
            processed = self._transform_artifacts(out)
            return ProcessingResult(token=processed, new_state=current_state.with_thinking(True))

        # 处于 <think> 中，直接追加内容
        if frame_is_think and current_state.is_thinking:
            processed = self._transform_artifacts(inner)
            return ProcessingResult(token=processed, new_state=current_state)

        # 离开 <think> 时关闭；若本分片内容为空则仅保持状态，不输出
        if (not frame_is_think) and current_state.is_thinking:
            if (token_text or "") == "":
                return ProcessingResult(should_skip=True, new_state=current_state)
            out = "</think>" + token_text
            processed = self._transform_artifacts(out)
            return ProcessingResult(
                token=processed,
                new_state=current_state.with_thinking(False).with_thinking_end(True),
            )

        # 其他情况：直接透传当前 token
        processed = self._transform_artifacts(token_text) if token_text else None
        return ProcessingResult(token=processed, new_state=current_state)

    

    def _transform_artifacts(self, text: Any) -> str:
        """构件转换在流式层处理；此处原样返回。"""
        if not text:
            return ""

        return str(text) if not isinstance(text, str) else text


class ResponseImageHandler:
    """处理图像响应：不做缓存，输出为 OpenAI 兼容格式。"""

    def __init__(self, config: ConfigurationManager):
        """初始化图像处理器。"""
        self.config = config
        self._cache = {}
        self._cache_lock = threading.Lock()
        self.max_cache_size = 1024 * 1024 * 16
        self.cache_access_order = []

    def handle_image_response(self, image_url: str, cookie: Optional[str] = None, proxy_url: Optional[str] = None) -> str:
        """处理图片响应并返回 OpenAI 兼容的格式（不使用缓存）。

        与参考应用保持一致：
        - 仅使用静态代理（不做动态轮换），避免过度刷新；
        - 若提供 Cookie，用于授权访问资源；
        - 失败前最多重试 2 次。
        """
        # 关闭缓存：始终按需拉取（不查缓存）

        max_retries = 2
        retry_count = 0
        image_data = None

        while retry_count < max_retries:
            try:
                proxy_config = UtilityFunctions.get_proxy_configuration(proxy_url)

                response = curl_requests.get(
                    f"https://assets.grok.com/{image_url}",
                    headers={
                        **get_dynamic_headers("GET", f"/assets/{image_url}", self.config),
                        **({"Cookie": cookie} if cookie else {}),
                    },
                    impersonate="chrome133a",
                    timeout=60,
                    **proxy_config,
                )
                print(f"Retrieving image: https://assets.grok.com/{image_url}")
                if response.status_code == 200:
                    image_data = response.content
                    break

                retry_count += 1
                if retry_count == max_retries:
                    raise GrokApiException(
                        f"Failed to retrieve image after {max_retries} attempts: {response.status_code}",
                        "IMAGE_RETRIEVAL_FAILED",
                    )

                time.sleep(self.config.get("API.RETRY_TIME", 1000) / 1000 * retry_count)

            except Exception as error:
                retry_count += 1
                if retry_count == max_retries:
                    print(f"Image retrieval failed: {error}")
                    raise

                time.sleep(self.config.get("API.RETRY_TIME", 1000) / 1000 * retry_count)

        if not image_data:
            raise GrokApiException("No image data retrieved", "NO_IMAGE_DATA")

        base64_image = base64.b64encode(image_data).decode("utf-8")
        content_type = "image/jpeg"
        data_url = f"data:{content_type};base64,{base64_image}"

        image_md = f"![image]({data_url})"

        # 关闭缓存：不存储结果，直接返回
        return image_md


from enum import Enum


class FilterState(Enum):
    """流式标签过滤状态机的状态。"""

    NORMAL = "normal"
    POTENTIAL_TAG = "potential_tag"
    IN_FILTERED_TAG = "in_filtered_tag"
    IN_PRESERVED_TAG = "in_preserved_tag"
    IN_CDATA = "in_cdata"
    TAG_ANALYSIS = "tag_analysis"


class TagBehavior(Enum):
    """被过滤标签的处理行为。"""

    PRESERVE_CONTENT = "preserve_content"
    REMOVE_ALL = "remove_all"


class StreamingTagFilter:
    """高性能的状态机流式过滤器：最小缓冲、各流互不影响。"""

    def __init__(
        self,
        tag_config: Dict[str, Dict[str, Any]] = {},
        content_type_mappings: Dict[str, Dict[str, str]] = {},
    ):
        """
        使用可配置的标签行为与 contentType 映射初始化过滤器。

        参数：
          - tag_config：标签到行为的映射（如 xaiartifact→保留内容，grok:render→移除）
          - content_type_mappings：contentType 与代码块包裹符的映射
        """
        self.tag_config = {}
        default_config = tag_config or {
            "xaiartifact": {"behavior": "preserve_content"},
            "grok:render": {"behavior": "remove_all"},
        }

        for tag_name, config in default_config.items():
            self.tag_config[tag_name.lower()] = {
                "behavior": TagBehavior(config.get("behavior", "preserve_content")),
                "extra_config": config.get("extra_config", {}),
            }
        self.content_type_mappings = content_type_mappings or {
            "text/plain": {"stag": "```", "etag": "```"},
            "text/markdown": {"stag": "", "etag": ""},
            "application/json": {"stag": "```json\n", "etag": "\n```"},
            "text/javascript": {"stag": "```javascript\n", "etag": "\n```"},
            "text/python": {"stag": "```python\n", "etag": "\n```"},
            "text/html": {"stag": "```html\n", "etag": "\n```"},
            "text/css": {"stag": "```css\n", "etag": "\n```"},
            "text/xml": {"stag": "```xml\n", "etag": "\n```"},
            "text/yaml": {"stag": "```yaml\n", "etag": "\n```"},
            "text/sql": {"stag": "```sql\n", "etag": "\n```"},
            "text/typescript": {"stag": "```typescript\n", "etag": "\n```"},
            "text/bash": {"stag": "```bash\n", "etag": "\n```"},
            "text/shell": {"stag": "```bash\n", "etag": "\n```"},
            "text/dockerfile": {"stag": "```dockerfile\n", "etag": "\n```"},
            "text/java": {"stag": "```java\n", "etag": "\n```"},
            "text/go": {"stag": "```go\n", "etag": "\n```"},
            "text/rust": {"stag": "```rust\n", "etag": "\n```"},
            "text/php": {"stag": "```php\n", "etag": "\n```"},
            "text/ruby": {"stag": "```ruby\n", "etag": "\n```"},
            "text/swift": {"stag": "```swift\n", "etag": "\n```"},
            "text/kotlin": {"stag": "```kotlin\n", "etag": "\n```"},
            "text/cpp": {"stag": "```cpp\n", "etag": "\n```"},
            "text/c": {"stag": "```c\n", "etag": "\n```"},
            "text/csharp": {"stag": "```csharp\n", "etag": "\n```"},
            "text/code": {"stag": "```\n", "etag": "\n```"},
            "application/code": {"stag": "```\n", "etag": "\n```"},
        }

        self.reset_state()

    def _get_tag_behavior(self, tag_name: str) -> Optional[TagBehavior]:
        """读取标签的处理行为。"""
        config = self.tag_config.get(tag_name.lower())
        return config["behavior"] if config else None

    def _is_filtered_tag(self, tag_name: str) -> bool:
        """判断标签是否在过滤名单中。"""
        return tag_name.lower() in self.tag_config

    def reset_state(self):
        """重置过滤器状态（便于复用实例）。"""
        self.state = FilterState.NORMAL
        self.buffer = ""
        self.tag_stack = []
        self.temp_output = ""
        self.has_mismatched_closing_tags = False

        self.has_filtered_tags_in_text = False
        self.last_char_was_lt = False

    def _quick_scan_for_filtered_content(self, text: str) -> bool:
        """快速扫描文本中是否包含待过滤内容。"""
        if not text or "<" not in text:
            return False

        text_lower = text.lower()

        if "<![cdata[" in text_lower:
            return True

        for tag_name in self.tag_config.keys():
            if f"<{tag_name}" in text_lower or f"</{tag_name}" in text_lower:
                return True

        return False

    def _extract_tag_name_quick(self, tag_content: str) -> str:
        """快速提取标签名（性能优化）。"""
        if not tag_content:
            return ""

        if tag_content.startswith("/"):
            tag_content = tag_content[1:]

        if tag_content.endswith("/"):
            tag_content = tag_content[:-1]

        parts = tag_content.split(None, 1)
        return parts[0].lower() if parts else ""

    def _extract_content_type(self, tag_content: str) -> Optional[str]:
        """从标签文本中提取 contentType 属性。"""
        match = re.search(
            r'contentType=["\']([^"\'>]+)["\']', tag_content, re.IGNORECASE
        )
        return match.group(1) if match else None

    def _should_preserve_content(
        self, tag_name: str, content_type: Optional[str]
    ) -> bool:
        """是否应保留内容（并替换包裹）。"""
        behavior = self._get_tag_behavior(tag_name)
        return behavior == TagBehavior.PRESERVE_CONTENT

    def _get_content_replacement(self, content_type: Optional[str]) -> Dict[str, str]:
        """按 contentType 获取替换映射，默认返回纯文本包裹。"""
        if content_type and content_type in self.content_type_mappings:
            return self.content_type_mappings[content_type]
        return {"stag": "", "etag": ""}

    def _process_complete_tag(self, tag_text: str) -> str:
        """处理完整标签并返回应输出文本。"""
        if not tag_text.startswith("<") or not tag_text.endswith(">"):
            return tag_text

        tag_content = tag_text[1:-1]

        if tag_content.lower().startswith("![cdata["):
            return ""

        tag_name = self._extract_tag_name_quick(tag_content)
        behavior = self._get_tag_behavior(tag_name)

        if behavior is None:
            return tag_text

        is_closing = tag_content.startswith("/")
        is_self_closing = tag_content.endswith("/")

        if is_closing:
            matched = False
            for i in range(len(self.tag_stack) - 1, -1, -1):
                if self.tag_stack[i]["name"] == tag_name:
                    tag_entry = self.tag_stack.pop(i)
                    self.tag_stack = self.tag_stack[:i]
                    matched = True

                    if tag_entry.get("preserve_content"):
                        return tag_entry["replacement"].get("etag", "")
                    break

            if not matched:
                if self._is_in_preserved_context():
                    self.has_mismatched_closing_tags = True
                    return tag_text
            return ""

        elif is_self_closing:
            if behavior == TagBehavior.PRESERVE_CONTENT:
                content_type = self._extract_content_type(tag_content)
                if self._should_preserve_content(tag_name, content_type):
                    replacement = self._get_content_replacement(content_type)
                    return replacement.get("stag", "") + replacement.get("etag", "")
            return ""

        else:
            content_type = self._extract_content_type(tag_content)
            preserve_content = self._should_preserve_content(tag_name, content_type)

            replacement = (
                self._get_content_replacement(content_type) if preserve_content else {}
            )

            self.tag_stack.append(
                {
                    "name": tag_name,
                    "behavior": behavior,
                    "content_type": content_type,
                    "preserve_content": preserve_content,
                    "replacement": replacement,
                }
            )

            if preserve_content:
                return replacement.get("stag", "")
            return ""

    def _might_be_closing_tag(self, tag_text: str) -> bool:
        """是否可能是栈中某个标签的关闭标记。"""
        if not tag_text.startswith("</"):
            return False

        tag_content = tag_text[1:-1] if tag_text.endswith(">") else tag_text[1:]
        tag_name = self._extract_tag_name_quick(tag_content)

        for tag_entry in self.tag_stack:
            if tag_entry["name"] == tag_name:
                return True
        return False

    def _is_in_removal_context(self) -> bool:
        """是否处于“移除”上下文（栈中存在 REMOVE_ALL 即为真）。"""
        for tag_entry in self.tag_stack:
            if tag_entry.get("behavior") == TagBehavior.REMOVE_ALL:
                return True
        return False

    def _is_in_preserved_context(self) -> bool:
        """是否处于“保留内容”上下文（以栈顶行为为准）。"""
        if not self.tag_stack:
            return False
        top_tag = self.tag_stack[-1]
        return top_tag.get("preserve_content", False)

    def _is_in_filtered_context(self) -> bool:
        """是否处于任意过滤上下文。"""
        return len(self.tag_stack) > 0

    def _should_output_char(self, char: str) -> bool:
        """根据当前上下文判断是否输出该字符。"""
        if not self._is_in_filtered_context():
            return True
        if self._is_in_removal_context():
            return False
        return self._is_in_preserved_context()

    def filter_chunk(self, chunk: str) -> str:
        """以最小缓冲、最高效率过滤文本分片。"""
        if not chunk:
            return ""

        if (
            self.state == FilterState.NORMAL
            and not self.tag_stack
            and not self.buffer
            and not self._quick_scan_for_filtered_content(chunk)
            and "<" not in chunk
        ):
            return chunk

        result = ""
        i = 0

        while i < len(chunk):
            char = chunk[i]

            if self.state == FilterState.NORMAL:
                if char == "<":
                    self.state = FilterState.POTENTIAL_TAG
                    self.buffer = "<"
                else:
                    if self._should_output_char(char):
                        result += char
                i += 1

            elif self.state == FilterState.POTENTIAL_TAG:
                self.buffer += char

                if char == ">":
                    tag_output = self._process_complete_tag(self.buffer)

                    if not self._is_in_removal_context():
                        result += tag_output

                    self.buffer = ""
                    self.state = FilterState.NORMAL
                    i += 1

                elif len(self.buffer) > 1 and self.buffer.lower().startswith(
                    "<![cdata["
                ):
                    self.state = FilterState.IN_CDATA
                    i += 1

                elif len(self.buffer) > 256:
                    first_char = self.buffer[0]
                    if self._should_output_char(first_char):
                        result += first_char

                    self.buffer = self.buffer[1:]

                    if not self.buffer or not self.buffer.startswith("<"):
                        if self.buffer:
                            for buf_char in self.buffer:
                                if self._should_output_char(buf_char):
                                    result += buf_char
                        self.buffer = ""
                        self.state = FilterState.NORMAL
                    continue
                else:
                    i += 1

            elif self.state == FilterState.IN_CDATA:
                self.buffer += char
                if self.buffer.endswith("]]>"):
                    self.buffer = ""
                    self.state = FilterState.NORMAL
                i += 1

        return result

    def finalize(self) -> str:
        """收尾并返回剩余内容。"""
        result = ""

        if self.buffer:
            if self.state == FilterState.POTENTIAL_TAG:
                buffer_lower = self.buffer.lower()
                is_filtered = False

                for tag_name in self.tag_config.keys():
                    if buffer_lower.startswith(
                        f"<{tag_name}"
                    ) or buffer_lower.startswith(f"</{tag_name}"):
                        is_filtered = True
                        break

                if not is_filtered and self._should_output_char(self.buffer[0]):
                    result += self.buffer
            elif self.state == FilterState.NORMAL and self._should_output_char(
                self.buffer[0]
            ):
                result += self.buffer

        if not self.has_mismatched_closing_tags:
            for tag_entry in reversed(self.tag_stack):
                if tag_entry.get("preserve_content"):
                    if tag_entry.get("replacement"):
                        result += tag_entry["replacement"].get("etag", "")

        self.reset_state()

        return result


@dataclass
class StreamingContext:
    """流式响应处理上下文。"""

    model: str
    processor: ModelResponseProcessor
    image_handler: ResponseImageHandler
    tag_filter: StreamingTagFilter
    state: ProcessingState = field(default_factory=ProcessingState)
    # 访问资源用的 Cookie（由 token + cf_clearance 组合）
    cookie: Optional[str] = None
    proxy_url: Optional[str] = None


class StreamProcessor:
    """处理流式响应。"""

    @staticmethod
    def process_non_stream_response(
        response: requests.Response, context: StreamingContext
    ) -> Union[str, Dict[str, Any]]:
        """处理非流式响应，支持两种格式：
        
        1. <think>标签格式：返回包含标签的完整文本字符串
        2. reasoning_content格式：返回分离reasoning和content的字典
        """
        

        full_response = ""
        reasoning_content = ""
        current_state = context.state
        use_reasoning_format = context.processor.config.get("USE_REASONING_FORMAT", False)
        in_think = False

        try:
            for chunk in response.iter_lines():
                if not chunk:
                    continue

                try:
                    line_data = json.loads(chunk.decode("utf-8").strip())

                    if line_data.get("error"):
                        error_info = line_data.get("error", {})
                        error_message = error_info.get("message", "Unknown error")
                        print(f"API error: {json.dumps(line_data, indent=2)}")
                        return f"Error: {error_message}"

                    response_data = line_data.get("result", {}).get("response")
                    if not response_data:
                        continue

                    result = context.processor.process_response(
                        response_data, context.model, current_state
                    )

                    if result.new_state:
                        current_state = result.new_state

                    if result.should_skip:
                        continue

                    if result.token:
                        filtered_token = context.tag_filter.filter_chunk(result.token)
                        if filtered_token:
                            if use_reasoning_format:
                                # reasoning 格式：分离思考和内容
                                parts = re.split(r'(<think>|</think>)', filtered_token)
                                for part in parts:
                                    if part == "<think>":
                                        in_think = True
                                    elif part == "</think>":
                                        in_think = False
                                    elif part:
                                        if in_think:
                                            reasoning_content += part
                                        else:
                                            full_response += part
                            else:
                                # <think> 标签格式：直接追加
                                full_response += filtered_token

                    if result.image_url:
                        image_content = context.image_handler.handle_image_response(
                            result.image_url, context.cookie, context.proxy_url
                        )
                        # 非流式：将图片内容直接追加到响应
                        full_response += image_content
                        # 非 imageGen 模型忽略图片 URL，避免意外拉取
                        continue

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error processing stream line: {e}")
                    continue

            final_content = context.tag_filter.finalize()
            if final_content:
                if use_reasoning_format:
                    # 处理 finalize 的内容
                    parts = re.split(r'(<think>|</think>)', final_content)
                    for part in parts:
                        if part == "<think>":
                            in_think = True
                        elif part == "</think>":
                            in_think = False
                        elif part:
                            if in_think:
                                reasoning_content += part
                            else:
                                full_response += part
                else:
                    full_response += final_content

            # 最后清理：移除可能残留的标签（非流式处理的兜底方案）
            # 这些标签可能因为跨块而没有被完全过滤，使用配置中的标签列表
            tag_config = context.tag_filter.tag_config
            for tag_name, tag_settings in tag_config.items():
                if tag_settings.get("behavior") == "remove_all":
                    escaped_tag = re.escape(tag_name)
                    # 处理三种情况：
                    # 1. 成对标签：<tag>...</tag>
                    # 2. 自闭合标签：<tag ... />
                    # 3. 单独标签：<tag ...>
                    patterns = [
                        rf'<{escaped_tag}[^>]*>.*?</{escaped_tag}>',  # 成对标签
                        rf'<{escaped_tag}[^>]*/\s*>',                  # 自闭合标签
                        rf'<{escaped_tag}[^>]*>',                      # 单独开始标签
                    ]
                    for pattern in patterns:
                        full_response = re.sub(pattern, '', full_response, flags=re.DOTALL | re.IGNORECASE)
                        if use_reasoning_format:
                            reasoning_content = re.sub(pattern, '', reasoning_content, flags=re.DOTALL | re.IGNORECASE)
            
            # 额外清理：移除 <argument> 标签（Grok 内部标签，通常与 grok:render 一起出现）
            argument_patterns = [
                r'<argument[^>]*>.*?</argument>',  # 成对的 argument 标签
                r'<argument[^>]*/\s*>',            # 自闭合 argument 标签
                r'<argument[^>]*>',                # 单独 argument 标签
            ]
            for pattern in argument_patterns:
                full_response = re.sub(pattern, '', full_response, flags=re.DOTALL | re.IGNORECASE)
                if use_reasoning_format:
                    reasoning_content = re.sub(pattern, '', reasoning_content, flags=re.DOTALL | re.IGNORECASE)

            # 返回格式
            if use_reasoning_format and reasoning_content:
                # 返回分离的字典格式
                return {
                    "content": full_response,
                    "reasoning_content": reasoning_content
                }
            else:
                # 返回普通字符串
                return full_response

        except Exception as e:
            print(f"Non-stream processing failed: {e}")
            return f"Error: {e}"

    @staticmethod
    def process_stream_response(
        response: requests.Response, context: StreamingContext
    ):
        """处理流式响应，支持两种格式：
        
        1. <think>标签格式（默认）：保留 <think>...</think> 标签
        2. reasoning_content格式（USE_REASONING_FORMAT=true）：分离推理和内容到不同字段
        """
        

        current_state = context.state
        show_thinking = context.processor.config.get("SHOW_THINKING", False)
        use_reasoning_format = context.processor.config.get("USE_REASONING_FORMAT", False)
        in_think = False
        reasoning_buffer = []  # 用于收集推理内容

        try:
            for chunk in response.iter_lines():
                if not chunk:
                    continue

                try:
                    line_data = json.loads(chunk.decode("utf-8").strip())

                    if line_data.get("error"):
                        error_info = line_data.get("error", {})
                        error_message = error_info.get("message", "Unknown error")
                        print(f"API error: {json.dumps(line_data, indent=2)}")
                        error_response = MessageProcessor.create_error_response(error_message)
                        yield f"data: {json.dumps(error_response)}\n\n"
                        return

                    response_data = line_data.get("result", {}).get("response")
                    if not response_data:
                        continue

                    result = context.processor.process_response(
                        response_data, context.model, current_state
                    )

                    if result.new_state:
                        current_state = result.new_state

                    if result.should_skip:
                        continue

                    if result.token:
                        filtered_token = context.tag_filter.filter_chunk(result.token)
                        if filtered_token:
                            try:
                                parts = re.split(r'(<think>|</think>)', filtered_token)
                            except Exception:
                                parts = [filtered_token]

                            for part in parts:
                                if part == "":
                                    continue
                                if part == "<think>":
                                    in_think = True
                                    if use_reasoning_format:
                                        # reasoning 格式：跳过标签，开始收集推理内容
                                        continue
                                    elif show_thinking:
                                        # <think> 标签格式：输出标签
                                        formatted_response = MessageProcessor.create_chat_completion_chunk(
                                            part, context.model
                                        )
                                        yield f"data: {json.dumps(formatted_response)}\n\n"
                                    continue
                                    
                                if part == "</think>":
                                    in_think = False
                                    if use_reasoning_format:
                                        # reasoning 格式：跳过标签
                                        continue
                                    elif show_thinking:
                                        # <think> 标签格式：输出标签
                                        formatted_response = MessageProcessor.create_chat_completion_chunk(
                                            part, context.model
                                        )
                                        yield f"data: {json.dumps(formatted_response)}\n\n"
                                    continue

                                if in_think:
                                    if use_reasoning_format:
                                        # reasoning 格式：收集推理内容
                                        reasoning_buffer.append(part)
                                        if show_thinking:
                                            # 输出到 reasoning_content 字段
                                            for ch in part:
                                                if not ch:
                                                    continue
                                                formatted_response = MessageProcessor.create_chat_completion_chunk_reasoning(
                                                    ch, context.model
                                                )
                                                yield f"data: {json.dumps(formatted_response)}\n\n"
                                    elif show_thinking:
                                        # <think> 标签格式：按字符流式输出到 content
                                        for ch in part:
                                            if not ch:
                                                continue
                                            formatted_response = MessageProcessor.create_chat_completion_chunk(
                                                ch, context.model
                                            )
                                            yield f"data: {json.dumps(formatted_response)}\n\n"
                                else:
                                    # 非思考内容：输出到 content 字段
                                    formatted_response = MessageProcessor.create_chat_completion_chunk(
                                        part, context.model
                                    )
                                    yield f"data: {json.dumps(formatted_response)}\n\n"

                    if result.image_url:
                        image_content = context.image_handler.handle_image_response(
                            result.image_url, context.cookie, context.proxy_url
                        )
                        # 流式：分块发送图片内容
                        _chunk_size = 4096
                        for _i in range(0, len(image_content), _chunk_size):
                            formatted_response = MessageProcessor.create_chat_completion_chunk(
                                image_content[_i:_i+_chunk_size], context.model
                            )
                            yield f"data: {json.dumps(formatted_response)}\n\n"
                        # 非 imageGen 模型忽略图片 URL，避免意外拉取
                        continue

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error processing stream line: {e}")
                    continue

            final_content = context.tag_filter.finalize()
            if final_content:
                try:
                    parts = re.split(r'(<think>|</think>)', final_content)
                except Exception:
                    parts = [final_content]

                for part in parts:
                    if part == "":
                        continue
                    if part == "<think>":
                        in_think = True
                        if show_thinking:
                            formatted_response = MessageProcessor.create_chat_completion_chunk(
                                part, context.model
                            )
                            yield f"data: {json.dumps(formatted_response)}\n\n"
                        continue
                    if part == "</think>":
                        if show_thinking:
                            formatted_response = MessageProcessor.create_chat_completion_chunk(
                                part, context.model
                            )
                            yield f"data: {json.dumps(formatted_response)}\n\n"
                        in_think = False
                        continue
                    if in_think and show_thinking:
                        for ch in part:
                            if not ch:
                                continue
                            formatted_response = MessageProcessor.create_chat_completion_chunk(
                                ch, context.model
                            )
                            yield f"data: {json.dumps(formatted_response)}\n\n"
                    else:
                        formatted_response = MessageProcessor.create_chat_completion_chunk(
                            part, context.model
                        )
                        yield f"data: {json.dumps(formatted_response)}\n\n"

            yield "data: [DONE]\n\n"

        except Exception as e:
            print(f"Stream processing failed: {e}")
            error_response = MessageProcessor.create_error_response(str(e))
            yield f"data: {json.dumps(error_response)}\n\n"


class MessageProcessor:
    """构造标准格式的 Chat Completion 响应。"""

    @staticmethod
    def create_chat_completion(message: str, model: str) -> Dict[str, Any]:
        """创建完整的 chat.completion 响应。"""
        return {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": message},
                    "finish_reason": "stop",
                }
            ],
            "usage": None,
        }

    @staticmethod
    def create_chat_completion_with_content(content: Any, model: str) -> Dict[str, Any]:
        """创建包含 content 数组的完整响应。"""
        return {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": None,
        }

    @staticmethod
    def create_chat_completion_chunk(message: str, model: str) -> Dict[str, Any]:
        """创建流式分片（content 增量）。"""
        return {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "delta": {"content": message}}],
        }

    @staticmethod
    def create_chat_completion_with_reasoning(
        content: str, reasoning: str, model: str
    ) -> Dict[str, Any]:
        """创建带独立 reasoning_content 字段的完整响应（类似 OpenAI o1 格式）。"""
        return {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                        "reasoning_content": reasoning,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": None,
        }

    @staticmethod
    def create_chat_completion_chunk_reasoning(message: str, model: str) -> Dict[str, Any]:
        """创建带 reasoning_content 增量的流式分片（类似 OpenAI o1 格式）。"""
        return {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "delta": {"reasoning_content": message}}],
        }

    @staticmethod
    def create_chat_completion_chunk_with_content(
        content: Any, model: str
    ) -> Dict[str, Any]:
        """创建支持 content 数组的流式分片。"""
        return {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "delta": {"content": content}}],
        }

    @staticmethod
    def create_error_response(error_message: str) -> Dict[str, Any]:
        """创建错误响应。"""
        return {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "error": {"message": error_message, "type": "server_error"},
        }


class AuthenticationService:
    """处理鉴权与授权。"""

    def __init__(
        self, config: ConfigurationManager, token_manager: ThreadSafeTokenManager
    ):
        """初始化鉴权服务。"""
        self.config = config
        self.token_manager = token_manager

    def validate_api_key(self, auth_header: Optional[str]) -> str:
        """从 Authorization 头解析并校验 API Key。"""
        if not auth_header:
            raise ValidationException("Authorization header missing")

        auth_token = auth_header.replace("Bearer ", "").strip()
        if not auth_token:
            raise ValidationException("API key missing")

        return auth_token

    def process_authentication(self, auth_header: Optional[str]) -> bool:
        """完成鉴权流程，必要时附加 token。"""
        try:
            auth_token = self.validate_api_key(auth_header)

            if self.config.get("API.IS_CUSTOM_SSO", False):
                try:
                    credential = TokenCredential.from_raw_token(
                        auth_token, TokenType.NORMAL
                    )
                    success = self.token_manager.add_token(credential)
                    if not success:
                        print("Failed to add custom SSO token")
                    return True
                except Exception as e:
                    print(
                        f"Failed to process custom SSO token: {e}",
                        "AuthenticationService",
                    )
                    raise ValidationException(f"Invalid SSO token format: {e}")
            else:
                expected_key = self.config.get("API.API_KEY", "sk-123456")
                if auth_token != expected_key:
                    print(f"Invalid API key provided")
                    raise ValidationException("Invalid API key")
                return True

        except ValidationException:
            raise
        except Exception as e:
            print(f"Authentication processing failed: {e}")
            raise ValidationException(f"Authentication failed: {e}") from e


def create_app(config: ConfigurationManager) -> Flask:
    """创建并配置 Flask 应用。"""
    app = Flask(__name__)

    app.config["SECRET_KEY"] = secrets.token_urlsafe(32)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    token_manager = ThreadSafeTokenManager(config)
    auth_service = AuthenticationService(config, token_manager)
    grok_client = GrokApiClient(config, token_manager)
    response_processor = ModelResponseProcessor(config)
    image_handler = ResponseImageHandler(config)

    def create_error_response(
        error_data: Union[str, Dict[str, Any]], status_code: int
    ) -> Tuple[Dict[str, Any], int]:
        """创建统一格式的错误响应。"""
        return UtilityFunctions.create_structured_error_response(
            error_data, status_code
        )

    # 后台更新器：每次请求后调用上游限额接口，并将准确的剩余额度写入 token_status.json
    def _update_rate_limits_async(
        cookie: Optional[str], used_token: Optional[str], model_name: str, proxy_url: Optional[str]
    ) -> None:
        if not used_token or not cookie:
            return

        def worker():
            try:
                # 先更新模型统计（计数）
                try:
                    credential = TokenCredential(used_token, TokenType.NORMAL)
                    sso_value = credential.extract_sso_value()
                    
                    with token_manager._lock:
                        if sso_value in token_manager._token_status:
                            token_data = token_manager._token_status[sso_value]
                            model_stats = token_data.get("modelStats", {})
                            
                            # 初始化模型统计（若不存在）
                            if model_name not in model_stats:
                                model_stats[model_name] = {
                                    "lastCallTime": None,
                                    "requestCount": 0,
                                    "failureCount": 0,
                                    "lastFailureTime": None,
                                    "lastFailureResponse": None
                                }
                            
                            # 更新调用时间和请求计数
                            model_stats[model_name]["lastCallTime"] = int(time.time() * 1000)
                            model_stats[model_name]["requestCount"] += 1
                except Exception as e:
                    print(f"Failed to update model stats: {e}")
                
                # 优先复用本次请求使用的代理；否则回退到静态/动态配置
                proxy = proxy_url or config.get("API.PROXY")
                if not proxy and config.get("API.DYNAMIC_PROXY_API"):
                    try:
                        pm = get_proxy_manager(config)
                        proxy = pm.get_working_proxy()
                    except Exception:
                        proxy = None
                proxy_config = UtilityFunctions.get_proxy_configuration(proxy)
                
                payload = {"requestKind": "DEFAULT", "modelName": model_name}
                resp = curl_requests.post(
                    f"{config.get('API.BASE_URL')}/rest/rate-limits",
                    headers={
                        **get_dynamic_headers("POST", "/rest/rate-limits", config),
                        "Cookie": cookie,
                    },
                    json=payload,
                    impersonate="chrome133a",
                    timeout=30,
                    **proxy_config,
                )

                if resp.status_code != 200:
                    print(
                        f"Rate-limits query failed: HTTP {resp.status_code}",
                        "RateLimits",
                    )
                    return

                data = resp.json() if hasattr(resp, "json") else None
                if not isinstance(data, dict):
                    print("Rate-limits response not JSON dict", "RateLimits")
                    return

                remaining = int(data.get("remainingTokens", 0))
                total = int(data.get("totalTokens", 80))
                window = data.get("windowSizeSeconds")

                token_manager.update_token_quota(used_token, remaining, total, window)
            except Exception as e:
                print(f"Failed to update rate-limits: {e}", "RateLimits")

        threading.Thread(target=worker, daemon=True).start()

    @app.errorhandler(ValidationException)
    def handle_validation_error(e: ValidationException) -> Tuple[Dict[str, Any], int]:
        """处理校验异常。"""
        return create_error_response(
            {"error": str(e), "error_code": "VALIDATION_ERROR"}, 400
        )

    @app.errorhandler(TokenException)
    def handle_token_error(e: TokenException) -> Tuple[Dict[str, Any], int]:
        """处理 Token 异常。"""
        return create_error_response(
            {"error": str(e), "error_code": "TOKEN_ERROR"}, 429
        )

    @app.errorhandler(RateLimitException)
    def handle_rate_limit_error(e: RateLimitException) -> Tuple[Dict[str, Any], int]:
        """处理限流异常。"""
        return create_error_response(
            {"error": str(e), "error_code": "RATE_LIMIT_ERROR"}, 429
        )

    @app.errorhandler(GrokApiException)
    def handle_grok_api_error(e: GrokApiException) -> Tuple[Dict[str, Any], int]:
        """处理 Grok API 异常。"""
        return create_error_response({"error": str(e), "error_code": e.error_code}, 500)

    @app.errorhandler(500)
    def handle_internal_error(e) -> Tuple[Dict[str, Any], int]:
        """处理服务端内部错误。"""
        print(f"Internal server error: {e}")
        return create_error_response("Internal server error", 500)

    @app.route("/v1/chat/completions", methods=["POST"])
    def chat_completions():
        """兼容 OpenAI 的 Chat Completions 入口（职责分离）。"""
        response_status_code = None

        try:
            if not request.is_json:
                raise ValidationException("Request must be JSON")

            data = request.get_json()
            if not data:
                raise ValidationException("Request body is empty")

            auth_service.process_authentication(request.headers.get("Authorization"))

            model = data.get("model")
            messages = data.get("messages", [])
            stream = data.get("stream", False)

            if not model:
                raise ValidationException("Model parameter is required")

            if not messages:
                raise ValidationException("Messages parameter is required")

            

            payload = grok_client.prepare_chat_request(data)

            # 计算用于限额查询的规范化模型名
            normalized_model = grok_client.validate_model_and_request(model, data)

            response = None
            used_token = None
            retry_count = 0
            max_retries = config.get("RETRY.MAX_ATTEMPTS", MAX_RETRY_ATTEMPTS)

            while retry_count < max_retries:
                try:
                    response, used_token, used_proxy_url = grok_client.make_request(
                        payload, model, stream
                    )
                    response_status_code = response.status_code

                    if response.status_code == 200:
                        break
                    elif response.status_code == 429:
                        print("Rate limited (429)")
                        # 若使用动态代理（未配置静态 PROXY），尝试轮换代理
                        try:
                            if not config.get("API.PROXY") and config.get("API.DYNAMIC_PROXY_API") and used_proxy_url:
                                pm = get_proxy_manager(config)
                                pm.invalidate_current(used_proxy_url)
                                print("Rate limited (429), rotating dynamic proxy")
                        except Exception:
                            # 忽略代理轮换失败，继续尝试轮换 token
                            pass

                        # 若存在多个 token，始终尝试轮换 token
                        if token_manager.get_token_count_for_model(model) > 1:
                            try:
                                # 先同步更新被限流token的状态
                                if used_token:
                                    cookie = f"{used_token};{config.get('SERVER.CF_CLEARANCE', '')}"
                                    # 同步调用rate-limits API获取准确状态
                                    proxy = used_proxy_url or config.get("API.PROXY")
                                    if not proxy and config.get("API.DYNAMIC_PROXY_API"):
                                        try:
                                            pm = get_proxy_manager(config)
                                            proxy = pm.get_working_proxy()
                                        except Exception:
                                            proxy = None
                                    proxy_config = UtilityFunctions.get_proxy_configuration(proxy)

                                    try:
                                        rate_limits_payload = {"requestKind": "DEFAULT", "modelName": normalized_model}
                                        resp = curl_requests.post(
                                            f"{config.get('API.BASE_URL')}/rest/rate-limits",
                                            headers={
                                                **get_dynamic_headers("POST", "/rest/rate-limits", config),
                                                "Cookie": cookie,
                                            },
                                            json=rate_limits_payload,
                                            impersonate="chrome133a",
                                            timeout=10,  # 较短超时，快速获取状态
                                            **proxy_config,
                                        )
                                        print(f"Rate-limits API response status: {resp.status_code}")
                                        if resp.status_code == 200:
                                            data = resp.json() if hasattr(resp, "json") else None
                                            print(f"Rate-limits API response data: {data}")
                                            if isinstance(data, dict):
                                                remaining = int(data.get("remainingTokens", 0))
                                                total = int(data.get("totalTokens", 80))
                                                window = data.get("windowSizeSeconds")
                                                print(f"Parsed values - remaining: {remaining}, total: {total}, window: {window}")
                                                token_manager.update_token_quota(used_token, remaining, total, window)

                                                # 直接标记为无效，防止立即重用
                                                sso_value = used_token.split("sso=")[1].split(";")[0]
                                                if sso_value in token_manager._token_status:
                                                    token_data = token_manager._token_status[sso_value]
                                                    token_data["isValid"] = False
                                                    token_manager._save_token_status()

                                                print(f"Updated 429 token status: {remaining}/{total} and marked as invalid")
                                            else:
                                                print(f"Rate-limits API returned non-dict data: {type(data)} - {data}")
                                        else:
                                            print(f"Rate-limits API failed with status: {resp.status_code}")
                                            if hasattr(resp, 'text'):
                                                print(f"Rate-limits API error response: {resp.text[:500]}")
                                    except Exception as e:
                                        print(f"Failed to immediately update 429 token status: {e}")

                                # 然后记录失败统计
                                token_manager.rotate_token(model, used_token)

                            except Exception:
                                pass
                            print("Rate limited (429), updated token status and retrying")
                            retry_count += 1
                            continue
                        else:
                            raise RateLimitException(
                                "Rate limit exceeded and no alternative tokens available"
                            )
                    else:
                        error_text = (
                            response.text
                            if response.text
                            else f"HTTP {response.status_code} error"
                        )
                        print(
                            f"API request failed with status {response.status_code}: {error_text}"
                        )
                        print(f"Full response headers: {dict(response.headers)}")
                        print(f"Full response content: {error_text[:2000]}")

                        if used_token:
                            token_manager.record_token_failure(
                                model, used_token, error_text, response.status_code
                            )

                        error_data = UtilityFunctions.parse_error_response(error_text)
                        raise GrokApiException(
                            error_data.get(
                                "error",
                                f"API request failed with status {response.status_code}",
                            ),
                            error_data.get("error_code", "API_ERROR"),
                        )

                except requests.exceptions.RequestException as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        raise GrokApiException(
                            f"Request failed after {max_retries} attempts: {e}",
                            "REQUEST_FAILED",
                        )

                    delay = BASE_RETRY_DELAY * (2 ** (retry_count - 1))
                    print(f"Request failed, retrying in {delay}s: {e}")
                    time.sleep(delay)

            if not response:
                error_msg = "Request failed: No response received"
                raise GrokApiException(error_msg, "REQUEST_FAILED")
            elif response.status_code != 200:
                if response_status_code:
                    error_msg = f"Request failed with status: {response_status_code}"
                else:
                    error_msg = f"Request failed with status: {response.status_code}"
                raise GrokApiException(error_msg, "REQUEST_FAILED")

            tag_config = config.get("TAG_CONFIG", {})
            content_type_mappings = config.get("CONTENT_TYPE_MAPPINGS", {})

            # 构造资源访问用 Cookie（与本次 token/cf_clearance 一致）
            cf_clearance = config.get("SERVER.CF_CLEARANCE", "")
            cookie = build_cookie(used_token, cf_clearance) if used_token else None

            context = StreamingContext(
                model=model,
                processor=response_processor,
                image_handler=image_handler,
                tag_filter=StreamingTagFilter(tag_config, content_type_mappings),
                cookie=cookie,
                proxy_url=used_proxy_url,
            )

            if stream:

                def generate():
                    try:
                        yield from StreamProcessor.process_stream_response(
                            response, context
                        )
                    except Exception as e:
                        print(f"Stream processing error: {e}")
                        error_response = MessageProcessor.create_error_response(str(e))
                        yield f"data: {json.dumps(error_response)}\n\n"
                    finally:
                        # 流式请求处理完成后更新额度状态
                        _update_rate_limits_async(cookie, used_token, normalized_model, used_proxy_url)

                return Response(
                    stream_with_context(generate()),
                    content_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive",
                        "X-Accel-Buffering": "no",
                    },
                )
            else:
                response_result = StreamProcessor.process_non_stream_response(
                    response, context
                )
                
                # 根据返回类型构造响应
                if isinstance(response_result, dict):
                    # reasoning 格式：包含 content 和 reasoning_content
                    if "reasoning_content" in response_result:
                        formatted_response = MessageProcessor.create_chat_completion_with_reasoning(
                            response_result["content"],
                            response_result["reasoning_content"],
                            model
                        )
                    else:
                        # 其他字典格式（如错误响应）
                        formatted_response = response_result
                else:
                    # 普通字符串：<think> 标签格式
                    formatted_response = MessageProcessor.create_chat_completion(
                        response_result, model
                    )
                
                # 非流式请求处理完成后更新额度状态
                _update_rate_limits_async(cookie, used_token, normalized_model, used_proxy_url)
                
                return jsonify(formatted_response)

        except (
            ValidationException,
            TokenException,
            RateLimitException,
            GrokApiException,
        ):
            raise
        except Exception as e:
            print(f"Unexpected error in chat completions: {e}")
            raise GrokApiException("Internal server error", "INTERNAL_ERROR") from e

    @app.route("/v1/models", methods=["GET"])
    def list_models():
        """列出可用模型。"""
        models_data = []
        current_time = int(time.time())

        for model_key in config.models.keys():
            # 隐藏上游内部 id，不在外部列表展示
            if model_key == "grok-4-mini-thinking-tahoe":
                continue
            models_data.append(
                {
                    "id": model_key,
                    "object": "model",
                    "created": current_time,
                    "owned_by": "grok",
                }
            )

        return jsonify({"object": "list", "data": models_data})

    @app.route("/health", methods=["GET"])
    def health_check():
        """健康检查接口。"""
        return jsonify(
            {"status": "healthy", "timestamp": int(time.time()), "version": "2.0.0"}
        )

    @app.route("/", methods=["GET"])
    def index():
        """首页：基础信息。"""
        return jsonify(
            {"message": "Grok API Gateway", "version": "2.0.0", "status": "running"}
        )

    def check_admin_auth() -> bool:
        """校验管理端登录态。"""
        if not config.get("ADMIN.MANAGER_SWITCH"):
            return False

        password = request.form.get("password") or request.args.get("password")
        expected_password = config.get("ADMIN.PASSWORD")

        return bool(password and expected_password and password == expected_password)

    @app.route("/add_token", methods=["POST"])
    def add_token():
        """新增 token（管理员）。"""
        if not check_admin_auth():
            return jsonify({"error": "Unauthorized"}), 401

        try:
            token_data = request.form.get("tokens") or (
                request.json and request.json.get("tokens")
            )
            if not token_data:
                return jsonify({"error": "Token data required"}), 400

            if isinstance(token_data, str):
                try:
                    token_dict = json.loads(token_data)
                except json.JSONDecodeError:
                    token_dict = {"token": token_data, "type": "normal"}
            else:
                token_dict = token_data

            token_string = token_dict.get("token", "")
            token_type_str = token_dict.get("type")
            token_type = (
                TokenType.SUPER if token_type_str == "super" else TokenType.NORMAL
            )

            if not token_string:
                return jsonify({"error": "Token string required"}), 400

            credential = TokenCredential(token_string, token_type)
            success = token_manager.add_token(credential)

            if success:
                return jsonify({"message": "Token added successfully"})
            else:
                return jsonify({"error": "Failed to add token"}), 500

        except Exception as e:
            print(f"Error adding token: {e}")
            return jsonify({"error": f"Failed to add token: {e}"}), 500

    @app.route("/tokens_info", methods=["GET"])
    def tokens_info():
        """获取 token 信息（管理员）。"""
        if not check_admin_auth():
            return jsonify({"error": "Unauthorized"}), 401

        try:
            status_map = token_manager.get_token_status_map()
            capacity_map = token_manager.get_remaining_capacity()
            health_summary = token_manager.get_token_health_summary()

            return jsonify(
                {
                    "token_status": status_map,
                    "remaining_capacity": capacity_map,
                    "health_summary": health_summary,
                }
            )
        except Exception as e:
            print(f"Error getting token info: {e}")
            return jsonify({"error": f"Failed to get token info: {e}"}), 500

    def check_session_auth() -> bool:
        """检查基于会话的管理端认证。"""
        return session.get("is_logged_in", False)

    @app.route("/manager/login", methods=["GET", "POST"])
    def manager_login():
        """管理端登录页及处理。"""
        if not config.get("ADMIN.MANAGER_SWITCH"):
            return redirect("/")

        if request.method == "POST":
            password = request.form.get("password")
            if password == config.get("ADMIN.PASSWORD"):
                session["is_logged_in"] = True
                return redirect("/manager")
            return render_template("login.html", error=True)

        return render_template("login.html", error=False)

    @app.route("/manager")
    def manager():
        """管理后台首页。"""
        if not check_session_auth():
            return redirect("/manager/login")
        return render_template("manager.html")

    @app.route("/manager/api/get")
    def get_manager_tokens():
        """通过管理端 API 获取 tokens。"""
        if not check_session_auth():
            return jsonify({"error": "Unauthorized"}), 401

        try:
            # 兼容旧版：确保默认配额/计数存在
            try:
                token_manager._ensure_quota_defaults_for_all()
            except Exception:
                pass
            status_map = token_manager.get_token_status_map()
            health_summary = token_manager.get_token_health_summary()

            return jsonify(
                {"token_status": status_map, "health_summary": health_summary}
            )
        except Exception as e:
            print(f"Error getting manager tokens: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/manager/api/model_stats")
    def get_model_stats():
        """获取聚合的模型使用统计。"""
        if not check_session_auth():
            return jsonify({"error": "Unauthorized"}), 401

        try:
            status_map = token_manager.get_token_status_map()
            models_summary = {}

            # 汇总所有token的模型统计数据
            for token_data in status_map.values():
                model_stats = token_data.get("modelStats", {})
                for model_name, stats in model_stats.items():
                    if model_name not in models_summary:
                        models_summary[model_name] = {
                            "totalRequests": 0,
                            "totalFailures": 0,
                            "lastCallTime": None,
                            "lastFailureTime": None,
                            "tokenCount": 0  # 使用该模型的token数量
                        }

                    models_summary[model_name]["totalRequests"] += stats.get("requestCount", 0)
                    models_summary[model_name]["totalFailures"] += stats.get("failureCount", 0)

                    # 记录最新的调用时间
                    if stats.get("lastCallTime"):
                        if not models_summary[model_name]["lastCallTime"] or stats["lastCallTime"] > models_summary[model_name]["lastCallTime"]:
                            models_summary[model_name]["lastCallTime"] = stats["lastCallTime"]

                    # 记录最新的失败时间
                    if stats.get("lastFailureTime"):
                        if not models_summary[model_name]["lastFailureTime"] or stats["lastFailureTime"] > models_summary[model_name]["lastFailureTime"]:
                            models_summary[model_name]["lastFailureTime"] = stats["lastFailureTime"]

                    # 统计使用该模型的token数量
                    if stats.get("requestCount", 0) > 0:
                        models_summary[model_name]["tokenCount"] += 1

            return jsonify({"models_summary": models_summary})
        except Exception as e:
            print(f"Error getting model stats: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/manager/api/add", methods=["POST"])
    def add_manager_token():
        """通过管理端 API 新增 token。"""
        if not check_session_auth():
            return jsonify({"error": "Unauthorized"}), 401

        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "JSON data required"}), 400

            sso = data.get("sso")
            if not sso or not sso.strip():
                return (
                    jsonify({"error": "SSO token is required and cannot be empty"}),
                    400,
                )

            credential = TokenCredential.from_raw_token(sso.strip(), TokenType.NORMAL)
            success = token_manager.add_token(credential)

            if success:
                return jsonify({"success": True})
            else:
                return jsonify({"error": "Failed to add token"}), 500

        except Exception as e:
            print(f"Error adding manager token: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/manager/api/delete", methods=["POST"])
    def delete_manager_token():
        """通过管理端 API 删除 token。"""
        if not check_session_auth():
            return jsonify({"error": "Unauthorized"}), 401

        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "JSON data required"}), 400

            sso = data.get("sso")
            if not sso:
                return jsonify({"error": "SSO token is required"}), 400

            token_string = f"sso-rw={sso};sso={sso}"
            success = token_manager.delete_token(token_string)

            if success:
                return jsonify({"success": True})
            else:
                return jsonify({"error": "Token not found or failed to delete"}), 404

        except Exception as e:
            print(f"Error deleting manager token: {e}")
            return jsonify({"error": str(e)}), 500


    @app.route("/manager/api/reset_quota", methods=["POST"])
    def reset_quota_manager():
        """重置单个/全部 token 的配额（管理端）。"""
        if not check_session_auth():
            return jsonify({"error": "Unauthorized"}), 401

        try:
            data = request.get_json() or {}
            if not isinstance(data, dict):
                data = {}

            remaining = data.get("remainingTokens")
            total = data.get("totalTokens")
            if remaining is not None:
                try:
                    remaining = int(remaining)
                except Exception:
                    remaining = None
            if total is not None:
                try:
                    total = int(total)
                except Exception:
                    total = None

            if data.get("all"):
                updated = token_manager.reset_all_quotas(remaining=remaining, total=total)
                return jsonify({"success": True, "updated": updated})

            sso = data.get("sso")
            if not sso:
                return jsonify({"error": "Missing 'sso' or 'all'"}), 400

            # 支持原始 sso 值或包含 sso= 的完整 token 字符串
            sso_value = sso
            if isinstance(sso, str) and "sso=" in sso:
                try:
                    cred = TokenCredential(sso, TokenType.NORMAL)
                    sso_value = cred.extract_sso_value()
                except Exception:
                    sso_value = sso

            ok = token_manager.reset_token_quota(sso_value, remaining=remaining, total=total)
            if ok:
                return jsonify({"success": True})
            else:
                return jsonify({"error": "Token not found"}), 404

        except Exception as e:
            print(f"Error resetting quota: {e}")
            return jsonify({"error": str(e)}), 500
    @app.route("/manager/api/cf_clearance", methods=["POST"])
    def set_cf_clearance():
        """通过管理端 API 设置 CF clearance。"""
        if not check_session_auth():
            return jsonify({"error": "Unauthorized"}), 401

        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "JSON data required"}), 400

            cf_clearance = data.get("cf_clearance")
            if not cf_clearance:
                return jsonify({"error": "cf_clearance is required"}), 400

            config.set("SERVER.CF_CLEARANCE", cf_clearance)
            return jsonify({"success": True})

        except Exception as e:
            print(f"Error setting CF clearance: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/get/tokens", methods=["GET"])
    def get_tokens():
        """旧版获取 tokens 的接口。"""
        auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")

        if config.get("API.IS_CUSTOM_SSO", False):
            return (
                jsonify(
                    {"error": "Custom SSO mode cannot get polling SSO token status"}
                ),
                403,
            )
        elif auth_token != config.get("API.API_KEY", "sk-123456"):
            return jsonify({"error": "Unauthorized"}), 401

        try:
            return jsonify(token_manager.get_token_status_map())
        except Exception as e:
            print(f"Error getting tokens: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/add/token", methods=["POST"])
    def add_token_api():
        """通过 API Key 新增 tokens 的接口。"""
        auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")

        if config.get("API.IS_CUSTOM_SSO", False):
            return jsonify({"error": "Custom SSO mode cannot add SSO tokens"}), 403
        elif auth_token != config.get("API.API_KEY", "sk-123456"):
            return jsonify({"error": "Unauthorized"}), 401

        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "JSON data required"}), 400

            sso = data.get("sso")
            if not sso or not sso.strip():
                return (
                    jsonify({"error": "SSO token is required and cannot be empty"}),
                    400,
                )

            credential = TokenCredential.from_raw_token(sso.strip(), TokenType.NORMAL)
            success = token_manager.add_token(credential)

            if success:
                return jsonify({"message": "Token added successfully"})
            else:
                return jsonify({"error": "Failed to add token"}), 500

        except Exception as e:
            print(f"Error adding token via API: {e}")
            return jsonify({"error": str(e)}), 500

    return app


def initialize_application(
    config: ConfigurationManager, token_manager: ThreadSafeTokenManager
) -> None:
    """使用环境中的 tokens 初始化应用。"""
    tokens_added = 0

    sso_tokens = os.environ.get("SSO", "")
    if sso_tokens:
        for token in sso_tokens.split(","):
            token = token.strip()
            if token:
                try:
                    credential = TokenCredential(token, TokenType.NORMAL)
                    if token_manager.add_token(credential, is_initialization=True):
                        tokens_added += 1
                except Exception as e:
                    print(f"Failed to add normal token: {e}")

    sso_super_tokens = os.environ.get("SSO_SUPER", "")
    if sso_super_tokens:
        for token in sso_super_tokens.split(","):
            token = token.strip()
            if token:
                try:
                    credential = TokenCredential(token, TokenType.SUPER)
                    if token_manager.add_token(credential, is_initialization=True):
                        tokens_added += 1
                except Exception as e:
                    print(f"Failed to add super token: {e}")

    if tokens_added > 0:
        print(f"Successfully loaded {tokens_added} tokens")
    else:
        print("No tokens loaded during initialization")
        if not config.get("API.IS_CUSTOM_SSO", False):
            print(
                "Set SSO or SSO_SUPER environment variables, or enable IS_CUSTOM_SSO",
                "Initialization",
            )

    # Statsig/Playwright：优先使用静态 PROXY；否则在可用时使用动态代理
    proxy_url = config.get("API.PROXY")
    if not config.get("API.DISABLE_DYNAMIC_HEADERS", False):
        try:
            dynamic_api = config.get("API.DYNAMIC_PROXY_API")
            if not proxy_url and dynamic_api:
                pm = get_proxy_manager(config)
                dyn = pm.get_working_proxy()
                if dyn:
                    proxy_url = dyn
        except Exception:
            pass
        # 初始化 Statsig 管理器
        initialize_statsig_manager(proxy_url=proxy_url)
    else:
        pass

    


def cleanup_resources():
    """进程退出前清理浏览器资源。"""
    global _global_statsig_manager
    if _global_statsig_manager:
        try:
            _global_statsig_manager.cleanup()
            print("Browser resources cleaned up successfully")
        except Exception as e:
            print(f"Error cleaning up browser resources: {e}")


def main():
    """应用入口。"""
    try:
        config = ConfigurationManager()
        # 暴露外部别名，并确保上游能透传完整模型 id
        try:
            # 将外部模型名映射为上游完整 id（按需）
            config.set("MODELS.grok-4-fast", "grok-4-mini-thinking-tahoe")
            config.set("MODELS.grok-4-fast-expert", "grok-4-mini-thinking-tahoe")
            # 保持完整 id 直通，便于直接使用
            config.set("MODELS.grok-4-mini-thinking-tahoe", "grok-4-mini-thinking-tahoe")
        except Exception as _e:
            # 非致命：若覆盖失败则回退到默认配置
            print(f"Model mapping override skipped: {_e}")

        token_manager = ThreadSafeTokenManager(config)

        initialize_application(config, token_manager)

        app = create_app(config)

        port = config.get("SERVER.PORT", 5200)
        print(f"Starting Grok API Gateway on port {port}")

        import atexit

        atexit.register(cleanup_resources)

        app.run(
            host="0.0.0.0",
            port=port,
            debug=False,
            threaded=True,
            processes=1,
        )

    except KeyboardInterrupt:
        print("Application stopped by user")
        cleanup_resources()
    except Exception as e:
        print(f"Application failed to start: {e}")
        cleanup_resources()
        sys.exit(1)
    finally:
        cleanup_resources()


if __name__ == "__main__":
    main()
