# ... header

import asyncio
import time
from typing import Dict, Any, List, Optional
import aiohttp
from yarl import URL

async def _fetch_text(resp: aiohttp.ClientResponse) -> str:
    try:
        return await resp.text(errors="ignore")
    except Exception:
        try:
            b = await resp.read()
            return b.decode("utf-8", "ignore")
        except Exception:
            return ""

async def check_single_page(session: aiohttp.ClientSession, page: Dict[str, Any]) -> Dict[str, Any]:
    url = page.get("url")
    method = page.get("method", "GET").upper()
    headers = page.get("headers", {})
    verify_ssl = page.get("verify_ssl", True)
    timeout = page.get("timeout", 10)
    expected_status = page.get("expected_status", 200)
    must_contain: Optional[str] = page.get("must_contain")
    must_not_contain: Optional[str] = page.get("must_not_contain")
    slow_ms_threshold = int(page.get("slow_ms_threshold", 1500))

    result: Dict[str, Any] = {
        "url": url, "method": method, "status": None, "response_time": None,
        "success": False, "error": None, "title": None, "content_preview": None,
        "final_url": None, "redirects": 0,
        "headers": {}, "meta": {}, "warnings": []
    }

    start_time = time.time()
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with session.request(
            method=method, url=url, headers=headers,
            timeout=timeout_obj, ssl=verify_ssl, allow_redirects=True
        ) as resp:
            elapsed_ms = (time.time() - start_time) * 1000
            result["response_time"] = round(elapsed_ms, 2)
            result["status"] = resp.status
            result["final_url"] = str(resp.url)
            result["redirects"] = len(resp.history)
            # headers snapshot
            h = {k: v for k, v in resp.headers.items()}
            result["headers"] = h

            text = await _fetch_text(resp)
            result["content_preview"] = text[:200].replace("\n", " ")

            # title extraction
            try:
                lower = text.lower()
                s = lower.find("<title>")
                e = lower.find("</title>")
                if s != -1 and e != -1 and e > s:
                    result["title"] = text[s+7:e].strip()
            except Exception:
                pass

            # Success by status
            if resp.status == expected_status:
                result["success"] = True
            else:
                result["error"] = f"Unexpected status: {resp.status} (expected {expected_status})"

            # Content checks
            if must_contain and result["success"] and must_contain not in text:
                result["success"] = False
                result["error"] = f"Required text not found: {must_contain!r}"

            if must_not_contain and result["success"] and must_not_contain in text:
                result["success"] = False
                result["error"] = f"Forbidden text found: {must_not_contain!r}"

            # Meta info for perf/security
            ct = h.get("Content-Type")
            clen = h.get("Content-Length")
            cc = h.get("Cache-Control", "")
            enc = h.get("Content-Encoding", "")
            server = h.get("Server")
            hsts = h.get("Strict-Transport-Security")
            cors = h.get("Access-Control-Allow-Origin")

            result["meta"] = {
                "content_type": ct, "content_length": clen,
                "cache_control": cc, "content_encoding": enc,
                "server": server, "hsts": hsts,
                "cors_acao": cors
            }

            # Warnings & best practices
            if result["response_time"] and result["response_time"] >= slow_ms_threshold:
                result["warnings"].append(f"Slow response >= {slow_ms_threshold} ms")

            # compression
            uses_compression = enc and any(tok in enc.lower() for tok in ("gzip", "br", "zstd"))
            if not uses_compression:
                result["warnings"].append("No content compression (gzip/br/zstd) detected")

            # cache guidance for static pages
            if cc == "" and "text/html" in (ct or "") and result["redirects"] == 0:
                result["warnings"].append("No Cache-Control header for HTML response")

            # https redirect consistency
            try:
                parsed = URL(url)
                if parsed.scheme == "http":
                    # if initial was http and ended as https
                    result["https_redirect_ok"] = str(resp.url).startswith("https://")
                    if not result["https_redirect_ok"]:
                        result["warnings"].append("No HTTP->HTTPS redirect")
                else:
                    result["https_redirect_ok"] = True
            except Exception:
                pass

            # HSTS on https
            if str(resp.url).startswith("https://") and not hsts:
                result["warnings"].append("Missing HSTS header")

            # Next.js static assets exposure hint (/_next/static)
            try:
                base = str(URL(result["final_url"]).with_query(None).with_fragment(None))
                if not base.endswith("/"):
                    base += "/"
                static_url = base + "_next/static/"
                # lightweight HEAD to check listing
                try:
                    async with session.get(static_url, timeout=5, ssl=verify_ssl) as sresp:
                        if sresp.status == 200:
                            # likely no directory listing; OK
                            result["nextjs_static_ok"] = True
                        elif sresp.status in (301,302,403,404):
                            result["nextjs_static_ok"] = True
                        else:
                            result["nextjs_static_ok"] = False
                except Exception:
                    result["nextjs_static_ok"] = None
            except Exception:
                pass

            # robots.txt / sitemap.xml presence (non-fatal)
            try:
                site_root = str(URL(result["final_url"]).with_path("/").with_query(None).with_fragment(None))
                robots_url = site_root + "robots.txt"
                sitemap_url = site_root + "sitemap.xml"
                robots_ok = None
                sitemap_present = None
                try:
                    async with session.get(robots_url, timeout=5, ssl=verify_ssl) as r1:
                        robots_ok = r1.status in (200, 404)  # 404 is acceptable
                except Exception:
                    robots_ok = None
                try:
                    async with session.get(sitemap_url, timeout=5, ssl=verify_ssl) as r2:
                        sitemap_present = (r2.status == 200)
                except Exception:
                    sitemap_present = None
                result["robots_ok"] = robots_ok
                result["sitemap_present"] = sitemap_present
            except Exception:
                pass

    except asyncio.TimeoutError:
        result["error"] = f"Timeout after {timeout}s"
        result["response_time"] = round(timeout * 1000, 2)
    except aiohttp.ClientError as e:
        result["error"] = f"Connection error: {e}"
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    return result


async def check_web_pages(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Runs checks for all configured web pages
    @param config Configuration dict from `page_monitoring`
    @return Summary results for all pages
    """
    pages: List[Dict[str, Any]] = config.get("pages", [])

    if not pages:
        return {
            "total": 0,
            "successful": 0,
            "failed": 0,
            "avg_response_time": 0.0,
            "results": [],
        }

    connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
    timeout = aiohttp.ClientTimeout(total=config.get("total_timeout", 60))

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [check_single_page(session, page) for page in pages]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    processed: List[Dict[str, Any]] = []
    successful = 0
    failed = 0

    for i, item in enumerate(results):
        if isinstance(item, Exception):
            page_cfg = pages[i]
            processed.append(
                {
                    "url": page_cfg.get("url", "unknown"),
                    "method": page_cfg.get("method", "GET").upper(),
                    "status": None,
                    "response_time": None,
                    "success": False,
                    "error": str(item),
                }
            )
            failed += 1
        else:
            processed.append(item)
            if item.get("success"):
                successful += 1
            else:
                failed += 1

    # compute average response time
    times = [r.get("response_time") for r in processed if r.get("response_time") is not None]
    avg_time = round(sum(times) / len(times), 2) if times else 0.0

    return {
        "total": len(pages),
        "successful": successful,
        "failed": failed,
        "avg_response_time": avg_time,
        "results": processed,
    }