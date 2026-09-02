import os
import csv
import time
import threading
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

URL_FILE = "url.txt"
CSV_OUTPUT = "site_files_scan.csv"
TXT_OUTPUT = "success_urls.txt"

# 保持旧版 UA，便于和旧版做严格对比
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# ==========================
# 诊断参数
# ==========================
HEARTBEAT_INTERVAL = 15          # GitHub Actions 每 15 秒输出一次心跳
SITE_PROGRESS_INTERVAL = 10      # 单站点每完成多少个链接输出一次进度
PRINT_SITE_START = True
PRINT_SITE_DONE = True

# 全局诊断状态
stats_lock = threading.Lock()
stats = {
    "sites_total": 0,
    "sites_started": 0,
    "sites_finished": 0,
    "sites_failed": 0,
    "links_discovered": 0,
    "links_submitted": 0,
    "links_finished": 0,
    "read_success": 0,
    "read_failed": 0,
    "discovered_only": 0,
    "binary": 0,
}

active_sites = {}
stop_heartbeat = threading.Event()


def heartbeat():
    """低频心跳，避免 GitHub 日志长时间没有输出而误判卡死。"""
    while not stop_heartbeat.wait(HEARTBEAT_INTERVAL):
        with stats_lock:
            s = stats.copy()
            active = list(active_sites.values())

        active_text = ""
        if active:
            # 最多显示前 5 个正在处理的网站，避免日志爆炸
            active_text = " | 活跃: " + " ; ".join(active[:5])
            if len(active) > 5:
                active_text += f" ...(+{len(active) - 5})"

        print(
            f"[心跳] 网站 {s['sites_finished']}/{s['sites_total']} | "
            f"发现链接 {s['links_discovered']} | "
            f"已完成检查 {s['links_finished']}/{s['links_submitted']} | "
            f"成功读取 {s['read_success']} | "
            f"失败 {s['read_failed']}"
            f"{active_text}",
            flush=True
        )


def fetch_page_with_fallback(session, raw_url):
    raw_url = raw_url.strip()
    if not raw_url:
        return None, None

    if raw_url.lower().startswith("http://"):
        candidates = [raw_url, "https://" + raw_url[7:]]
    elif raw_url.lower().startswith("https://"):
        candidates = [raw_url, "http://" + raw_url[8:]]
    else:
        candidates = [f"http://{raw_url}", f"https://{raw_url}"]

    for url in candidates:
        try:
            resp = session.get(url, headers=headers, timeout=6)
            if resp.status_code == 200:
                return url, resp
        except Exception:
            continue

    return None, None


def check_single_link(session, base_url, full_url, file_name, file_ext):
    file_content_snippet = ""
    status = "Discovered Only"
    target_exts = ("YAML", "YML", "TXT", "MD", "CONF", "JSON", "INI", "LOG", "CFG")

    try:
        if file_ext in target_exts or not file_name:
            try:
                file_resp = session.get(
                    full_url,
                    headers=headers,
                    timeout=4,
                    stream=True
                )

                if file_resp.status_code == 200:
                    content_bytes = b""
                    max_bytes = 100 * 1024

                    for chunk in file_resp.iter_content(chunk_size=4096):
                        content_bytes += chunk
                        if len(content_bytes) >= max_bytes:
                            break

                    try:
                        file_content_snippet = content_bytes.decode(
                            "utf-8", errors="ignore"
                        )[:500]
                        status = "Read Success"
                    except Exception:
                        file_content_snippet = "[Binary or Undecodable Content]"
                        status = "Binary Content"

            except Exception as e:
                status = f"Read Failed: {str(e)[:30]}"

    except Exception as e:
        status = f"Read Failed: {str(e)[:30]}"

    return {
        "BaseSite": base_url,
        "FileName": file_name if file_name else "Index/Root",
        "FileExtension": file_ext,
        "FullURL": full_url,
        "Status": status,
        "ContentSnippet": file_content_snippet.replace("\n", " ").strip()
    }


def scan_single_url(target_line, txt_file_path):
    target_line = target_line.strip()

    if not target_line or target_line.startswith("#"):
        return []

    thread_name = threading.current_thread().name

    with stats_lock:
        stats["sites_started"] += 1
        active_sites[thread_name] = target_line

    if PRINT_SITE_START:
        print(f"[开始] {target_line}", flush=True)

    site_start = time.monotonic()

    try:
        with requests.Session() as session:
            base_url, resp = fetch_page_with_fallback(session, target_line)

            if not base_url or not resp:
                with stats_lock:
                    stats["sites_failed"] += 1
                    active_sites.pop(thread_name, None)

                print(f"[跳过] 无法连接: {target_line}", flush=True)
                return []

            print(f"[主页成功] {base_url}", flush=True)

            results = []
            visited_links = set()
            links_to_check = []

            try:
                soup = BeautifulSoup(resp.text, "html.parser")

                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()

                    if not href or href.startswith(
                        ("#", "javascript:", "mailto:", "tel:")
                    ):
                        continue

                    full_url = urljoin(base_url, href)

                    if full_url in visited_links:
                        continue

                    visited_links.add(full_url)

                    parsed_path = urlparse(full_url)
                    file_name = os.path.basename(parsed_path.path)

                    if not file_name or "." not in file_name:
                        file_ext = "DIRECTORY/HTML"
                    else:
                        file_ext = file_name.split(".")[-1].upper()

                    links_to_check.append(
                        (base_url, full_url, file_name, file_ext)
                    )

                discovered_count = len(links_to_check)

                with stats_lock:
                    stats["links_discovered"] += discovered_count
                    stats["links_submitted"] += discovered_count

                print(
                    f"[链接发现] {base_url} | 本页 {discovered_count} 个唯一链接",
                    flush=True
                )

                if discovered_count == 0:
                    elapsed = time.monotonic() - site_start

                    with stats_lock:
                        stats["sites_finished"] += 1
                        active_sites.pop(thread_name, None)

                    if PRINT_SITE_DONE:
                        print(
                            f"[完成] {base_url} | 0 链接 | {elapsed:.1f}s",
                            flush=True
                        )

                    return results

                completed_local = 0
                success_local = 0
                failed_local = 0

                # 保持原版：每个网站内部仍然使用 5 个线程
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=5
                ) as inner_executor:

                    futures = [
                        inner_executor.submit(
                            check_single_link,
                            session,
                            b_url,
                            f_url,
                            f_name,
                            f_ext
                        )
                        for b_url, f_url, f_name, f_ext in links_to_check
                    ]

                    for future in concurrent.futures.as_completed(futures):
                        try:
                            res = future.result()
                        except Exception as e:
                            # 防止单个 Future 异常导致整个站点任务异常退出
                            completed_local += 1

                            with stats_lock:
                                stats["links_finished"] += 1
                                stats["read_failed"] += 1

                            failed_local += 1

                            if (
                                completed_local == 1
                                or completed_local % SITE_PROGRESS_INTERVAL == 0
                                or completed_local == discovered_count
                            ):
                                print(
                                    f"[检查异常] {base_url} | "
                                    f"{completed_local}/{discovered_count} | "
                                    f"{str(e)[:80]}",
                                    flush=True
                                )
                            continue

                        completed_local += 1

                        with stats_lock:
                            stats["links_finished"] += 1

                        if res:
                            results.append(res)

                            if res["Status"] == "Read Success":
                                success_local += 1

                                with stats_lock:
                                    stats["read_success"] += 1

                            elif res["Status"] == "Read Failed":
                                failed_local += 1

                                with stats_lock:
                                    stats["read_failed"] += 1

                            elif res["Status"] == "Binary Content":
                                with stats_lock:
                                    stats["binary"] += 1

                            else:
                                with stats_lock:
                                    stats["discovered_only"] += 1

                        # 降低 GitHub 日志量：
                        # 不再每成功一个 URL 都打印，只打印固定间隔/完成节点。
                        if (
                            completed_local == 1
                            or completed_local % SITE_PROGRESS_INTERVAL == 0
                            or completed_local == discovered_count
                        ):
                            print(
                                f"[检查进度] {base_url} | "
                                f"{completed_local}/{discovered_count} | "
                                f"读取成功 {success_local} | "
                                f"失败 {failed_local}",
                                flush=True
                            )

                elapsed = time.monotonic() - site_start

                with stats_lock:
                    stats["sites_finished"] += 1
                    active_sites.pop(thread_name, None)

                if PRINT_SITE_DONE:
                    print(
                        f"[完成] {base_url} | "
                        f"链接 {discovered_count} | "
                        f"成功 {success_local} | "
                        f"失败 {failed_local} | "
                        f"耗时 {elapsed:.1f}s",
                        flush=True
                    )

                return results

            except Exception as e:
                with stats_lock:
                    stats["sites_failed"] += 1
                    stats["sites_finished"] += 1
                    active_sites.pop(thread_name, None)

                print(
                    f"[解析异常] {base_url} | {str(e)[:120]}",
                    flush=True
                )
                return []

    except Exception as e:
        with stats_lock:
            stats["sites_failed"] += 1
            stats["sites_finished"] += 1
            active_sites.pop(thread_name, None)

        print(
            f"[目标异常] {target_line} | {str(e)[:120]}",
            flush=True
        )
        return []


def main():
    total_start = time.monotonic()

    if not os.path.exists(URL_FILE):
        print(f"未找到 {URL_FILE} 文件", flush=True)
        return

    with open(URL_FILE, "r", encoding="utf-8") as f:
        urls = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    with stats_lock:
        stats["sites_total"] = len(urls)

    # 初始化输出文件
    with open(TXT_OUTPUT, "w", encoding="utf-8"):
        pass

    all_scan_results = []

    print(
        f"[启动] 开始扫描 | 网站数: {len(urls)} | "
        f"外层线程: 5 | 内层线程: 5 | "
        f"主页超时: 6s | 文件请求超时: 4s",
        flush=True
    )

    heartbeat_thread = threading.Thread(
        target=heartbeat,
        name="diagnostic-heartbeat",
        daemon=True
    )
    heartbeat_thread.start()

    try:
        # 保持原版：外层仍然 5 个线程
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=5
        ) as executor:

            future_to_url = {
                executor.submit(scan_single_url, url, TXT_OUTPUT): url
                for url in urls
            }

            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]

                try:
                    res = future.result()

                    if res:
                        all_scan_results.extend(res)

                except Exception as e:
                    print(
                        f"[外层任务异常] {url} | {str(e)[:120]}",
                        flush=True
                    )

    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=2)

    scan_elapsed = time.monotonic() - total_start

    print(
        f"[扫描阶段结束] 耗时 {scan_elapsed:.1f}s | "
        f"网站完成 {stats['sites_finished']}/{stats['sites_total']} | "
        f"结果 {len(all_scan_results)}",
        flush=True
    )

    # ==========================
    # CSV 写入阶段
    # ==========================
    csv_start = time.monotonic()
    print(
        f"[CSV开始] 准备写入 {len(all_scan_results)} 条记录...",
        flush=True
    )

    csv_columns = [
        "BaseSite",
        "FileName",
        "FileExtension",
        "FullURL",
        "Status",
        "ContentSnippet"
    ]

    with open(
        CSV_OUTPUT,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=csv_columns
        )
        writer.writeheader()

        for index, data in enumerate(all_scan_results, 1):
            writer.writerow(data)

            if index % 10000 == 0:
                print(
                    f"[CSV进度] {index}/{len(all_scan_results)}",
                    flush=True
                )

    csv_elapsed = time.monotonic() - csv_start

    print(
        f"[CSV完成] {len(all_scan_results)} 条 | "
        f"耗时 {csv_elapsed:.1f}s",
        flush=True
    )

    # ==========================
    # TXT 写入阶段
    # ==========================
    txt_start = time.monotonic()

    success_count = 0

    print("[TXT开始] 写入成功读取 URL...", flush=True)

    with open(TXT_OUTPUT, "w", encoding="utf-8") as f_txt:
        for data in all_scan_results:
            if data["Status"] == "Read Success":
                f_txt.write(data["FullURL"] + "\n")
                success_count += 1

    txt_elapsed = time.monotonic() - txt_start
    total_elapsed = time.monotonic() - total_start

    # ==========================
    # 最终诊断汇总
    # ==========================
    with stats_lock:
        s = stats.copy()

    print("", flush=True)
    print("========== 诊断汇总 ==========", flush=True)
    print(f"网站总数       : {s['sites_total']}", flush=True)
    print(f"网站已完成     : {s['sites_finished']}", flush=True)
    print(f"网站连接失败   : {s['sites_failed']}", flush=True)
    print(f"发现链接总数   : {s['links_discovered']}", flush=True)
    print(f"检查完成       : {s['links_finished']}/{s['links_submitted']}", flush=True)
    print(f"读取成功       : {s['read_success']}", flush=True)
    print(f"读取失败       : {s['read_failed']}", flush=True)
    print(f"Binary         : {s['binary']}", flush=True)
    print(f"仅发现         : {s['discovered_only']}", flush=True)
    print(f"CSV 写入耗时   : {csv_elapsed:.1f}s", flush=True)
    print(f"TXT 写入耗时   : {txt_elapsed:.1f}s", flush=True)
    print(f"总耗时         : {total_elapsed:.1f}s", flush=True)
    print("==============================", flush=True)

    print(
        f"扫描完成！共发现并记录文件链接: {len(all_scan_results)} 个",
        flush=True
    )
    print(
        f"  - CSV 完整报告已保存至: {CSV_OUTPUT}",
        flush=True
    )
    print(
        f"  - 成功读取的 URL: {success_count} 个",
        flush=True
    )
    print(
        f"  - 成功读取的 URL 已保存至: {TXT_OUTPUT}",
        flush=True
    )


if __name__ == "__main__":
    main()
