import os
import csv
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# ============================================================
# 配置
# ============================================================

URL_FILE = "url.txt"
CSV_OUTPUT = "site_files_scan.csv"
TXT_OUTPUT = "success_urls.txt"

# 保持原来的 UA
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}

# 原脚本真正会读取内容的目标扩展名
TARGET_EXTS = {
    "YAML", "YML", "TXT"
}

# ============================================================
# 大目录页保护
#
# 目的不是改变正常网站的文件识别，而是防止：
#   1. 软件包镜像
#   2. distfiles/package 索引
#   3. 巨型目录列表
#   4. 自动生成的海量文件索引
#
# 把数万条链接全部提交给线程池。
#
# 正常网站一般几十/几百个链接，不会触发这里。
# ============================================================

# 发现超过这个数量后才进行“大目录页”结构判断
LARGE_PAGE_LINKS = 1200

# 极端目录页直接进入保护模式
HUGE_PAGE_LINKS = 10000

# 大目录页最多保留的“有价值候选”
LARGE_PAGE_MAX_CANDIDATES = 600

# 每批最多提交给线程池的任务数量，避免一次创建数万个 Future
CHECK_BATCH_SIZE = 100

# 页面内部同时检查的链接数
INNER_WORKERS = 5

# 外部同时扫描的网站数
OUTER_WORKERS = 5


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

    if file_ext in TARGET_EXTS or not file_name:
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

    return {
        "BaseSite": base_url,
        "FileName": file_name if file_name else "Index/Root",
        "FileExtension": file_ext,
        "FullURL": full_url,
        "Status": status,
        "ContentSnippet": file_content_snippet.replace("\n", " ").strip()
    }


def classify_links(links):
    """
    对已经发现的链接进行轻量结构判断。

    返回：
        normal_links       正常页面：保持原扫描能力
        protected_links    大目录页：只保留高价值候选
        skipped_count      被大目录保护主动跳过的链接数

    这里不做评分，也不改变普通网站的识别规则。
    """

    total = len(links)

    if total < LARGE_PAGE_LINKS:
        return links, [], 0, False

    # 统计目标扩展名数量
    target_links = []
    directory_links = []
    other_links = []

    for item in links:
        _, _, file_name, file_ext = item

        if file_ext in TARGET_EXTS:
            target_links.append(item)
        elif not file_name:
            directory_links.append(item)
        else:
            other_links.append(item)

    # 判断是否具有典型“海量目录/镜像”结构
    #
    # 关键原则：
    # - 有大量目标配置文件时，绝不因为目录大而直接跳过
    # - 目标扩展名本身就是我们真正要找的内容
    # - 只有在“链接极多 + 绝大多数不是目标文件”的情况下
    #   才进入保护
    non_target = total - len(target_links)

    target_ratio = len(target_links) / max(total, 1)

    # 典型大型索引页：
    #   > 1200 链接，且目标文件占比很低
    is_large_index = (
        total >= LARGE_PAGE_LINKS
        and (
            target_ratio < 0.20
            or total >= HUGE_PAGE_LINKS
        )
    )

    if not is_large_index:
        return links, [], 0, False

    # 大目录页：
    # 1. 所有目标扩展名全部保留
    # 2. 少量目录链接保留，用于保持发现能力
    # 3. 非目标海量文件不逐个发 HTTP 请求
    #
    # 目录链接只保留前面一小部分，避免镜像站不断向下扩散。
    protected = list(target_links)

    remaining_slots = max(0, LARGE_PAGE_MAX_CANDIDATES - len(protected))

    if remaining_slots:
        protected.extend(directory_links[:remaining_slots])

    # 不对其他普通文件逐个请求。
    # 仍然在 CSV 中保留“Discovered Only”记录，
    # 因此“发现”信息没有消失，只是不再产生海量 HTTP 请求。
    skipped = other_links + directory_links[len(
        protected) - len(target_links)
    :]

    return protected, skipped, len(skipped), True


def make_discovered_only_record(base_url, item):
    _, full_url, file_name, file_ext = item

    return {
        "BaseSite": base_url,
        "FileName": file_name if file_name else "Index/Root",
        "FileExtension": file_ext,
        "FullURL": full_url,
        "Status": "Discovered Only",
        "ContentSnippet": ""
    }


def scan_single_url(target_line, txt_file_path):
    target_line = target_line.strip()

    if not target_line or target_line.startswith("#"):
        return []

    print(f"[开始] 正在连接目标: {target_line}")

    with requests.Session() as session:
        base_url, resp = fetch_page_with_fallback(session, target_line)

        if not base_url or not resp:
            print(f"[跳过] 无法连接到目标: {target_line}")
            return []

        print(f"[成功] 成功连接主页: {base_url}")

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

            total_links = len(links_to_check)

            print(
                f"[链接发现] {base_url} | "
                f"本页 {total_links} 个唯一链接"
            )

            # ====================================================
            # 大目录页自动识别
            # ====================================================

            links_to_process, skipped_links, skipped_count, protected = (
                classify_links(links_to_check)
            )

            if protected:
                target_count = sum(
                    1 for x in links_to_process
                    if x[3] in TARGET_EXTS
                )

                print(
                    f"[大目录保护] {base_url} | "
                    f"原始链接 {total_links} | "
                    f"目标文件 {target_count} | "
                    f"实际检查 {len(links_to_process)} | "
                    f"跳过海量低价值链接 {skipped_count}"
                )

                # 被跳过的链接仍然进入 CSV，保持“发现能力”
                for item in skipped_links:
                    results.append(
                        make_discovered_only_record(base_url, item)
                    )

            # ====================================================
            # 重要优化：
            #
            # 原版会把所有链接都 submit 给线程池。
            # 但绝大多数非目标扩展名根本不会发 HTTP 请求。
            #
            # 现在：
            #   - 非目标文件：直接记录 Discovered Only
            #   - YAML/JSON/TXT/...：才进入 HTTP 检查
            #
            # 这不会改变原版最终识别规则，只减少无意义 Future。
            # ====================================================

            request_candidates = []
            direct_discovered = []

            for item in links_to_process:
                _, full_url, file_name, file_ext = item

                if file_ext in TARGET_EXTS or not file_name:
                    request_candidates.append(item)
                else:
                    direct_discovered.append(item)

            for item in direct_discovered:
                results.append(
                    make_discovered_only_record(base_url, item)
                )

            # ====================================================
            # 分批提交任务
            #
            # 防止一个 3~4 万链接页面一次创建 3~4 万 Future。
            # ====================================================

            total_candidates = len(request_candidates)
            completed = 0

            for start in range(0, total_candidates, CHECK_BATCH_SIZE):
                batch = request_candidates[
                    start:start + CHECK_BATCH_SIZE
                ]

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=INNER_WORKERS
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
                        for b_url, f_url, f_name, f_ext in batch
                    ]

                    for future in concurrent.futures.as_completed(futures):
                        try:
                            res = future.result()
                        except Exception as e:
                            print(
                                f"[检查异常] {base_url}: "
                                f"{str(e)[:80]}"
                            )
                            continue

                        if res:
                            results.append(res)

                            if res["Status"] == "Read Success":
                                print(
                                    f"  └── [读取成功] "
                                    f"{res['FullURL']}"
                                )

                        completed += 1

                # 大页面给出进度，普通页面也不改变结果
                if total_candidates >= 100:
                    print(
                        f"[检查进度] {base_url} | "
                        f"{completed}/{total_candidates} | "
                        f"结果 {len(results)}"
                    )

        except Exception as e:
            print(f"[Error] 解析页面 {base_url} 失败: {e}")

        return results


def main():
    if not os.path.exists(URL_FILE):
        print(f"未找到 {URL_FILE} 文件")
        return

    with open(URL_FILE, "r", encoding="utf-8") as f:
        urls = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    # 每次运行重新生成成功 URL 文件
    with open(TXT_OUTPUT, "w", encoding="utf-8"):
        pass

    all_scan_results = []

    print(f"开始并行扫描 {len(urls)} 个网站...")
    print(
        f"配置: 外部并发={OUTER_WORKERS}, "
        f"内部并发={INNER_WORKERS}, "
        f"批量={CHECK_BATCH_SIZE}, "
        f"大目录阈值={LARGE_PAGE_LINKS}"
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=OUTER_WORKERS
    ) as executor:

        future_to_url = {
            executor.submit(
                scan_single_url,
                url,
                TXT_OUTPUT
            ): url
            for url in urls
        }

        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]

            try:
                res = future.result()

                if res:
                    all_scan_results.extend(res)

            except Exception as e:
                print(f"[目标异常] {url}: {str(e)[:100]}")

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

        for data in all_scan_results:
            writer.writerow(data)

    # 成功 URL 统一写入
    with open(TXT_OUTPUT, "w", encoding="utf-8") as f_txt:
        for data in all_scan_results:
            if data["Status"] == "Read Success":
                f_txt.write(data["FullURL"] + "\n")

    discovered = len(all_scan_results)
    success = sum(
        1 for x in all_scan_results
        if x["Status"] == "Read Success"
    )
    failed = sum(
        1 for x in all_scan_results
        if x["Status"].startswith("Read Failed")
    )
    discovered_only = sum(
        1 for x in all_scan_results
        if x["Status"] == "Discovered Only"
    )

    print("\n" + "=" * 60)
    print("扫描完成")
    print("=" * 60)
    print(f"共发现并记录: {discovered}")
    print(f"读取成功:     {success}")
    print(f"读取失败:     {failed}")
    print(f"仅发现未读取: {discovered_only}")
    print(f"CSV: {CSV_OUTPUT}")
    print(f"成功 URL: {TXT_OUTPUT}")
    print("=" * 60)


if __name__ == "__main__":
    main()
