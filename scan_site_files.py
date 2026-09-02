import os
import csv
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

URL_FILE = "url.txt"
CSV_OUTPUT = "site_files_scan.csv"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def scan_single_url(target_url):
    target_url = target_url.strip()
    if not target_url or target_url.startswith("#"):
        return []

    results = []
    visited_links = set()

    try:
        # 1. 请求目标主页
        resp = requests.get(target_url, headers=headers, timeout=8)
        if resp.status_code != 200:
            return []

        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # 2. 提取页面中所有的超链接，并严格拼接待检测的完整 URL
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            # 使用 urljoin 确保像 /SOUL.md 或 SOUL.md 能完美拼成 http://20.46.163.222:8000/SOUL.md
            full_url = urljoin(target_url, href)
            if full_url in visited_links:
                continue
            visited_links.add(full_url)

            # 解析文件名称和后缀
            parsed_path = urlparse(full_url)
            file_name = os.path.basename(parsed_path.path)
            
            if not file_name or "." not in file_name:
                file_ext = "DIRECTORY/HTML"
            else:
                file_ext = file_name.split('.')[-1].upper()

            # 3. 针对常见配置文件或文本文件（如 yaml, yml, txt, md, conf 等），尝试读取前几百KB内容
            file_content_snippet = ""
            status = "Discovered Only"
            
            # 扩展了常用文本/配置格式（包含 md、yaml、yml、txt 等）
            target_exts = ("YAML", "YML", "TXT", "MD", "CONF", "JSON", "INI", "LOG", "CFG")
            if file_ext in target_exts or not file_name:
                try:
                    file_resp = requests.get(full_url, headers=headers, timeout=5, stream=True)
                    if file_resp.status_code == 200:
                        content_bytes = b""
                        max_bytes = 300 * 1024  # 最大读取 300 KB
                        for chunk in file_resp.iter_content(chunk_size=4096):
                            content_bytes += chunk
                            if len(content_bytes) >= max_bytes:
                                break
                        
                        try:
                            file_content_snippet = content_bytes.decode('utf-8', errors='ignore')[:1000]
                            status = "Read Success"
                        except Exception:
                            file_content_snippet = "[Binary or Undecodable Content]"
                            status = "Binary Content"
                except Exception as e:
                    status = f"Read Failed: {str(e)[:30]}"

            results.append({
                "BaseSite": target_url,
                "FileName": file_name if file_name else "Index/Root",
                "FileExtension": file_ext,
                "FullURL": full_url,  # 这里存储的就是完整的绝对路径 URL（例如 http://20.46.163.222:8000/SOUL.md）
                "Status": status,
                "ContentSnippet": file_content_snippet.replace('\n', ' ').strip()
            })

    except Exception as e:
        print(f"[Error] 扫描网站 {target_url} 失败: {e}")

    return results

def main():
    if not os.path.exists(URL_FILE):
        print(f"未找到 {URL_FILE} 文件")
        return

    with open(URL_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    all_scan_results = []
    
    print(f"开始并行扫描 {len(urls)} 个网站...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(scan_single_url, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            res = future.result()
            if res:
                all_scan_results.extend(res)

    # 保存结果到 CSV 文件
    csv_columns = ["BaseSite", "FileName", "FileExtension", "FullURL", "Status", "ContentSnippet"]
    
    with open(CSV_OUTPUT, "w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in all_scan_results:
            writer.writerow(data)

    print(f"扫描完成！共发现并记录文件链接: {len(all_scan_results)} 个，已保存至 {CSV_OUTPUT}")

if __name__ == "__main__":
    main()
