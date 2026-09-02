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

def fetch_page_with_fallback(raw_url):
    """先试 http://，不行再试 https://，最后放弃"""
    raw_url = raw_url.strip()
    if not raw_url:
        return None, None

    # 如果用户自带了协议，先按原样或拆分处理
    if raw_url.lower().startswith("http://"):
        candidates = [raw_url, "https://" + raw_url[7:]]
    elif raw_url.lower().startswith("https://"):
        candidates = [raw_url, "http://" + raw_url[8:]]
    else:
        # 纯 IP 或域名格式：先试 http，再试 https
        candidates = [f"http://{raw_url}", f"https://{raw_url}"]

    for url in candidates:
        try:
            resp = requests.get(url, headers=headers, timeout=6)
            if resp.status_code == 200:
                return url, resp
        except Exception:
            continue
            
    return None, None

def scan_single_url(target_line):
    target_line = target_line.strip()
    if not target_line or target_line.startswith("#"):
        return []

    # 使用多协议尝试连接主页
    base_url, resp = fetch_page_with_fallback(target_line)
    if not base_url or not resp:
        return []

    results = []
    visited_links = set()

    try:
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
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
                file_ext = file_name.split('.')[-1].upper()

            file_content_snippet = ""
            status = "Discovered Only"
            
            target_exts = ("YAML", "YML", "TXT", "MD", "CONF", "JSON", "INI", "LOG", "CFG")
            if file_ext in target_exts or not file_name:
                try:
                    file_resp = requests.get(full_url, headers=headers, timeout=5, stream=True)
                    if file_resp.status_code == 200:
                        content_bytes = b""
                        max_bytes = 300 * 1024
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
                "BaseSite": base_url,
                "FileName": file_name if file_name else "Index/Root",
                "FileExtension": file_ext,
                "FullURL": full_url,
                "Status": status,
                "ContentSnippet": file_content_snippet.replace('\n', ' ').strip()
            })

    except Exception as e:
        print(f"[Error] 解析页面 {base_url} 失败: {e}")

    return results

def main():
    if not os.path.exists(URL_FILE):
        print(f"未找到 {URL_FILE} 文件")
        return

    with open(URL_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    all_scan_results = []
    
    print(f"开始并行扫描 {len(urls)} 个网站（支持 HTTP/HTTPS 自动降级重试）...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(scan_single_url, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            res = future.result()
            if res:
                all_scan_results.extend(res)

    csv_columns = ["BaseSite", "FileName", "FileExtension", "FullURL", "Status", "ContentSnippet"]
    
    with open(CSV_OUTPUT, "w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in all_scan_results:
            writer.writerow(data)

    print(f"扫描完成！共发现并记录文件链接: {len(all_scan_results)} 个，已保存至 {CSV_OUTPUT}")

if __name__ == "__main__":
    main()
