import os
import concurrent.futures
import requests
from bs4 import BeautifulSoup
import yaml
from urllib.parse import urljoin, urlparse

URL_FILE = "success_urls.txt"
OUTPUT_FILE = "nodes.txt"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def extract_proxies_from_content(content):
    """尝试将文本解析为 YAML 并提取 proxies 列表"""
    try:
        data = yaml.safe_load(content)
    except Exception:
        try:
            clean_content = content.replace('!!', '')
            data = yaml.safe_load(clean_content)
        except Exception:
            return []

    proxies_found = []
    if isinstance(data, dict) and "proxies" in data:
        proxies = data["proxies"]
        if isinstance(proxies, list):
            for p in proxies:
                if isinstance(p, dict):
                    server = str(p.get("server", ""))
                    # 过滤本地回环及无效地址
                    if server and server not in ["127.0.0.1", "localhost", "0.0.0.0", "::1"]:
                        proxies_found.append(p)
    return proxies_found

def fetch_and_parse(target_url):
    target_url = target_url.strip()
    if not target_url or target_url.startswith("#"):
        return []

    proxies_found = []
    visited_links = set()

    try:
        # 1. 如果链接本身直接指向 yaml/yml，直接尝试下载解析
        if target_url.lower().endswith((".yaml", ".yml")):
            resp = requests.get(target_url, headers=headers, timeout=6)
            if resp.status_code == 200:
                return extract_proxies_from_content(resp.text)

        # 2. 否则，先访问主页，通过 BeautifulSoup 提取页面中所有指向 .yaml 或 .yml 的链接
        resp = requests.get(target_url, headers=headers, timeout=6)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            yaml_links = set()
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if href.lower().endswith((".yaml", ".yml")):
                    full_url = urljoin(target_url, href)
                    yaml_links.add(full_url)

            # 并行或依次请求页面里发现的随机 yaml 链接
            for y_url in yaml_links:
                if y_url in visited_links:
                    continue
                visited_links.add(y_url)
                try:
                    y_resp = requests.get(y_url, headers=headers, timeout=5)
                    if y_resp.status_code == 200:
                        res = extract_proxies_from_content(y_resp.text)
                        if res:
                            proxies_found.extend(res)
                            print(f"[成功] 从动态发现的链接 {y_url} 获取到 {len(res)} 个节点")
                except Exception:
                    continue

            # 3. 兜底策略：如果页面没有直接暴露出超链接，再顺便试一下常见命名
            if not proxies_found:
                base_url = target_url.rstrip("/")
                fallback_names = ["config.yaml", "config.yml", "proxy.yaml", "sub.yaml", "all.yaml"]
                for fname in fallback_names:
                    f_url = f"{base_url}/{fname}"
                    try:
                        f_resp = requests.get(f_url, headers=headers, timeout=4)
                        if f_resp.status_code == 200:
                            res = extract_proxies_from_content(f_resp.text)
                            if res:
                                proxies_found.extend(res)
                                break
                    except Exception:
                        continue

    except Exception as e:
        print(f"[Error] 访问 {target_url} 失败: {e}")

    return proxies_found

def main():
    if not os.path.exists(URL_FILE):
        print(f"未找到 {URL_FILE} 文件")
        return

    with open(URL_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    all_proxies = []
    # 线程池并行加速
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_and_parse, urls)
        for res in results:
            if res:
                all_proxies.extend(res)

    # 去重（基于 server, port, type）
    unique_proxies = {}
    for p in all_proxies:
        key = (p.get("server"), p.get("port"), p.get("type"))
        if key not in unique_proxies:
            unique_proxies[key] = p

    # 保存结果
    output_data = {"proxies": list(unique_proxies.values())}
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(output_data, f, allow_unicode=True, sort_keys=False)

    print(f"处理完成，共收集有效去重节点: {len(unique_proxies)} 个，已保存至 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
