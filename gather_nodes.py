import os
import concurrent.futures
import requests
import yaml

URL_FILE = "url.txt"
OUTPUT_FILE = "nodes.txt"

# 常见根目录 YAML 文件名字典
COMMON_FILENAMES = [
    "config.yaml", "config.yml",
    "clash.yaml", "clash.yml",
    "proxy.yaml", "proxy.yml",
    "sub.yaml", "sub.yml",
    "all.yaml", "all.yml",
    "node.yaml", "node.yml",
    "data.yaml", "data.yml"
]

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def fetch_and_parse(target_url):
    target_url = target_url.strip()
    if not target_url or target_url.startswith("#"):
        return []

    urls_to_try = []
    if target_url.endswith((".yaml", ".yml")):
        urls_to_try.append(target_url)
    else:
        base_url = target_url.rstrip("/")
        for filename in COMMON_FILENAMES:
            urls_to_try.append(f"{base_url}/{filename}")
        # 同时尝试原链接本身
        urls_to_try.append(base_url)

    proxies_found = []
    for url in urls_to_try:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                content = response.text
                # 尝试解析 YAML
                data = None
                try:
                    data = yaml.safe_load(content)
                except Exception:
                    # 容错处理：清理部分不标准字符后再次尝试
                    try:
                        clean_content = content.replace('!!', '')
                        data = yaml.safe_load(clean_content)
                    except Exception:
                        continue

                if isinstance(data, dict) and "proxies" in data:
                    proxies = data["proxies"]
                    if isinstance(proxies, list):
                        for p in proxies:
                            if isinstance(p, dict):
                                server = str(p.get("server", ""))
                                # 过滤本地回环及无效地址
                                if server and server not in ["127.0.0.1", "localhost", "0.0.0.0", "::1"]:
                                    proxies_found.append(p)
                        if proxies_found:
                            print(f"[成功] 从 {url} 获取到 {len(proxies_found)} 个节点")
                            break
        except Exception:
            continue
    return proxies_found

def main():
    if not os.path.exists(URL_FILE):
        print(f"未找到 {URL_FILE} 文件")
        return

    with open(URL_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    all_proxies = []
    # 并行加速抓取
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_and_parse, urls)
        for res in results:
            if res:
                all_proxies.extend(res)

    # 去重（基于 server 和 port）
    unique_proxies = {}
    for p in all_proxies:
        key = (p.get("server"), p.get("port"), p.get("type"))
        if key not in unique_proxies:
            unique_proxies[key] = p

    # 保存为明文格式（输出为 YAML 格式的节点列表或自定义明文文本）
    output_data = {"proxies": list(unique_proxies.values())}
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(output_data, f, allow_unicode=True, sort_keys=False)

    print(f"共收集到有效去重节点: {len(unique_proxies)} 个，已保存至 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()