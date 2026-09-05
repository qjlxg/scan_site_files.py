import os
import csv
from urllib.parse import urlparse

# ============================================================
# 配置
# ============================================================
CSV_INPUT = "site_files_scan.csv"
OUTPUT_M3U = "playlist.m3u"

# 支持的视频扩展名（转为大写以便统一匹配）
VIDEO_EXTS = {"MP4", "MKV", "AVI", "MOV", "FLV", "WEBM", "M4V", "TS", "M3U8"}

def main():
    if not os.path.exists(CSV_INPUT):
        print(f"未找到输入文件: {CSV_INPUT}")
        return

    m3u_lines = ["#EXTM3U"]
    count = 0

    with open(CSV_INPUT, "r", encoding="utf-8", errors="ignore") as f:
        cleaned_lines = (line.replace("\x00", "") for line in f)
        reader = csv.reader(cleaned_lines)
        
        for row in reader:
            if len(row) > 3:
                full_url = row[3].strip()
                if not full_url or full_url.startswith("FullURL") or full_url.startswith("BaseSite"):
                    continue
                
                # 准确解析 URL 路径，避开 ?后面的参数干扰
                parsed_url = urlparse(full_url)
                path = parsed_url.path
                filename = os.path.basename(path)
                
                if "." in filename:
                    ext = filename.split(".")[-1].upper()
                else:
                    ext = ""

                if ext in VIDEO_EXTS:
                    title = os.path.splitext(filename)[0]
                    m3u_lines.append(f"#EXTINF:-1,{title}")
                    m3u_lines.append(full_url)
                    count += 1

    with open(OUTPUT_M3U, "w", encoding="utf-8") as f:
        f.write("\n".join(m3u_lines) + "\n")

    print(f"转换完成！成功从 CSV 第四列提取并写入 {count} 个视频链接到 {OUTPUT_M3U}")

if __name__ == "__main__":
    main()
