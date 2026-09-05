import os
from urllib.parse import urlparse

# ============================================================
# 配置
# ============================================================
INPUT_TXT = "success_urls.txt"
OUTPUT_M3U = "playlist.m3u"

# 支持的视频扩展名（可按需增减）
VIDEO_EXTS = {"MP4", "MKV", "AVI", "MOV", "FLV", "WEBM", "M4V"}

def main():
    if not os.path.exists(INPUT_TXT):
        print(f"未找到输入文件: {INPUT_TXT}")
        return

    with open(INPUT_TXT, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    m3u_lines = ["#EXTM3U"]
    count = 0

    for url in urls:
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        
        # 提取扩展名
        if "." in filename:
            ext = filename.split(".")[-1].upper()
        else:
            ext = ""

        # 如果只要视频格式，可以加上判断；如果不设限制，把下面这行 if 删掉即可全部转入
        if ext in VIDEO_EXTS:
            # 去掉后缀作为播放列表里的显示名称（或者直接用整个文件名）
            title = os.path.splitext(filename)[0]
            m3u_lines.append(f"#EXTINF:-1,{title}")
            m3u_lines.append(url)
            count += 1

    with open(OUTPUT_M3U, "w", encoding="utf-8") as f:
        f.write("\n".join(m3u_lines) + "\n")

    print(f"转换完成！成功写入 {count} 个视频链接到 {OUTPUT_M3U}")

if __name__ == "__main__":
    main()