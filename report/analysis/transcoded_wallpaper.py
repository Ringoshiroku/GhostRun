def extract_wallpaper_path(blob: bytes):
    if not blob:
        return None

    try:
        text = blob.decode("utf-16-le", errors="ignore")

        # cari pola drive letter, misal C:\ atau D:\
        for i in range(len(text) - 2):
            if text[i].isalpha() and text[i+1:i+3] == ":\\":
                path = text[i:].split("\x00")[0]
                return path.strip()

    except Exception:
        pass

    return None
