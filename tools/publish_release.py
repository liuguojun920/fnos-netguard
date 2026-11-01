# -*- coding: utf-8 -*-
"""把打包好的 fpk 上传为 Gitee 发行版（Release）。

用法（在仓库根目录执行）：
    python tools/publish_release.py

需要 Gitee 私人令牌（Settings → 私人令牌，勾选 projects 权限），
通过环境变量传入，**不落盘、不进仓库**：

    export GITEE_TOKEN=xxxx
    python tools/publish_release.py

可选环境变量：
    GITEE_OWNER   仓库拥有者，默认 liuguojun920
    GITEE_REPO    仓库名，默认 fnos-netguard
    RELEASE_NOTE  发行说明文件路径，默认从 manifest 的 changelog 生成

流程：
    1. 找到 app.netguard-<版本>.fpk；
    2. 读 manifest 的 version 作为 tag（v1.0.22）；
    3. 创建 / 更新 Release；
    4. 上传 fpk 作为附件。
"""
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OWNER = os.environ.get("GITEE_OWNER", "liuguojun920")
REPO = os.environ.get("GITEE_REPO", "fnos-netguard")
API = "https://gitee.com/api/v5/repos/%s/%s" % (OWNER, REPO)
UA = "fnos-netguard-publisher"


def die(msg, code=1):
    print("ERROR: %s" % msg, file=sys.stderr)
    sys.exit(code)


def _manifest():
    with io.open(os.path.join(ROOT, "manifest"), "r", encoding="utf-8") as fh:
        return fh.read()


def version():
    m = re.search(r"^version\s*=\s*(\S+)", _manifest(), re.M)
    if not m:
        die("manifest 里读不到 version")
    return m.group(1).strip()


def changelog():
    m = re.search(r"^changelog\s*=\s*(.*)$", _manifest(), re.M)
    return m.group(1).strip() if m else ""


def find_pkg(ver):
    """优先 app.netguard-<ver>.fpk，其次任何 app.netguard*.fpk 里最新的。"""
    exact = os.path.join(ROOT, "app.netguard-%s.fpk" % ver)
    if os.path.exists(exact):
        return exact
    cands = sorted((os.path.join(ROOT, f) for f in os.listdir(ROOT)
                    if f.endswith(".fpk")), key=os.path.getmtime, reverse=True)
    if cands:
        return cands[0]
    die("找不到 .fpk，请先跑 python tools/build_fpk.py")


def api(method, path, token, data=None, files=None):
    """调 Gitee API。files 为待上传附件（multipart）。"""
    url = path if path.startswith("http") else API + path
    params = {"access_token": token}
    body = None
    headers = {"User-Agent": UA, "Accept": "application/json"}

    if files:
        boundary = "----fnosnetguard%s" % os.getpid()
        buf = io.BytesIO()
        for k, v in (data or {}).items():
            buf.write(("--%s\r\n" % boundary).encode("utf-8"))
            buf.write(('Content-Disposition: form-data; name="%s"\r\n\r\n' % k).encode("utf-8"))
            buf.write(str(v).encode("utf-8") + b"\r\n")
        for field, path_ in files.items():
            fname = os.path.basename(path_)
            with open(path_, "rb") as fh:
                content = fh.read()
            buf.write(("--%s\r\n" % boundary).encode("utf-8"))
            buf.write(('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
                       % (field, fname)).encode("utf-8"))
            buf.write(b"Content-Type: application/octet-stream\r\n\r\n")
            buf.write(content + b"\r\n")
        buf.write(("--%s--\r\n" % boundary).encode("utf-8"))
        body = buf.getvalue()
        headers["Content-Type"] = "multipart/form-data; boundary=%s" % boundary
    elif data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    if body is None:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    else:
        params_enc = urllib.parse.urlencode(params)
        url = url + ("&" if "?" in url else "?") + params_enc

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        die("%s %s -> HTTP %s\n%s" % (method, path, exc.code, detail))
    except Exception as exc:
        die("%s %s -> %s" % (method, path, exc))
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def main():
    token = os.environ.get("GITEE_TOKEN", "").strip()
    if not token:
        die("缺少环境变量 GITEE_TOKEN（Gitee 私人令牌，勾选 projects 权限）")

    ver = version()
    tag = "v%s" % ver
    pkg = find_pkg(ver)
    size = os.path.getsize(pkg)
    print("版本   : %s  (tag %s)" % (ver, tag))
    print("附件   : %s  (%.1f KB)" % (os.path.basename(pkg), size / 1024.0))

    note_file = os.environ.get("RELEASE_NOTE")
    if note_file and os.path.exists(note_file):
        with io.open(note_file, "r", encoding="utf-8") as fh:
            body = fh.read().strip()
    else:
        body = changelog()
    print("说明   : %d 字" % len(body))

    # 1. 查是否已有同 tag 的 Release
    existing = api("GET", "/releases/tags/%s" % tag, token)
    if isinstance(existing, dict) and existing.get("id"):
        rid = existing["id"]
        print("已有 Release #%s，更新" % rid)
        api("PATCH", "/releases/%s" % rid, token,
            data={"tag_name": tag, "name": "网络守卫 %s" % ver, "body": body,
                  "prerelease": "false"})
    else:
        res = api("POST", "/releases", token,
                  data={"tag_name": tag, "name": "网络守卫 %s" % ver, "body": body,
                        "prerelease": "false"})
        rid = res.get("id")
        if not rid:
            die("创建 Release 失败：%s" % json.dumps(res, ensure_ascii=False)[:300])
        print("已创建 Release #%s" % rid)

    # 2. 上传附件（同名附件先删，避免重复）
    atts = api("GET", "/releases/%s/attach_files" % rid, token) or []
    for a in atts:
        if a.get("name") == os.path.basename(pkg):
            api("DELETE", "/repos/%s/%s/releases/attach_files/%s"
                % (OWNER, REPO, urllib.parse.quote(a["name"], safe="")), token)
            print("已移除同名旧附件")

    res = api("POST", "/releases/%s/attach_files" % rid, token,
              data={"name": os.path.basename(pkg)}, files={"file": pkg})
    print("附件上传完成：%s" % (res.get("name") or os.path.basename(pkg)))

    url = "https://gitee.com/%s/%s/releases/tag/%s" % (OWNER, REPO, tag)
    print("\n发行版地址：%s" % url)


if __name__ == "__main__":
    main()
