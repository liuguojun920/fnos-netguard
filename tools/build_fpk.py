# -*- coding: utf-8 -*-
"""重新打包 fpk：修正权限位 + 同步 manifest 里的 checksum。

fnOS 安装时会校验 checksum 并要求脚本可执行，Windows 上直接打包会丢权限位，
所以这里用 Python 手工重建两层 tar。

产物名带版本号（app.netguard-1.0.22.fpk），直接当发行版上传用，
免得下载的人分不清是哪个版本。版本号从 manifest 读，与包内一致。

用法（在仓库根目录执行）：
    python tools/build_fpk.py
"""
import hashlib
import io
import os
import re
import shutil
import tarfile

# 本脚本在 tools/ 下，仓库根目录是它的上一级 —— 打包源（app/ cmd/ config/
# manifest / ICON）都在根目录。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = ROOT


def _read_version():
    """从 manifest 里读版本号（拿不到就用未知）。"""
    try:
        with open(os.path.join(PKG, "manifest"), "r", encoding="utf-8") as fh:
            m = re.search(r"^version\s*=\s*(\S+)", fh.read(), re.M)
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return "unknown"


VERSION = _read_version()
OUT = os.path.join(PKG, "app.netguard-%s.fpk" % VERSION)

EXEC_SUFFIX = (".sh", ".py")
DIR_MODE = 0o755
EXEC_MODE = 0o755
DATA_MODE = 0o644


def add_tree(tar, base, arcroot, skip=()):
    names = sorted(os.listdir(base))
    for n in names:
        # 测试脚本 import 过 server.py 会留下 __pycache__，体积大且版本无意义，绝不入包
        if n in skip or n == "__pycache__" or n.endswith(".pyc"):
            continue
        src = os.path.join(base, n)
        arc = os.path.join(arcroot, n) if arcroot else n
        if os.path.isdir(src):
            ti = tar.gettarinfo(src, arc)
            ti.mode = DIR_MODE
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            tar.addfile(ti)
            add_tree(tar, src, arc)
        else:
            ti = tar.gettarinfo(src, arc)
            ti.mode = EXEC_MODE if n.endswith(EXEC_SUFFIX) else DATA_MODE
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            with open(src, "rb") as fh:
                tar.addfile(ti, fh)


# ---------- 内层：app.tgz ----------
app_dir = os.path.join(PKG, "app")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    add_tree(tar, app_dir, "")
app_bytes = buf.getvalue()
app_md5 = hashlib.md5(app_bytes).hexdigest()
print("app.tgz  %d bytes  md5=%s" % (len(app_bytes), app_md5))

# ---------- 同步 manifest ----------
manifest_path = os.path.join(PKG, "manifest")
with open(manifest_path, "r", encoding="utf-8") as fh:
    lines = fh.read().splitlines()
out_lines = []
for ln in lines:
    if ln.startswith("checksum"):
        continue
    out_lines.append(ln)
out_lines.append("checksum              = %s" % app_md5)
with open(manifest_path, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(out_lines) + "\n")
print("manifest checksum ->", app_md5)

# ---------- 外层：fpk ----------
# 关键：fnpack 产出的 fpk 外层是 gzip 压缩的 tar（tar.gz），
# 用 mode="w"（裸 tar）会被 fnOS 安装器判为"不是有效的 fpk 文件"。
tmp = OUT + ".tmp"
with tarfile.open(tmp, mode="w:gz") as tar:
    ti = tarfile.TarInfo("app.tgz")
    ti.size = len(app_bytes)
    ti.mode = DATA_MODE
    ti.mtime = int(os.path.getmtime(manifest_path))
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    tar.addfile(ti, io.BytesIO(app_bytes))

    # cmd/* 必须可执行
    cmd_dir = os.path.join(PKG, "cmd")
    ti = tarfile.TarInfo("cmd")
    ti.type = tarfile.DIRTYPE
    ti.mode = DIR_MODE
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    tar.addfile(ti)
    for n in sorted(os.listdir(cmd_dir)):
        src = os.path.join(cmd_dir, n)
        t2 = tar.gettarinfo(src, "cmd/" + n)
        t2.mode = EXEC_MODE
        t2.uid = t2.gid = 0
        t2.uname = t2.gname = "root"
        with open(src, "rb") as fh:
            tar.addfile(t2, fh)

    for d in ("config",):
        src_dir = os.path.join(PKG, d)
        ti = tarfile.TarInfo(d)
        ti.type = tarfile.DIRTYPE
        ti.mode = DIR_MODE
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = "root"
        tar.addfile(ti)
        for n in sorted(os.listdir(src_dir)):
            src = os.path.join(src_dir, n)
            t2 = tar.gettarinfo(src, "%s/%s" % (d, n))
            t2.mode = DATA_MODE
            t2.uid = t2.gid = 0
            t2.uname = t2.gname = "root"
            with open(src, "rb") as fh:
                tar.addfile(t2, fh)

    for n in ("ICON.PNG", "ICON_256.PNG", "manifest"):
        src = os.path.join(PKG, n)
        t2 = tar.gettarinfo(src, n)
        t2.mode = DATA_MODE
        t2.uid = t2.gid = 0
        t2.uname = t2.gname = "root"
        with open(src, "rb") as fh:
            tar.addfile(t2, fh)

# 沙箱里 os.replace/remove 可能被拦，先尝试替换再退化为拷贝
try:
    os.replace(tmp, OUT)
except Exception:
    shutil.copyfile(tmp, OUT)
    try:
        os.remove(tmp)
    except Exception:
        pass

# ---------- 自检 ----------
with tarfile.open(OUT) as t:
    data = t.extractfile("app.tgz").read()
    ok_md5 = hashlib.md5(data).hexdigest() == app_md5
    modes = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as inner:
        for m in inner.getmembers():
            modes[m.name] = oct(m.mode)
        pyc = [m.name for m in inner.getmembers()
               if m.name.endswith(".pyc") or "__pycache__" in m.name]
    cmd_modes = {m.name: oct(m.mode) for m in t.getmembers() if m.name.startswith("cmd/")}

print("\n=== 包内自检 ===")
print("outer md5 match :", ok_md5)
for k in ("server/server.py", "server/net-guard.sh", "server/www/index.html"):
    print("  %-26s %s" % (k, modes.get(k)))
print("  cmd/main                   ", cmd_modes.get("cmd/main"))
print("  cmd/install_callback       ", cmd_modes.get("cmd/install_callback"))
print("size: %.1f KB" % (os.path.getsize(OUT) / 1024.0))
assert ok_md5, "checksum 不一致"
assert not pyc, "包内混入了字节码缓存：%s" % pyc
assert modes.get("server/server.py") == "0o755"
assert modes.get("server/net-guard.sh") == "0o755"
assert cmd_modes.get("cmd/main") == "0o755"
print("\nBUILD OK ->", OUT)
