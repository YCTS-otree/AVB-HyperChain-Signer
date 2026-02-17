#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AVB 聚合式全自动链路签名工具（去重 descriptors / 原地覆盖 / RAW 强约束）

用法思路：
1) 传入 --keys（文件/文件夹均可） + --image（要签名的分区镜像）
2) 若 image Algorithm != NONE：直接重签该 image
3) 若 Algorithm == NONE：要求传入所有 vbmeta 镜像（--vbmeta_dir 或 --vbmetas）
   自动定位父 vbmeta -> 去掉旧 descriptor -> 合入新 descriptor -> 签名 -> pad 到原 vbmeta 大小 -> 覆盖

关键保证：
- 输出镜像与输入文件名一致（默认 inplace 覆盖）
- 自动备份 .bak_时间戳
- partition_size 默认取文件大小，并强制要求 RAW 分区 dump（拒绝 sparse）
- vbmeta 去重：移除旧分区 descriptor，避免重复导致 size 爆

依赖：
- Python 3.8+
- avbtool.py（同目录）
"""

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ------------------- avbtool 输出解析（够用就行，别搞成反编译器） -------------------
RE_ALGO = re.compile(r"^\s*Algorithm:\s*(.+?)\s*$", re.MULTILINE)
RE_PUBKEY_SHA1 = re.compile(r"^\s*Public key\s*\(sha1\)\s*:\s*([0-9a-fA-F]{40})\s*$", re.MULTILINE)
RE_PUBKEY_SHA256 = re.compile(r"^\s*Public key\s*\(sha256\)\s*:\s*([0-9a-fA-F]{64})\s*$", re.MULTILINE)
RE_PART_NAME = re.compile(r"^\s*Partition Name:\s*([A-Za-z0-9_]+)\s*$", re.MULTILINE)
RE_PART_SIZE = re.compile(r"^\s*Partition size:\s*([0-9]+)\s+bytes\s*$", re.MULTILINE)
RE_RB_INDEX_LOC = re.compile(r"^\s*Rollback Index Location:\s*([0-9]+)\s*$", re.MULTILINE)
RE_HASH_DESC = re.compile(r"^\s*Hash descriptor:\s*$", re.MULTILINE)
RE_HASHTREE_DESC = re.compile(r"^\s*Hashtree descriptor:\s*$", re.MULTILINE)
RE_ANY_PARTITION_NAME = re.compile(r"^\s*Partition Name:\s*([A-Za-z0-9_]+)\s*$", re.MULTILINE)

SPARSE_MAGIC = 0xED26FF3A

# ------------------- vbmeta 二进制结构（只做我们需要的那一部分） -------------------
# AVB vbmeta header: 256 bytes, big-endian
# 参考 libavb：struct AvbVBMetaImageHeader
VBMETA_HEADER_FMT = ">4sIIQQIQQQQQQQQQQQIIBB48s80s"
# 上面这个格式太容易写错（还涉及 flags/rollback_index_location 的布局），
# 所以我们不用“一把梭 struct unpack 到底”，而是按固定偏移读写关键字段。
# 关键字段偏移（字节）：
# magic(0) 4
# auth_size(12) u64
# aux_size(20) u64
# descriptors_offset(96) u64
# descriptors_size(104) u64
# header size = 256
OFF_MAGIC = 0

OFF_AUTH_SIZE = 12   # u64 big-endian
OFF_AUX_SIZE  = 20   # u64 big-endian

OFF_DESC_OFF  = 96   # u64 big-endian (relative to aux block start)
OFF_DESC_SIZE = 104  # u64 big-endian

HEADER_SIZE = 256

def u64be(b: bytes) -> int:
    return struct.unpack(">Q", b)[0]

def p64be(x: int) -> bytes:
    return struct.pack(">Q", x)

def die(msg: str, code: int = 2) -> None:
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)

def now_tag() -> str:
    return time.strftime("%Y%m%d_%H%M%S")

def backup_file(p: Path) -> Path:
    bak = p.with_suffix(p.suffix + f".bak_{now_tag()}")
    shutil.copy2(p, bak)
    return bak

def run_avbtool(args_list: List[str]) -> Tuple[int, str, str]:
    avbtool = Path(__file__).with_name("avbtool.py")
    if not avbtool.exists():
        raise FileNotFoundError(f"找不到 avbtool.py：{avbtool}")
    cmd = [sys.executable, str(avbtool)] + args_list
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def print_banner(title: str) -> None:
    print(f"\n=== {title} ===")

def print_cmd_result(title: str, cmd: List[str], code: int, out: str, err: str, show_stdout: bool) -> None:
    print(f"[*] {title}")
    print(f"    CMD : {' '.join(cmd)}")
    print(f"    Code: {code}")
    if show_stdout:
        print("    ----- STDOUT -----")
        print(out.rstrip() or "(empty)")
        print("    ----- STDERR -----")
        print(err.rstrip() or "(empty)")

def clean_keys(inputs: List[str]) -> List[Path]:
    exts = {".pem", ".key", ".pk8"}
    out: List[Path] = []
    for s in inputs:
        p = Path(s).expanduser().resolve()
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in exts:
                    out.append(f)
        elif p.is_file():
            out.append(p)
        else:
            die(f"找不到 key 路径：{p}")
    # 去重
    uniq, seen = [], set()
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq

def hash_file(p: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def extract_pubkey_bin_from_pem(pem: Path, out_bin: Path) -> None:
    code, out, err = run_avbtool(["extract_public_key", "--key", str(pem), "--output", str(out_bin)])
    if code != 0:
        raise RuntimeError(f"extract_public_key 失败：{pem}\nSTDOUT:\n{out}\nSTDERR:\n{err}")

def load_keys(pem_files: List[Path], show_stdout: bool) -> List[Dict]:
    keys: List[Dict] = []
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for pem in pem_files:
            try:
                pubbin = td / (pem.stem + ".pub.bin")
                cmd = ["extract_public_key", "--key", str(pem), "--output", str(pubbin)]
                code, out, err = run_avbtool(cmd)
                print_cmd_result(f"解析公钥: {pem.name}", cmd, code, out, err, show_stdout)
                if code != 0:
                    raise RuntimeError(f"extract_public_key 失败: {pem}")
                keys.append({
                    "path": pem,
                    "sha1": hash_file(pubbin, "sha1"),
                    "sha256": hash_file(pubbin, "sha256"),
                })
            except Exception:
                # 非 PEM 私钥格式就跳过
                continue
    return keys

def match_key_sha1(sha1: Optional[str], keys: List[Dict]) -> Optional[Path]:
    if not sha1:
        return None
    sha1 = sha1.lower()
    for k in keys:
        if k["sha1"].lower() == sha1:
            return k["path"]
    return None

def assert_raw_partition_image(img: Path) -> None:
    # 检测 sparse：前 4 字节小端 magic
    with img.open("rb") as f:
        head = f.read(4)
    if len(head) == 4 and struct.unpack("<I", head)[0] == SPARSE_MAGIC:
        die(
            "检测到 Android sparse 镜像（0xED26FF3A）。\n"
            "本工具要求 RAW 分区 dump（完整分区大小，不稀疏、不裁剪）。\n"
            "请先用 simg2img/unsparse 转成 raw 后再签名。"
        )

def info_image(img: Path) -> Dict:
    code, out, err = run_avbtool(["info_image", "--image", str(img)])
    if code != 0:
        raise RuntimeError(f"avbtool info_image 失败：{img}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    algo = None
    m = RE_ALGO.search(out)
    if m:
        algo = m.group(1).strip()
    top_sha1 = None
    m = RE_PUBKEY_SHA1.search(out)
    if m:
        top_sha1 = m.group(1).lower()
    top_sha256 = None
    m = RE_PUBKEY_SHA256.search(out)
    if m:
        top_sha256 = m.group(1).lower()
    part_name = None
    m = RE_PART_NAME.search(out)
    if m:
        part_name = m.group(1)
    part_size = None
    m = RE_PART_SIZE.search(out)
    if m:
        part_size = int(m.group(1))
    rb_loc = None
    m = RE_RB_INDEX_LOC.search(out)
    if m:
        rb_loc = int(m.group(1))
    referenced_parts = sorted(set(m.group(1) for m in RE_ANY_PARTITION_NAME.finditer(out)))
    return {
        "raw": out,
        "algorithm": algo,
        "top_sha1": top_sha1,
        "top_sha256": top_sha256,
        "partition_name": part_name,
        "partition_size": part_size,
        "rollback_index_location": rb_loc,
        "use_hashtree": bool(RE_HASHTREE_DESC.search(out)),
        "use_hash": bool(RE_HASH_DESC.search(out)),
        "referenced_parts": referenced_parts,
    }

def try_erase_footer(img: Path, show_stdout: bool) -> None:
    code, out, err = run_avbtool(["erase_footer", "--image", str(img)])
    print_cmd_result(f"尝试清除 footer: {img.name}", ["erase_footer", "--image", str(img)], code, out, err, show_stdout)
    if code == 0:
        print(f"[*] erase_footer OK: {img.name}")
    else:
        print(f"[*] erase_footer skipped (non-fatal): {img.name}")

def resign_footer_image_inplace(
    img: Path,
    algorithm: str,
    key_pem: Path,
    partition_name: str,
    partition_size: int,
    use_hashtree: bool,
    rollback_index_location: Optional[int],
    show_stdout: bool,
) -> None:
    backup_file(img)
    try_erase_footer(img, show_stdout)
    cmd = []
    if use_hashtree:
        cmd = [
            "add_hashtree_footer",
            "--image", str(img),
            "--partition_name", partition_name,
            "--partition_size", str(partition_size),
            "--algorithm", algorithm,
            "--key", str(key_pem),
        ]
    else:
        cmd = [
            "add_hash_footer",
            "--image", str(img),
            "--partition_name", partition_name,
            "--partition_size", str(partition_size),
            "--algorithm", algorithm,
            "--key", str(key_pem),
        ]
    if rollback_index_location is not None:
        cmd += ["--rollback_index_location", str(rollback_index_location)]
    code, out, err = run_avbtool(cmd)
    print_cmd_result(f"重签分区镜像: {img.name}", cmd, code, out, err, show_stdout)
    if code != 0:
        raise RuntimeError(f"重签失败：{img}\nCMD: {' '.join(cmd)}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    print(f"[+] Signed inplace: {img.name}")

# ------------------- vbmeta descriptor 去重（核心优化点） -------------------
def vbmeta_strip_partition_descriptors_keep_size(vbmeta_bytes: bytes, target_part: str) -> Tuple[bytes, int, int]:
    """
    从 vbmeta 中移除所有“payload 内含 target_part\\x00”的 descriptor。
    但不改变 vbmeta 文件大小与 aux block 大小，只在 descriptors 区域内部做紧缩，
    并更新 header.descriptors_size 为新大小（后面空余补 0）。

    返回：(new_vbmeta_bytes, removed_count, new_desc_size)
    """
    if len(vbmeta_bytes) < HEADER_SIZE:
        raise ValueError("vbmeta 太小，不像合法 vbmeta")

    magic = vbmeta_bytes[OFF_MAGIC:OFF_MAGIC+4]
    if magic != b"AVB0":
        raise ValueError("vbmeta magic 非 AVB0")

    auth_size = u64be(vbmeta_bytes[OFF_AUTH_SIZE:OFF_AUTH_SIZE+8])
    aux_size = u64be(vbmeta_bytes[OFF_AUX_SIZE:OFF_AUX_SIZE+8])
    desc_off = u64be(vbmeta_bytes[OFF_DESC_OFF:OFF_DESC_OFF+8])
    desc_size = u64be(vbmeta_bytes[OFF_DESC_SIZE:OFF_DESC_SIZE+8])

    aux_start = HEADER_SIZE + auth_size
    desc_start = aux_start + desc_off
    desc_end = desc_start + desc_size

    if desc_end > len(vbmeta_bytes):
        raise ValueError(
            f"vbmeta descriptors 区域越界：desc_end={desc_end}, file_size={len(vbmeta_bytes)}\n"
            f"auth_size={auth_size}, aux_size={aux_size}, desc_off={desc_off}, desc_size={desc_size}\n"
            "常见原因：header 偏移错误 / vbmeta 文件损坏 / 不是标准 vbmeta.img"
        )


    target = (target_part.encode("ascii") + b"\x00")

    # descriptor 格式：tag(u64) + num_bytes_following(u64) + payload(num_bytes_following)
    kept = bytearray()
    removed = 0

    i = desc_start
    while i + 16 <= desc_end:
        tag = u64be(vbmeta_bytes[i:i+8])
        nbf = u64be(vbmeta_bytes[i+8:i+16])
        rec_len = 16 + nbf
        rec_end = i + rec_len
        if rec_end > desc_end:
            # 剩余区域可能是 padding 0，直接停止
            break
        payload = vbmeta_bytes[i+16:rec_end]
        if target in payload:
            removed += 1
        else:
            kept += vbmeta_bytes[i:rec_end]
        i = rec_end

    # kept 的新大小不能超过原 desc_size，否则就不是“去重”，而是越写越肥
    if len(kept) > desc_size:
        raise ValueError("去重后 descriptors 反而变大？这不科学。")

    new_bytes = bytearray(vbmeta_bytes)
    # 写入紧缩后的 descriptors，并把剩余填 0
    new_bytes[desc_start:desc_start+len(kept)] = kept
    pad_len = desc_size - len(kept)
    if pad_len > 0:
        new_bytes[desc_start+len(kept):desc_start+desc_size] = b"\x00" * pad_len

    # 更新 header 的 descriptors_size 为 kept 实际长度
    new_bytes[OFF_DESC_SIZE:OFF_DESC_SIZE+8] = p64be(len(kept))

    return bytes(new_bytes), removed, len(kept)

def pad_to_size(b: bytes, size: int) -> bytes:
    if len(b) > size:
        raise ValueError(f"产物大小 {len(b)} 超过分区大小 {size}（会爆）")
    if len(b) == size:
        return b
    return b + b"\x00" * (size - len(b))

def make_descriptor_vbmeta_for_partition(
    part_img: Path,
    partition_name: str,
    partition_size: int,
    use_hashtree: bool,
    out_vbmeta: Path,
) -> None:
    """
    用 avbtool 从分区镜像生成“仅包含该分区 descriptor”的 vbmeta（algorithm=NONE）。
    注意：这一步不改动 part_img。
    """
    # avbtool 允许：add_hash_footer / add_hashtree_footer + --output_vbmeta_image + --do_not_append_vbmeta_image
    # algorithm=NONE 时一般不需要 key，但某些版本仍要求给 --key；我们用临时 dummy key 文件兜底：
    # 这里最稳：直接传一个真实 PEM（最终签名在父 vbmeta 做），但 avbtool 可能仍会检查 key。
    # 所以我们给一个临时的“空 PEM”不行；干脆让用户必须提供 keys，我们外层调用会传真实 key。

    raise RuntimeError("内部错误：这个函数应由调用方传入 key（见下面调用处）")

def build_new_parent_vbmeta(
    parent_vbmeta: Path,
    parent_algo: str,
    parent_key: Path,
    stripped_parent: Path,
    extra_desc_vbmeta: Path,
    out_vbmeta_small: Path,
    show_stdout: bool,
) -> None:
    """
    make_vbmeta_image:
      include_descriptors_from_image stripped_parent
      include_descriptors_from_image extra_desc_vbmeta
    然后用 parent_key + parent_algo 签名生成 out_vbmeta_small（未 pad）
    """
    cmd = [
        "make_vbmeta_image",
        "--output", str(out_vbmeta_small),
        "--algorithm", parent_algo,
        "--key", str(parent_key),
        "--include_descriptors_from_image", str(stripped_parent),
        "--include_descriptors_from_image", str(extra_desc_vbmeta),
    ]
    code, out, err = run_avbtool(cmd)
    print_cmd_result(f"重建父 vbmeta: {parent_vbmeta.name}", cmd, code, out, err, show_stdout)
    if code != 0:
        raise RuntimeError(
            f"重建父 vbmeta 失败：{parent_vbmeta}\nCMD: {' '.join(cmd)}\nSTDOUT:\n{out}\nSTDERR:\n{err}"
        )

def main():
    ap = argparse.ArgumentParser(
        description="AVB 聚合式全自动链路签名工具（去重 descriptors / 原地覆盖 / RAW 强约束）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--keys", nargs="+", required=True, help="PEM/KEY/PK8 文件或目录（目录递归搜索）")
    ap.add_argument("--img_patched", required=True, help="需要处理的 patch 后镜像（RAW 分区 dump）")
    ap.add_argument("--orig_img", required=True, help="原机提取的参考镜像（RAW 分区 dump，用于匹配 key/算法）")
    ap.add_argument("--vbmetas", nargs="*", help="所有 vbmeta*.img（Algorithm NONE 必需）")
    ap.add_argument("--vbmeta_dir", help="包含 vbmeta 镜像的目录（自动匹配 *vbmeta*.img）")
    ap.add_argument("--partition_name", help="手动指定分区名（覆盖自动解析）")
    ap.add_argument("--out_dir", default="./signed_img", help="输出目录（所有签名产物统一输出到该目录）")
    ap.add_argument("--show_stdout", action="store_true", help="打印 avbtool 的 stdout/stderr")
    ap.add_argument("--force", action="store_true", help="强制继续（一些警告会变为可放行）")
    if len(sys.argv) == 1:
        ap.print_help()
        sys.exit(0)
    args = ap.parse_args()

    img = Path(args.img_patched).resolve()
    if not img.exists():
        die(f"找不到 img_patched：{img}")

    assert_raw_partition_image(img)

    orig = Path(args.orig_img).resolve()
    if not orig.exists():
        die(f"找不到 orig_img：{orig}")

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] 输出目录: {out_dir}")

    # keys
    key_candidates = clean_keys(args.keys)
    if not key_candidates:
        die("没有找到任何 key 文件（.pem/.key/.pk8）")

    keys = load_keys(key_candidates, args.show_stdout)
    if not keys:
        die("没有任何 key 能通过 avbtool extract_public_key（请确认 PEM 私钥格式）")
    print_banner("已加载的 PEM key 指纹")
    for k in keys:
        print(f"- {k['path'].name}")
        print(f"  sha1   : {k['sha1']}")
        print(f"  sha256 : {k['sha256']}")
    print(f"[*] Loaded usable keys: {len(keys)}")

    img_info = info_image(img)
    orig_info = info_image(orig)

    algorithm = (img_info.get("algorithm") or orig_info.get("algorithm") or "").strip()
    if not algorithm:
        die("无法解析 Algorithm（avbtool info_image 输出异常）")

    partition_name = args.partition_name or img_info.get("partition_name") or orig_info.get("partition_name")
    if not partition_name:
        die("无法解析 Partition Name，请用 --partition_name 手动指定")

    # 你要求：partition_size = 文件大小（RAW dump）
    partition_size = img.stat().st_size

    print_banner("目标镜像基础信息")
    print(f"[*] orig_img     : {orig}")
    print(f"[*] img_patched  : {img}")
    print(f"[*] Partition    : {partition_name}")
    print(f"[*] Algorithm    : {algorithm}")
    print(f"[*] Size(patched): {partition_size} bytes (RAW dump assumed)")


    # 匹配 key（优先 orig）
    key_pem = match_key_sha1(orig_info.get("top_sha1"), keys) or match_key_sha1(img_info.get("top_sha1"), keys)
    print(f"[*] Top pubkey sha1(orig): {orig_info.get('top_sha1') or '(not found)'}")
    print(f"[*] Top pubkey sha1(img) : {img_info.get('top_sha1') or '(not found)'}")

    print_banner("镜像解析与匹配结果")
    all_to_show: List[Tuple[str, Path, Dict]] = [("img_patched", img, img_info), ("orig_img", orig, orig_info)]
    for v in sorted({p.resolve() for p in (([Path(x).resolve() for x in args.vbmetas] if args.vbmetas else []) + ([q for q in Path(args.vbmeta_dir).resolve().rglob("*.img") if "vbmeta" in q.name.lower()] if args.vbmeta_dir and Path(args.vbmeta_dir).resolve().exists() else []))}):
        try:
            all_to_show.append(("vbmeta", v, info_image(v)))
        except Exception:
            continue
    for tag, path, ii in all_to_show:
        print("\n" + "=" * 80)
        print(f"[{tag}] {path}")
        print("-" * 80)
        print(f"Algorithm            : {ii.get('algorithm') or '(unknown)'}")
        sha1 = ii.get("top_sha1")
        sha1_match = match_key_sha1(sha1, keys)
        print(f"Top pubkey sha1      : {sha1 or '(not found)'}" + (f"  -> {sha1_match.name}" if sha1_match else ""))
        print(f"Top pubkey sha256    : {ii.get('top_sha256') or '(not found)'}")
        parts = ii.get("referenced_parts") or []
        print(f"Referenced partitions: {', '.join(parts) if parts else '(none)'}")

    # ---------------- Case 1: Algorithm != NONE -> sign image itself ----------------
    if algorithm.upper() != "NONE":
        if not key_pem:
            die("找不到匹配的 PEM（请补充/更换 keys）")

        signed_img = out_dir / img.name
        shutil.copy2(img, signed_img)
        print(f"[*] 已复制待签镜像到输出目录: {signed_img}")

        use_hashtree = bool(orig_info.get("use_hashtree") or img_info.get("use_hashtree"))
        rb_loc = orig_info.get("rollback_index_location") or img_info.get("rollback_index_location")

        print(f"[*] Key match : {key_pem.name}")
        print(f"[*] Mode      : resign image inplace ({'hashtree' if use_hashtree else 'hash'})")
        resign_footer_image_inplace(
            img=signed_img,
            algorithm=algorithm,
            key_pem=key_pem,
            partition_name=partition_name,
            partition_size=partition_size,
            use_hashtree=use_hashtree,
            rollback_index_location=rb_loc,
            show_stdout=args.show_stdout,
        )
        print(f"[✓] Done. 输出文件: {signed_img}")
        return

    # ---------------- Case 2: Algorithm == NONE -> sign parent vbmeta ----------------
    vbmeta_list: List[Path] = []
    if args.vbmeta_dir:
        d = Path(args.vbmeta_dir).resolve()
        if not d.exists():
            die(f"找不到 vbmeta_dir：{d}")
        vbmeta_list += [p for p in d.rglob("*.img") if "vbmeta" in p.name.lower()]
    if args.vbmetas:
        vbmeta_list += [Path(x).resolve() for x in args.vbmetas]

    vbmeta_list = [p for p in vbmeta_list if p.exists()]
    if not vbmeta_list:
        die("Algorithm NONE：必须提供所有 vbmeta*.img（--vbmeta_dir 或 --vbmetas）")

    # 先找出引用了该 partition 的 vbmeta
    candidates: List[Tuple[Path, Dict]] = []
    for v in vbmeta_list:
        try:
            vi = info_image(v)
        except Exception:
            continue
        if partition_name in vi.get("referenced_parts", []):
            candidates.append((v, vi))

    if not candidates:
        die(f"没有任何提供的 vbmeta 引用分区 {partition_name}。请补齐更多 *vbmeta*.img。")

    # 选择一个我们能签的（key 匹配）
    chosen = None
    for v, vi in candidates:
        k = match_key_sha1(vi.get("top_sha1"), keys)
        if k and vi.get("algorithm") and vi["algorithm"].upper() != "NONE":
            chosen = (v, vi, k)
            break

    if not chosen:
        die(
            "找到了引用该分区的 vbmeta，但没有任何 vbmeta 的签名 key 在你提供的 PEM 里匹配。\n"
            "请补充/更换 PEM（或传入更大的 key 目录）。"
        )

    parent_vbmeta, parent_info, parent_key = chosen
    parent_algo = parent_info["algorithm"]

    print(f"[*] Mode         : resign parent vbmeta (with descriptor dedup)")
    print(f"[*] Parent vbmeta: {parent_vbmeta.name}")
    print(f"[*] Parent algo  : {parent_algo}")
    print(f"[*] Parent key   : {parent_key.name}")

    # 备份父 vbmeta（你要求输出一致，这里就是覆盖同名）
    out_parent = out_dir / parent_vbmeta.name
    shutil.copy2(parent_vbmeta, out_parent)
    backup_file(out_parent)
    print(f"[*] 已复制父 vbmeta 到输出目录: {out_parent}")

    # 1) 先把父 vbmeta 的旧 descriptor 去掉（只改 descriptors_size 和 descriptors 区内部，不改变文件大小）
    parent_bytes = out_parent.read_bytes()
    try:
        stripped_bytes, removed_cnt, new_desc_size = vbmeta_strip_partition_descriptors_keep_size(parent_bytes, partition_name)
    except Exception as e:
        die(f"父 vbmeta 去重失败：{e}")

    if removed_cnt > 0:
        print(f"[+] Dedup: removed {removed_cnt} old descriptor(s) for {partition_name} (new desc_size={new_desc_size})")
    else:
        print(f"[*] Dedup: no existing descriptor found for {partition_name} (ok)")

    # 2) 生成该分区的新 descriptor vbmeta（algorithm=NONE），不修改分区镜像
    #    注意：avbtool 1.3.0 在某些情况下仍要求 --key；这里直接给 parent_key 的 PEM（只是生成 descriptor，不用它最终签名）
    use_hashtree = bool(orig_info.get("use_hashtree") or img_info.get("use_hashtree"))
    desc_mode = "hashtree" if use_hashtree else "hash"

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        stripped_parent_path = td / ("parent_stripped.img")
        stripped_parent_path.write_bytes(stripped_bytes)

        extra_desc = td / f"{partition_name}_desc.vbmeta.img"
        # 用 add_*_footer 生成 descriptor-vbmeta
        cmd = []
        if use_hashtree:
            cmd = [
                "add_hashtree_footer",
                "--image", str(img),
                "--partition_name", partition_name,
                "--partition_size", str(partition_size),
                "--algorithm", "NONE",
                "--key", str(parent_key),
                # 显式给空 salt，避免某些环境（如 Windows）无 /dev/urandom 导致失败。
                "--salt", "",
                "--output_vbmeta_image", str(extra_desc),
                "--do_not_append_vbmeta_image",
            ]
        else:
            cmd = [
                "add_hash_footer",
                "--image", str(img),
                "--partition_name", partition_name,
                "--partition_size", str(partition_size),
                "--algorithm", "NONE",
                "--key", str(parent_key),
                # 显式给空 salt，避免某些环境（如 Windows）无 /dev/urandom 导致失败。
                "--salt", "",
                "--output_vbmeta_image", str(extra_desc),
                "--do_not_append_vbmeta_image",
            ]

        code, out, err = run_avbtool(cmd)
        if code != 0 or not extra_desc.exists():
            # 某些 avbtool 版本在 --do_not_append_vbmeta_image 时会把 image 以只读模式打开，
            # 但内部仍尝试 truncate()，导致 "ImageHandler is in read-only mode"。
            # 兜底策略：复制一份临时镜像并重试（去掉 do_not_append，允许改临时文件）。
            retry_cmd = [x for x in cmd if x != "--do_not_append_vbmeta_image"]
            retry_img = td / f"{img.stem}.desc_work{img.suffix}"
            shutil.copy2(img, retry_img)

            # 把 --image 参数替换成临时副本。
            for i in range(len(retry_cmd) - 1):
                if retry_cmd[i] == "--image":
                    retry_cmd[i + 1] = str(retry_img)
                    break

            print("[!] descriptor-vbmeta 首次生成失败，尝试兼容模式重试（临时镜像）")
            code2, out2, err2 = run_avbtool(retry_cmd)
            if code2 != 0 or not extra_desc.exists():
                die(
                    "生成 descriptor-vbmeta 失败（可能是 avbtool 对 algorithm=NONE 的行为有差异）。\n"
                    f"CMD: {' '.join(cmd)}\nSTDOUT:\n{out}\nSTDERR:\n{err}\n\n"
                    f"RETRY CMD: {' '.join(retry_cmd)}\nSTDOUT:\n{out2}\nSTDERR:\n{err2}"
                )
        print(f"[+] Built descriptor vbmeta for {partition_name} ({desc_mode})")

        # 3) 重建并签名父 vbmeta（小体积产物）
        out_small = td / "parent_new_small.img"
        build_new_parent_vbmeta(
            parent_vbmeta=out_parent,
            parent_algo=parent_algo,
            parent_key=parent_key,
            stripped_parent=stripped_parent_path,
            extra_desc_vbmeta=extra_desc,
            out_vbmeta_small=out_small,
            show_stdout=args.show_stdout,
        )

        # 4) pad 到原 vbmeta 分区大小，并原地覆盖
        parent_size = out_parent.stat().st_size  # RAW dump 分区大小
        new_small_bytes = out_small.read_bytes()
        try:
            new_padded = pad_to_size(new_small_bytes, parent_size)
        except Exception as e:
            die(
                f"新 vbmeta 超过分区大小（爆了）：{e}\n"
                "这通常意味着父 vbmeta 分区太小或仍有重复/异常 descriptors。\n"
                "你可以把 parent vbmeta 的 info_image 输出贴我，我再把去重规则收紧到 descriptor 类型级别。"
            )

        out_parent.write_bytes(new_padded)
        print(f"[+] Signed & padded parent vbmeta: {out_parent}")

    print("[✓] Done.")

if __name__ == "__main__":
    main()
