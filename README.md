# AVB-HyperChain-Signer
### AVB Aggregated Automatic Chain Signing Engine

[中文说明（README.zh-CN.md）](./README.zh-CN.md)

AVB HyperChain Signer is a full-chain Android Verified Boot (AVB) signing engine designed for serious firmware modification workflows.

It automatically:

- Detects signing algorithms
- Matches correct PEM private keys
- Handles Algorithm != NONE images (self-signed partitions)
- Handles Algorithm == NONE partitions (parent vbmeta aggregation)
- Removes duplicate descriptors before rebuild
- Reconstructs and resigns parent vbmeta images safely
- Preserves original partition image size (RAW dump only)
- Performs in-place signing with automatic backups

No guesswork. No manual descriptor editing. No accidental vbmeta overflow.

---

## Core Philosophy

Android AVB is not about signing a single image.

It is about maintaining a **valid trust chain**:

```
vbmeta
 ├── boot
 ├── vendor_boot
 └── vbmeta_system
        ├── system
        └── product
```

Modifying one partition without understanding its position in the chain will brick devices.

This tool ensures:

- The correct key is selected
- The correct algorithm is reused
- The correct parent vbmeta is rebuilt
- Duplicate descriptors are removed before aggregation
- Final output size matches original partition size exactly

---

## Features

- Automatic key discovery from file or directory
- SHA1 public key fingerprint matching
- RAW partition enforcement (rejects sparse images)
- Descriptor deduplication before vbmeta rebuild
- Parent vbmeta auto-detection for Algorithm NONE partitions
- In-place signing with timestamped backup
- Preserves original image filename and size
- No external compression or resizing
- Designed for EDL / BROM / 9008 RAW partition dumps

---

## RAW Partition Requirement

This tool assumes:

- Images are full RAW partition dumps
- File size equals partition size
- No sparse images
- No trimmed trailing zeroes

If a sparse image is detected, the tool will refuse to proceed.

Convert sparse images first using:

```
simg2img input.img output_raw.img
```

---

## Installation

Requirements:

- Python 3.8+
- `avbtool.py` in the same directory
- Valid PEM private keys

Directory example:

```
project/
 ├── avb_chain_autosign.py
 ├── avbtool.py
 ├── pem/
 └── vbmeta/vbmeta*.img
```

---

## Usage

### Case 1 — Self-signed partition (Algorithm != NONE)

Example: boot patched with root.

```
python avb_chain_autosign.py \
  --keys ./pem \
  --orig_img ./boot_b.img \
  --img_patched ./boot_patched.img
```

What happens:

- Algorithm and key fingerprint extracted from original
- Patched image resigned in-place
- Backup created automatically

---

### Case 2 — Parent-signed partition (Algorithm == NONE)

Example: vendor_boot patched.

```
python avb_chain_autosign.py \
  --keys ./pem \
  --orig_img ./vendor_boot_b.img \
  --img_patched ./vendor_boot_patched.img \
  --vbmeta_dir ./vbmeta
```

What happens:

1. Detects Algorithm NONE
2. Locates parent vbmeta referencing the partition
3. Removes old descriptor for that partition
4. Builds new descriptor
5. Reconstructs and resigns parent vbmeta
6. Pads result to original vbmeta partition size
7. Overwrites parent vbmeta in-place

No duplicate descriptors.
No size overflow.
No manual intervention.

---

## Safety Model

- Always creates `.bak_TIMESTAMP` backup
- Never shrinks or expands partition size
- Refuses sparse images
- Refuses unknown key matches
- Refuses missing parent vbmeta

---

## Why This Exists

Traditional AVB workflows require:

- Manual descriptor inspection
- Manual chain tracing
- Manual make_vbmeta_image reconstruction
- Manual size padding
- Trial-and-error flashing

This tool eliminates that entire cycle.

It is built for:

- Advanced Android modding
- Secure boot research
- AVB chain reconstruction
- Automated firmware pipelines

---

## Technical Highlights

- Binary-level descriptor filtering inside vbmeta
- Header-aware descriptor size rewriting
- Descriptor block zero-padding
- Deterministic output size preservation
- Parent aggregation via `make_vbmeta_image`
- Fully automated SHA1 fingerprint key selection

---

## Warning

This tool assumes:

- You understand AVB trust chains
- You are working on unlocked bootloaders
- You are using RAW partition dumps

Misuse may brick devices.

---

## License

MIT License

---

## Codename

AVB 聚合式全自动链路签名工具

---

## Author Intent

Built for deterministic, chain-safe AVB modification workflows.

Zero guess.
Zero duplication.
Zero size overflow.
