# Motrix static FFmpeg

[English](./README.md) | 简体中文

面向 Motrix v2 的独立 FFmpeg 构建，覆盖 macOS、Linux 与 Windows。

FFmpeg **不会随 Motrix 一同分发**。是否安装由用户自行决定；无需修改 Motrix
应用即可替换或删除它。在 Motrix 中点击 **设置 → 集成 → 媒体工具 → 下载 FFmpeg**，
支持项目签名校验的 Windows 版 Motrix 可直接下载并验证；macOS 和 Linux 会打开
本项目的 Releases。

> [!IMPORTANT]
> 这些是由 Motrix 维护的第三方二进制文件，**不是 FFmpeg 官方构建**。使用前请阅读
> [FFmpeg 免责声明](#ffmpeg-免责声明)。

## 下载

打开 [motrixapp/ffmpeg-static Releases](https://github.com/motrixapp/ffmpeg-static/releases)，
选择一个已经发布的版本，然后下载与你系统匹配的压缩包。

Release 压缩包使用以下命名格式：

```text
ffmpeg-<FFmpeg 版本>-motrix.<构建号>-<目标>.<扩展名>
```

| 系统 | 目标 | 压缩包 | 声明的最低系统 |
| --- | --- | --- | --- |
| Apple 芯片 Mac | `darwin-arm64` | `...-darwin-arm64.zip` | macOS 12.0 |
| Intel Mac | `darwin-x64` | `...-darwin-x64.zip` | macOS 12.0 |
| ARM64 Linux | `linux-arm64` | `...-linux-arm64.tar.gz` | Linux kernel 3.7.0 |
| x86-64 Linux | `linux-x64` | `...-linux-x64.tar.gz` | Linux kernel 2.6.39 |
| Windows on ARM | `win32-arm64` | `...-win32-arm64.zip` | Windows 10.0 |
| x86-64 Windows | `win32-x64` | `...-win32-x64.zip` | Windows 10.0 |

最低版本是构建目标，并不保证每个发行版、设备、驱动或 Motrix 安装包都支持相同
配置。Windows ARM64 FFmpeg 压缩包是否提供，与某一版 Motrix 是否同时提供原生
Windows ARM64 应用安装包相互独立。

## 验证下载文件

从压缩包所在的**同一个带 tag 的 Release** 下载 `SHA256SUMS`。选择文件名字段与完整
压缩包名称完全相等的唯一一行（不是名称相似的 `.metadata.json` 文件），计算本地
SHA-256，并确认两个值完全一致。

macOS：

```sh
shasum -a 256 ffmpeg-<FFmpeg-版本>-motrix.<构建号>-darwin-<架构>.zip
```

Linux：

```sh
sha256sum ffmpeg-<FFmpeg-版本>-motrix.<构建号>-linux-<架构>.tar.gz
```

Windows PowerShell：

```powershell
Get-FileHash .\ffmpeg-<FFmpeg-版本>-motrix.<构建号>-win32-<架构>.zip -Algorithm SHA256
```

请用 Release 中的完整文件名替换占位符。SHA-256 一致可以发现文件损坏，但单凭哈希
不能证明发布者身份。Motrix 内置公钥用于校验发布清单的 Ed25519 项目签名。若要
验证项目签名、Release、attestation、manifest、tag 及 macOS 签名，请按照 [SECURITY.md](SECURITY.md#verify-a-download) 的完整步骤操作。

独立发布的 [Motrix FFmpeg 签名公钥页面](https://motrix.app/zh/security/ffmpeg/)
提供公钥、key ID 和轮换记录。不要因为替换公钥与下载包一起提供，就直接信任它。

任何检查失败时，**都不要安装或运行该文件**。平台签名验证需要先通过共同检查，再按
`SECURITY.md` 的安全流程，只把 `ffmpeg` 与 `ffprobe` 解压到新建的临时目录。请重新
从本仓库带 tag 的 Release 下载，并报告潜在安全问题。切勿绕过 Gatekeeper、
SmartScreen 或失败的校验。

## 安装到 Motrix

Windows 用户可在支持项目签名校验的 Motrix 中点击 **下载 FFmpeg → 下载并验证**。
Motrix 会选择 x64 或 ARM64，验证签名清单、压缩包及二进制后安装；失败时保留原有
已验证版本。自定义路径优先，安装后重启 Motrix 可刷新插件缓存的 FFmpeg 能力。

手动安装时，“媒体”设置页会显示并可复制路径。推荐的手动安装位置是：

```text
<userData>/binaries/ffmpeg
<userData>/binaries/ffmpeg.exe       # Windows
```

1. 按照[完整验证流程](SECURITY.md#verify-a-download)验证压缩包。
2. 在 Motrix 的 **设置 → 集成 → 媒体工具** 中展开检测详情，复制 **Motrix FFmpeg
   路径**；若其父级 `binaries` 目录不存在，请先创建。
3. 解压后，将 `ffmpeg`（Windows 为 `ffmpeg.exe`）复制到该路径。
4. 可将 `ffprobe`（Windows 为 `ffprobe.exe`）一并复制到旁边，用于诊断。
5. 在 macOS 或 Linux 上保留可执行权限。执行 `chmod 755 ffmpeg`；若复制了
   `ffprobe`，再执行 `chmod 755 ffprobe`。
6. 返回 **媒体工具**，刷新 FFmpeg 检测结果。

Motrix 会依次检查：“媒体”设置中的自定义路径、
`<userData>/binaries/ffmpeg[.exe]`、`MOTRIX_FFMPEG_BIN`，最后是系统 `PATH`。
因此，你也可以使用可信的系统软件包或自己的兼容构建。

## 包含内容

每个压缩包都包含：

- `ffmpeg` 和 `ffprobe`（Windows 文件名带 `.exe`）；
- 完整构建配置与构建元数据；
- `LICENSES.json`、第三方声明与各组件许可证文本。

`motrix-full-gpl` 功能档位有意只覆盖 Motrix v2 所需能力：FFmpeg 原生 AAC、FLAC、
PCM、探测、滤镜、缩放和常见封装格式，另外通过 x264 支持 H.264 编码、通过 LAME
支持 MP3 编码。macOS 构建还会启用 Apple VideoToolbox 与 AudioToolbox。它不会启用
每一种可选编解码器、硬件 SDK 或 FFmpeg 库。

“静态”在各平台上的含义不同：

| 平台 | 分发方式 |
| --- | --- |
| Linux | 使用 musl 的静态可执行文件，不依赖运行时加载器或共享库。 |
| macOS | 静态链接 x264 与 LAME；Apple 系统库和 Framework 仍由系统提供。 |
| Windows | 静态链接 x264、LAME 与编译器运行时；仅导入 Windows 系统 DLL。 |

每个 Release 都会发布经过认证的 FFmpeg、x264、LAME、musl、fortify-headers、NASM、
llvm-mingw 构建 recipe 与 LLVM runtime 源码包，以及精确构建脚本、源码锁、校验和、
元数据和 SPDX SBOM。完整 mingw-w64 上游源码树只引用而不镜像；其不可变 URL、
revision 与 SHA-256 仍会记录在 `sources.env` 和 SBOM 中。

## 平台信任

所有平台都必须先完成 [SECURITY.md](SECURITY.md#verify-a-download) 中共同的 Release、
annotated tag、attestation、manifest、文件大小与 SHA-256 验证。发布清单带有
Ed25519 项目签名，公钥独立内置于 Motrix。各平台的策略如下：

- **macOS：**本项目正式 Release 中的可执行文件使用 Developer ID Application
  身份签名，启用 hardened runtime 与安全时间戳；发布的同一个 ZIP 还必须获得 Apple
  公证服务的接受。
- **Windows x64 与 ARM64：**可执行文件没有公共 Authenticode 签名。Motrix 使用
  内置 Ed25519 公钥校验发布清单，再核对压缩包与二进制哈希。这不会建立 Windows
  发布者信誉，也不保证消除 SmartScreen 或杀毒软件警告。不要安装自签根证书，
  不要关闭系统保护。
- **Linux：**按照 [SECURITY.md](SECURITY.md#verify-a-download) 验证带 tag 的
  Release、attestation、manifest 与 SHA-256。

平台警告意味着必须停止。不要移除 macOS quarantine 属性、添加 ad-hoc 签名、强行
点击通过 SmartScreen，或压制失败的签名检查。

## 常见问题

### macOS 下载文件需要签名吗？

其中的可执行文件需要。FFmpeg 是在安装 Motrix 后单独下载的，因此不会继承 Motrix
应用本身的签名。ZIP 容器本身不做代码签名：其中的 `ffmpeg` 与 `ffprobe` 使用
Developer ID 签名，最终的同一个 ZIP 会提交 Apple 公证服务；这种普通 ZIP 布局不
声称带有 stapled ticket。

### 支持 Windows ARM64 吗？

支持。原生 Windows on ARM 请选择 `win32-arm64`；x86-64 Windows 请选择
`win32-x64`。

### 用户必须安装 Python 吗？

不需要。Python 只用于构建与发布管线，下载的 `ffmpeg` 与 `ffprobe` 没有 Python
运行时依赖。

### 必须安装本项目的构建吗？

不必。FFmpeg 对 Motrix 而言保持可选且独立。你可以在 Motrix 的“媒体”设置中选择
兼容的系统软件包或自定义构建。

### Gatekeeper、SmartScreen 或校验报告问题时怎么办？

立即停止，不要绕过警告，也不要运行文件。请从带 tag 的 Release 重新下载，按照
[完整验证流程](SECURITY.md#verify-a-download)检查；若问题仍然存在，请使用
[私密漏洞报告](https://github.com/motrixapp/ffmpeg-static/security/advisories/new)。

## FFmpeg 免责声明

本仓库提供由 Motrix 维护、供 Motrix 使用的第三方 FFmpeg 二进制文件。本项目独立于
FFmpeg 项目，与 FFmpeg 及其贡献者不存在隶属、赞助、批准或背书关系；这里的文件也
不是由 FFmpeg 项目分发的构建。名称 **FFmpeg** 是 Fabrice Bellard 的商标；其他名称
和商标归各自所有者所有。

当前构建启用了 GPL 代码与 `libx264`，因此生成的 `ffmpeg` 与 `ffprobe` 可执行文件按
**GPL-2.0-or-later** 分发；其中静态链接的各组件仍保留各自的附加许可证条款。每个
压缩包中的 `LICENSES.json` 与 `LICENSES/` 是这些二进制文件的完整有效许可证记录，
FFmpeg、x264 与 LAME 的对应源码包及上文列出的其他可再分发源码材料会发布在同一
Release 中。根目录 [LICENSE](LICENSE) 主要覆盖本项目原创的构建脚本与仓库内容。
另请参阅 [FFmpeg 官方下载页](https://ffmpeg.org/download.html) 与
[FFmpeg 法律信息](https://ffmpeg.org/legal.html)。

编解码器、格式、专利、出口与商业使用规则会因司法辖区和具体用途而异。本仓库内容
不构成法律建议。用户有责任判断适用的法律与许可证义务，并确保自己对所处理、下载、
编码、解码、转换或分发的媒体拥有所需权利或许可。

这些构建均按**现状**提供，不附带任何形式的保证或担保。在适用法律允许的范围内，
维护者不对使用或无法使用这些文件、数据丢失、兼容性问题或第三方索赔承担责任。

Motrix 打包、下载或集成问题请在本仓库反馈，不要联系 FFmpeg 上游支持渠道。只有在
确认问题可在上游 FFmpeg 重现、且并非本构建特有问题后，才应向上游报告。

## 项目链接

- 安全策略与完整验证：[SECURITY.md](SECURITY.md)
- 贡献方式与发布要求：[CONTRIBUTING.md](CONTRIBUTING.md)
- 一般打包问题：[GitHub Issues](https://github.com/motrixapp/ffmpeg-static/issues)
