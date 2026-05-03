# phantom-frida — fork 仓库工作笔记

## Fork 关系

- **origin**: `git@github.com:RainbowXie/phantom-frida.git`（自己的 fork，所有日常推送）
- **upstream**: `git@github.com:TheQmaks/phantom-frida.git`（原作者）
- 同步上游：`git fetch upstream && git merge upstream/master`

## 项目目标

在 phantom-frida 现有 **Android 构建路径**基础上**新增 iOS 构建路径**，输出 phantom 化的 gadget dylib 和 server 二进制，供越狱真机使用。

**硬约束**：不能破坏现有 Android 路径。Android workflow / build.py Android 分支保持向后兼容。

## iOS 构建范围

| 维度 | 决策 |
|---|---|
| arch | `ios-arm64`, `ios-arm64e`（覆盖 A12+ Dopamine 越狱） |
| 产物 | `lib{name}-gadget.dylib` + `{name}-server` |
| 越狱场景 | Dopamine / iOS 16 rootless（路径 `/var/jb/...`） |
| codesign | ad-hoc（`codesign --force --sign -`），仅越狱可用，重打包 IPA 时会被覆盖 |
| 反检测覆盖 | 跨平台向量（字符串/符号重命名、thread name binary patch） + iOS 专属（install_name 改名、ObjC 类名重命名、Mach-O 符号清扫） |
| 跳过 | Android 专属反检测向量（SELinux 标签、memfd 名、libc hook、DEX 重打包） |

## 构建环境

- **本地无 macOS**，iOS 构建依赖 GitHub Actions `macos-14` runner（Xcode 15+ 预装）
- Android 路径保持 `ubuntu-22.04` + Android NDK r29（自动下载，缓存）
- 触发方式：手动 `workflow_dispatch`

## 真机验证（iOS）

- ssh 连通性：`sshpass -p '1' ssh root@192.168.9.220`
- 设备类型：Dopamine 越狱，iOS 16 rootless
- 部署路径：
  - server: `/var/jb/usr/sbin/{name}-server`
  - gadget: `/var/jb/usr/lib/lib{name}-gadget.dylib`
- 验证命令（从 host）：
  ```
  frida-ps -H 192.168.9.220:27042
  ```
- 进程名校验：`ssh root@192.168.9.220 "ps -e | grep -i frida"` 应无输出

## 关键文件

| 路径 | 作用 |
|---|---|
| `build.py` | 主构建脚本：clone Frida 源 → 应用 patches → configure/make → 收集 artifacts |
| `patches.py` | 87 条补丁定义（源码字符串、targeted meson、binary 字节）+ 17 条 rollback |
| `namegen.py` | 随机自定义名/端口生成器 |
| `build-wsl.sh` | WSL Ubuntu 本地构建辅助脚本（仅 Android） |
| `.github/workflows/build.yml` | Android 手动构建 workflow |
| `.github/workflows/build-ios.yml` | iOS 构建 workflow（macos-14 runner） |
| `test_comprehensive.js` | 反检测 + Java bridge 验证脚本（Android） |

## 默认参数

- Frida 版本：`17.7.2`（同上游 build.yml 默认）
- 自定义名：`ajeossida`（与 `frida` 等长，便于二进制等长替换；想换其他名需保证 5 字符）
- 默认端口：`27042`（Frida 默认，可用 `--port` 改）
- 反检测档位：`--extended` 默认开（D-Bus、符号、binary sweep）

## 已知限制

- iOS 反检测覆盖少于 Android（Linux 专属向量不适用）
- iOS dylib `install_name` 默认走 `@rpath`，重打包非越狱 IPA 时需用户自行 `install_name_tool` 调整
- Frida 16.x → 17.x 差异由 `detect_frida_major` 自动分支，但只测过 17.x

## 任务执行守则

1. 改 `build.py` 加 iOS 分支时，**先读现有 Android 分支再判断要不要拆函数**，避免重复逻辑
2. `patches.py` 的 SELinux/MEMFD/LIBC_HOOK/DEX 块绝不在 iOS 路径调用
3. Mach-O 二进制后处理顺序：`install_name_tool` → 字节替换 → **最后**才 `codesign --force --sign -`（codesign 必须在所有修改之后）
4. Workflow 改动后 push 前用 `actionlint` 或 yaml lint 静检一遍
5. 真机验证用 `sshpass`，不写死密码到文件，密码 `1` 是测试机临时账号
