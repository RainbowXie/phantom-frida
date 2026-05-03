# phantom-frida — fork 仓库工作笔记

## Fork 关系

- **origin**: `git@github.com:RainbowXie/phantom-frida.git`（自己的 fork，所有日常推送）
- **upstream**: `git@github.com:TheQmaks/phantom-frida.git`（原作者）
- 同步上游：`git fetch upstream && git merge upstream/master`
- 当前领先上游：~28 commits（iOS 路径 + 单元测试 + CI 阈值门）

## 项目目标

维护一个 **Android + iOS 双平台**的 phantom-frida builder。在保留上游 Android 16 个反检测向量的基础上扩出 iOS 路径（i1–i7），输出 phantom 化的 gadget dylib + server 二进制供越狱真机使用。

**硬约束**：
- 不破坏既有 Android 路径。Android workflow / build.py Android 分支保持向后兼容。
- patches.py 所有 patch 必须跨 Frida 版本兼容（已在 17.7.2 + 17.9.1 双版本验证）。

## iOS 构建范围

| 维度 | 决策 |
|---|---|
| arch | `ios-arm64`, `ios-arm64e`，自动 lipo 出 `ios-universal` fat |
| 产物 | `lib{name}-gadget.dylib` + `{name}-server`（每 arch + universal） |
| 越狱场景 | Dopamine / iOS 16 rootless（路径 `/var/jb/...`） |
| codesign | ad-hoc（`codesign --force --sign - --identifier <override>`），仅越狱可用 |
| 反检测覆盖 | 跨平台向量 + iOS 专属：i1 install_name 改名、i3 nm 驱动 Mach-O 符号清扫、i6 codesign identifier override、i7 26-pattern PascalCase 字节扫（`Frida[A-Z]`） |
| 残留 floor | 75 lowercase `\bfrida\b`（全是协议绑定的 `/re/frida/*` D-Bus 路径 + Vala 自动生成的 `frida-context` 属性名 + `frida:rpc` JS 协议字面量） |
| 跳过 | Android 专属向量（SELinux 标签、memfd 名、libc hook、DEX 重打包） |

## 构建环境

- **本地无 macOS**，iOS 构建依赖 GitHub Actions `macos-14` runner（Xcode 15+ 预装，IOS_CERTID=- 触发 ad-hoc codesign）
- Android 路径在 `ubuntu-22.04` 上跑；NDK 由 workflow 的 `Resolve NDK version` 步骤按 `frida_version` 自动选：17.7.x/17.6.x → r25c，17.9.x+ → r29
- 触发方式：手动 `workflow_dispatch`（无 scheduled job）

## 真机验证（iOS）

- ssh 连通性：`sshpass -p '1' ssh root@192.168.9.220`
- 设备类型：iPhone 14 (A15, arm64e)，Dopamine 越狱，iOS 16.1 rootless
- 部署路径：
  - server: `/var/jb/usr/sbin/{name}-server`
  - gadget: `/var/jb/usr/lib/lib{name}-gadget.dylib`
  - tweak（substrate filter 注入用）: `/var/jb/Library/MobileSubstrate/DynamicLibraries/<benign-name>.{dylib,plist,config}`
- 验证命令（从 host）：
  ```
  frida-ps -H 192.168.9.220:<port>          # 默认 27042，自定义用 -l 0.0.0.0:<port>
  frida -H 192.168.9.220:<port> -p <pid> --eval='Frida.version'
  ```
- 服务存活校验：`ssh root@192.168.9.220 "ps -ax | grep -E '{name}-server|frida'" | grep -v grep`
- gadget 配置文件命名陷阱：`<basename>.config`，**不是** `<basename>.dylib.config`

## 关键文件

| 路径 | 作用 |
|---|---|
| `build.py` | 主构建脚本：clone Frida 源 → 应用 patches → configure/make → 收集 artifacts。含 iOS post-process 链（install_name_tool → 字节 patch → Mach-O 符号清扫 → codesign）+ multi-arch 之间 wipe build/ + frida_agent_main 跨 arch revert |
| `patches.py` | ~95 条 patch（40 source + 17 rollback + 3 binary thread + 28 binary string sweep + 4 internal + 3 temp path）。28 条 binary string 含 26 个 PascalCase 模式（自动按 custom_name 生成）+ 2 条 frida\\0/FRIDA\\0 |
| `namegen.py` | 随机自定义名/端口生成器（CLI 工具，无自动调度） |
| `build-wsl.sh` | WSL Ubuntu 本地构建辅助脚本（仅 Android） |
| `tests/test_patches.py` | 18 个 unittest，校验 patches.py 不变量（同长度、无重复、无 self-referential、PascalCase 26 完整、`/frida/` 5-char 严格等长） |
| `.github/workflows/build.yml` | Android 手动构建 workflow，含 NDK 版本选择 + 单元测试步骤 |
| `.github/workflows/build-ios.yml` | iOS 构建 workflow（macos-14 runner），含单元测试 + Mach-O 验证 + Residual regression gate |
| `test_comprehensive.js` | 反检测 + Java bridge 运行时验证脚本（Android） |

## 默认参数

- Frida 版本：`17.9.1`（同上游 weekly tag）
  - 17.9.x → NDK r29
  - 17.7.x / 17.6.x → NDK r25c（workflow 自动按版本选）
- 自定义名：`ajeossida`（与 `frida` 等长，便于二进制等长替换；想换其他名需保证 5 字符）
- 默认端口：`27042`（Frida 默认，可用 `--port` 改）
- 反检测档位：`--extended` 默认开（D-Bus、符号、binary sweep）

## 已知限制

- iOS 反检测覆盖少于 Android（Linux 专属向量不适用）
- iOS dylib `install_name` 默认走 `@rpath`，重打包非越狱 IPA 时需用户自行 `install_name_tool` 调整
- Frida 16.x → 17.x 差异由 `detect_frida_major` 自动分支，但只测过 17.x
- **Rename-only 思路打不过应用级反检测**：上游 frida-server 跟我们的 ajeossida-server 在 spawn-attach Snapchat 这类对手时同样 <1s 自杀，因为检测在 attach 行为本身（task_for_pid / ptrace）而不是二进制品牌。这条线的解法不在 builder 范畴

## 发布物

GitHub Releases on `RainbowXie/phantom-frida`（非自动，手动构建后用 `gh release create` 发）：

| Tag | 内容 |
|---|---|
| `v17.7.2-ios-20260503` | iOS arm64+arm64e+universal，Frida 17.7.2 |
| `v17.9.1-ios-20260503` | iOS 同上，Frida 17.9.1（patches 跨版本兼容） |
| `v17.9.1-android-20260503` | Android 4-arch（arm64/arm/x86_64/x86），Frida 17.9.1 |

每个 release 都含未压缩 + .gz 双份 + `SHA256SUMS.txt`。

## 任务执行守则

1. 改 `build.py` 加平台分支时，**先读现有分支再判断要不要拆函数**，避免重复逻辑。`is_ios_arch()` / `is_android_arch()` 已是公共门
2. `patches.py` 的 SELinux/MEMFD/LIBC_HOOK/DEX 块绝不在 iOS 路径调用（受 `apply_targeted_patches` 的 `has_android` 参数控制）
3. Mach-O 二进制后处理顺序：`install_name_tool` → 字节替换 → 符号清扫 → **最后**才 `codesign --force --sign - --identifier <override>`（codesign 必须在所有修改之后）
4. 多 arch iOS 构建：每个 arch 迭代前必须 `rm -rf build/frida/build`，并 `replace_in_tree` 把 `<name>_agent_main` 还原回 `frida_agent_main`，否则 Vala 重新生成的 C 跟已 patched 的 meson.build 对不上，链接器报 `Undefined symbols ... -exported_symbol`
5. patches.py 5-char 短前缀的硬门槛：`len(custom_name) >= 5`，否则 `/frida/` 路径 patch 不启用（gumcmodule.c:678 `name += 7;` 要求 `/<short5>/` 严格 7 字节）
6. `apply_post_build_patches` 现在跑两条：`frida_agent_main` 和 `frida-error-quark`（后者只在 Vala 自动生成的 C 里出现，必须 `include_build=True` 才能命中）
7. Workflow 改动后 push 前用 `python3 -c "import yaml; yaml.safe_load(open(...))"` 静检
8. push 任何 patches.py / build.py 改动前先跑 `python3 -m unittest discover -s tests`
9. 真机验证用 `sshpass`，不写死密码到文件，密码 `1` 是测试机临时账号
10. actions/cache@v4 跨 workflow 用 partial-prefix restore-keys 会撞库 — Android cache key 必须含 `-android` 后缀，iOS 含 `-ios` 后缀
