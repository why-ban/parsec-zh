# parsec-zh —— Parsec 客户端中文汉化

把 **Windows 版 Parsec 客户端** 的界面在运行时替换为简体中文的注入式汉化工具。

- **不改动磁盘上任何 Parsec 文件**（其可执行文件/库都带数字签名，版本校验会拒绝被改动的文件）。
- **不联网、不收集任何数据**；日志默认不写入用户名/主机名/PeerID 等信息，且限制在 4MB。
- 通过 Hook Parsec UI 使用的 Dear ImGui 文本绘制接口，把界面文案实时替换为中文；中文与英文共用同一个字体（把系统中的中文字体**合并**进原字体），因此英文不受影响、中文也不糊。
- 附带一个常驻监听器：在 Parsec 启动/重启时自动把汉化模块注入到客户端进程；如果首屏来不及汉化，会自动重启一次客户端使其变为中文。

> ⚠️ **免责声明**：本项目与 Parsec / Unity 无任何隶属或合作关系；仅修改**运行中进程的内存**，不修改也不分发 Parsec 的任何二进制文件。使用第三方客户端注入可能违反 Parsec 的服务条款，请自行评估并自行承担风险。请勿将本项目用于违反任何服务条款或法律的用途。

---

## 一、系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 10 / 11（64 位） |
| Parsec | 已安装官方 Windows 客户端（默认 `C:\Program Files\Parsec\`） |
| 权限 | 安装/卸载**需要管理员**（要写入 `C:\Windows\parsec-zh\`、结束并重启客户端） |
| 中文字体 | 任意一款即可：微软雅黑 / 等线 / 黑体 / 宋体（系统自带，缺省即可） |

安装脚本会自动定位 Parsec 客户端：优先 `C:\Program Files\Parsec\parsecd.exe`，否则读取正在运行的 `parsecd` 进程的真实路径。监听器也按进程名 + “镜像路径包含 parsec”来判断，因此自定义安装位置通常也能工作。

---

## 二、一键安装（推荐给普通用户）

1. 下载并解压 `parsec-zh-<version>.zip`。
2. 双击 **`install.cmd`**，在 UAC 弹窗中选择“是”。
3. 等待脚本结束；若此时客户端是英文，监听器会在数秒内自动重启一次客户端，界面即变为中文。

脚本会：

- 把 `parsec-zh.dll`、`parsec-zh-launcher.exe` 复制到 `C:\Windows\parsec-zh\`
  （Parsec 收窄了 DLL 搜索路径，运行期模块只能从 `C:\Windows` 下加载）。
- 注册一个**当前用户**的计划任务 `ParsecZH`（登录时启动、最高权限、与客户端同一会话），并**每 2 分钟做一次健康检查**：若监听器不在则自动拉起。监听器**没有窗口**，不会打扰你。
- 结束并重启一次客户端，使其立即生效。

> 请用**将要使用 Parsec 的那个 Windows 用户**（且以管理员身份）运行安装脚本，使任务注册到该用户名下。

---

## 三、手动安装

以管理员身份打开 PowerShell，在解压目录执行：

```powershell
pwsh -ExecutionPolicy Bypass -File .\install.ps1
```

常用参数：

```powershell
# 只复制与注册自启，不主动启动监听器/不重启客户端
pwsh -ExecutionPolicy Bypass -File .\install.ps1 -NoStart
```

---

## 四、卸载与恢复

- **卸载**（推荐，普通用户）：双击 `uninstall.cmd`，或管理员执行：

  ```powershell
  pwsh -ExecutionPolicy Bypass -File .\uninstall.ps1
  ```

  它会：停止监听器与客户端 → 注销计划任务 `ParsecZH` / `ParsecZH-logon`（并清除历史遗留的 `HKCU\...\Run\ParsecZH`）→ 删除 `C:\Windows\parsec-zh\` → 清理历史方案的遗留物 → 重启客户端。删除后客户端恢复为原版英文界面。

- **彻底恢复**（仓库内开发用）：管理员执行 `restore.ps1`，逻辑与卸载一致，另会清理崩溃计数、锁文件与历史 IFEO 项。

---

## 五、从源码构建

要求：Windows + PowerShell 7 + MinGW-w64（gcc）+ Python 3。

```powershell
# 1) 指定 MinGW（三种任选其一）
$env:PARSEC_ZH_MINGW = "C:\mingw64\bin"        # 方式 A：环境变量
# 方式 B：把 gcc 加进 PATH
# 方式 C：装到常见目录（脚本会自动探测）

# 2) 构建（自动重新生成 src/translations.h 并编译 DLL 与监听器）
pwsh -File build.ps1
```

产物位于 `build\`：`parsec-zh.dll`、`parsec-zh-launcher.exe`。

### 目录结构

```
src/parsec_zh.c        汉化主模块（注入 DLL）：字体合并、文本翻译、子进程注入
src/render_stub.S      RenderText / CalcTextSizeA 的汇编桩
src/inject.c           常驻监听器：注入 + 自愈
src/translations.h     由 tools/gen_translations.py 生成的词表（勿手改）
translations/zh.json   英→中词典（唯一需要维护的翻译文件）
tools/gen_translations.py      由 zh.json 生成 translations.h
tools/merge_additions.py       批量补充词条（可选）
tools/verify_discovery.py      校验各版本 skel 的函数定位（可选）
minhook/               MinHook（BSD-2-Clause），用于 AddFont 的 inline hook
install.ps1 / uninstall.ps1    安装 / 卸载
deploy.ps1 / restore.ps1       开发机部署 / 彻底恢复
```

### 修改翻译

只改 `translations\zh.json`（键=英文原文，值=中文），然后重新构建即可（`build.ps1` 会自动重新生成 `src/translations.h`）。词典采用**整串精确匹配**，并额外支持：去首尾空格、去前导图标字符、printf 占位符分段匹配、多行逐行匹配。

---

## 六、开发者选项（默认关闭）

以下开关**默认全部关闭**，只有设置了环境变量 `PARSEC_ZH_DEV=1` 时才读取，且 flag 文件需放在被注入 DLL 的同目录：

- `PARSEC_ZH_VERBOSE=1`：打开逐帧翻译采样 / 未命中(MISS)采集 / 周期心跳等**高噪声日志**（默认关闭，以避免写入用户信息、避免日志膨胀）。
- `PARSEC_ZH_DEV=1`：允许读取 `*.flag` 开发开关（`nofont/nocalc/norender/noldr/nocp/nosuspend/passthru/discover_only/...`）。

监听器命令行：

```
parsec-zh-launcher.exe                 常驻：注入 + 自愈
parsec-zh-launcher.exe --no-restart    常驻：仅注入，不做自愈重启
parsec-zh-launcher.exe --inject-now    立即注入一次后退出
parsec-zh-launcher.exe --inject-pid <PID>   只注入指定进程
```

---

## 七、常见问题（FAQ）

**Q：安装后还是英文？**
A：客户端不是“已运行”，就是刚装好的首屏来不及汉化。安装脚本会重启一次；若仍为英文，手动退出并重新打开 Parsec 即可。仍不行请看 `C:\Windows\parsec-zh\parsec-zh.log` 中是否有 `AddFont hooked` / `RenderText hooked`。

**Q：会被杀毒软件拦截吗？**
A：很可能。注入类工具（跨进程写内存 + 远程线程 + 内联 Hook）是 Defender/SmartScreen/EDR 以及**火绒、腾讯电脑管家、360** 等安全软件的常见拦截与查杀特征（表现为：安装时提示“访问被拒绝”、文件被锁定无法覆盖、程序被隔离）。本包**未做代码签名**。解决办法：把 `C:\Windows\parsec-zh` 加入安全软件的**白名单/信任区**，或安装时临时关闭其实时防护；面向公众大规模分发前建议先做代码签名与误报申诉。

> 若安装中途报“对路径 `C:\Windows\parsec-zh\parsec-zh.dll` 的访问被拒绝”：优先确认不是被安全软件锁定（见本条）。安装脚本也会自动尝试 `takeown` + `icacls /reset` 接管权限并给出提示。

**Q：会修改 Parsec 的文件或注册表吗？**
A：不会改 Parsec 的任何文件。持久化仅来自**安装脚本**：它注册当前用户的登录计划任务 `ParsecZH`（卸载会删除）。DLL 与监听器自身不写注册表、不装服务。

**Q：日志在哪？会收集隐私吗？**
A：`C:\Windows\parsec-zh\parsec-zh.log` 与 `...\parsec-zh-launcher.log`。默认只记录系统路径 / 进程号 / 模块名 / 计数，**不记录用户名、主机名、PeerID、命令行**；两份日志均有 4MB 上限。

**Q：某些生僻汉字显示成“?”？**
A：仅当**用户自己输入的动态文本**（如中文计算机名/用户名）含罕见字时可能出现。ImGui 1.73 的字体图集对常用字与全部界面文案均覆盖，界面本身不会出现问号。

**Q：Parsec 升级后还能用吗？**
A：本工具在运行时定位函数（不依赖固定地址），并会在版本不匹配时**安全退回英文**而非出错。当前已在 `150-101b` / `150-104a` / `105c` 上验证定位一致。

**Q：升级/重装 Parsec 后需要重装汉化吗？**
A：一般不需要，重启客户端即可。若恢复到英文且日志有 `VERIFY rejected`，说明该版本结构变化，请提 Issue 反馈版本号。

---

## 八、安全与隐私

- 不联网、无遥测、无上传。
- 不修改 Parsec 二进制（其签名校验会拒绝被改动的文件）；只打补丁到进程内存。
- `C:\Windows\parsec-zh\` 目录与其中的 `parsec-zh.dll`/`parsec-zh-launcher.exe` 对 `Users` 只读（避免可被普通用户改写而造成的提权风险）；仅两个**日志文件**对 `Users` 可写，以便用户态进程记录诊断。
- 卸载脚本可 100% 移除本工具的所有产物与注册项。

---

## 九、许可

本仓库中**我们自己的代码**以 [MIT](LICENSE) 许可发布。
`minhook/` 为第三方库，遵循其自带的 **BSD-2-Clause**（见 `minhook/LICENSE.txt`）。
本项目**不含** Parsec 的任何文件或转储。
