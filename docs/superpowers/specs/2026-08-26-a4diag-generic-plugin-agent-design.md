# A4Diag 通用插件化 LangGraph 故障处理 Agent 设计规范

**日期：** 2026-08-26
**状态：** 已批准（2026-08-26）
**目标版本：** v3 通用插件化版本

## 1. 决策摘要

A4Diag v3 是一个可从 GitHub 获取、可部署到不同 Linux 环境的通用故障诊断与修复 Agent。产品本身不包含 `t_11`、固定 IP 或某一机房的专用逻辑；`t_11` 只是管理员通过标准安装向导创建的一条普通目标配置。

系统采用 LangGraph 编排和进程外插件架构。核心进程拥有不可绕过的策略、审批、摘要绑定、事务、审计与恢复状态机；模型、目标连接、故障处理能力和通知渠道由独立插件提供。新安装默认处于 `NO_TARGETS + READ_ONLY`，没有管理员显式注册目标、启用能力并允许写入前，Agent 不能更改任何机器。

首版支持 Linux + systemd：Rocky/RHEL/AlmaLinux 8/9、Ubuntu 22.04/24.04、Debian 12。Docker、Kubernetes 和非 systemd 系统不在首版范围内。

## 2. 与既有方案的关系

本规范取代 v3 中“产品只能管理 `t_11`”的目标专用设计。此前 `t_03 -> t_11` 的安全实验仍然有效，但它现在是通用产品的一次部署实例，而不是核心代码约束。

本规范不授权当前工作立即连接、修改或部署到任何真实服务器。基础设施创建、服务器安装和目标写入必须在后续实施计划及管理员操作中单独执行。

当前已生成的 release candidate 只能作为依赖锁定和离线构建的技术基线，不能作为符合本规范的最终发行物。

## 3. 目标与非目标

### 3.1 目标

1. 安装后安全默认：无目标、只读、无写能力、无预设模型密钥。
2. 同时支持本机目标和远程 SSH 目标。
3. 将故障处理能力做成可安装、可验证、可固定版本的插件。
4. 在管理员授权范围内增强 Agent 自主诊断、低风险修复、验证和回滚能力。
5. 高风险操作由模型识别，但核心设置不可降低的风险下限；所有 HIGH 操作必须人工批准。
6. 支持在线安装和带完整 wheelhouse、摘要清单的离线安装。
7. 所有写操作可追踪、可验证；可逆操作必须具备恢复路径，无法确认时必须如实停止。

### 3.2 非目标

1. 不允许 Agent 自行安装、升级、启用插件或扩大权限。
2. 不允许模型修改目标、allowlist、风险策略、审批规则或通知屏障。
3. 首版不提供 Docker、Kubernetes、Windows、非 systemd Unix 支持。
4. 首版不建立公共插件市场；插件包由管理员从可信发行源安装。
5. 不承诺自动恢复根文件系统彻底损坏、主机永久失联等无法从当前控制面触达的故障。
6. 不把任意 shell 命令当作 LOW 风险能力。

## 4. 不可变安全条件

以下条件由核心强制执行，插件和模型均不能覆盖：

1. 未注册目标不能被读取或写入。
2. 目标默认只读；写入必须由管理员逐目标开启。
3. 操作必须同时满足目标、身份、能力、动作、参数和资源 allowlist。
4. 越出授权边界的操作直接拒绝，不能通过人工审批将其放行。
5. HIGH 操作永不自动执行，必须由本地 CLI 对当前摘要进行明确批准。
6. 从计划、审批到执行，目标身份、规范化命令/操作、参数、前置条件和回滚动作必须由同一摘要绑定。
7. 审批后任何实质字段变化都会使审批失效。
8. 模型输出只是提案，不是执行指令；插件只接收核心验证后的类型化请求。
9. 插件不能调用核心管理接口来增加自身权限。
10. 同一目标默认只运行一个写事务；不同目标可按全局并发上限并行。
11. 只读诊断可并行，但不能与同目标写事务产生不一致视图。
12. 审计记录追加写入，禁止模型和执行插件修改历史记录。
13. 任何不确定执行结果都不能自动重放。
14. 高风险能力即使由管理员启用，其写操作仍强制归类为 HIGH。

## 5. 总体架构

### 5.1 核心进程

核心是唯一决策与编排控制面，负责：

- LangGraph 状态图和检查点；
- 目标注册表与身份绑定；
- 插件注册表、版本/API/SHA 固定；
- 类型化操作规范化和 allowlist 校验；
- 风险下限与模型风险结果合并；
- 计划摘要、人工审批及审批失效；
- 事务锁、预算、超时和幂等键；
- apply/verify/undo/reconcile 状态机；
- 追加式审计、事件日志和恢复日志；
- 密钥引用解析和最小化分发；
- 通知策略与 `notification_required` 屏障。

核心不执行模型生成的原始 shell 文本，也不把策略判断委托给执行插件。

### 5.2 插件类型

首版定义四类插件：

| 类型 | 职责 | 首版内置插件 |
|---|---|---|
| Model | 诊断推理、计划、风险意见、复核 | OpenAI-compatible |
| Transport | 本机或远程目标身份验证、读取与受控执行通道 | local、ssh |
| Capability | 将意图转换为类型化操作，声明检查、执行、验证与回滚语义 | files、services、packages |
| Notification | 发送待审批、结果和异常事件 | CLI、FlashDuty、SMTP、Webhook |

`processes` 可作为只读诊断能力先提供；涉及终止进程等写动作时必须具备单独 allowlist 和事务语义。

`network`、`firewall`、`ssh`、`virtualization` 属于高风险插件，首版默认不安装、不启用。管理员以后可显式安装并启用，但其中所有写操作均强制 HIGH。

### 5.3 进程边界

插件运行在独立进程中，由 systemd 管理，通过版本化 JSON-RPC 协议和 Unix Domain Socket 与核心通信。每类插件使用独立服务账户、文件权限和 systemd 加固项，避免共享全部密钥或系统权限。

核心向插件发送类型化请求和短时操作票据。操作票据至少绑定：

- target ID 与目标身份指纹；
- capability、operation 和规范化参数；
- transaction ID、step ID 和幂等键；
- plan digest；
- 风险等级及审批引用；
- 签发时间、过期时间和单次使用标记。

插件必须拒绝缺失、过期、摘要不匹配或重复使用的票据。

### 5.4 信任边界的诚实说明

核心策略可以阻止模型通过合法接口越权，但不能把管理员主动安装的恶意执行插件变成安全代码。获得本机 root 权限或远程 SSH 凭据的恶意插件理论上可以绕过 JSON-RPC 协议。

因此：

1. 执行插件属于管理员信任的代码边界；
2. 安装时必须验证发行签名/摘要，并固定名称、版本、API 版本和 SHA256；
3. 不同插件只获得所需目标凭据和最小 OS 权限；
4. 高风险插件未安装或未启用时，不向其部署对应凭据和权限；
5. systemd sandbox、文件 ACL、独立账户和网络出口限制用于降低插件失陷后的影响面；
6. 第三方插件必须通过一致性测试，但测试不等同于恶意代码证明。

## 6. 插件契约

### 6.1 清单

每个插件包必须包含机器可读清单，至少声明：

- 唯一名称和插件类型；
- 插件版本、核心 API 最小/最大兼容版本；
- 可执行入口和 Unix socket；
- 配置 JSON Schema；
- 支持的操作及参数 Schema；
- 每个操作的风险下限；
- 所需系统权限、网络访问和密钥引用；
- 是否支持 prepare、verify、undo、reconcile；
- 目标系统兼容矩阵；
- 清单内容摘要标识；软件包 SHA256 和清单 SHA256 存放在外部签名发行索引及管理员 pin 中，避免软件包内部产生自引用摘要。

核心启动时验证清单、固定值和兼容性。验证失败的插件保持禁用，系统降级为仍可安全提供的只读能力。

### 6.2 类型化操作

Capability 插件暴露有限的、可验证的操作，例如：

- `files.replace_managed_file`
- `files.set_mode`
- `services.restart`
- `services.enable`
- `packages.install_exact`

每个操作必须给出：前置检查、规范化参数、预期变更、验证条件、回滚方法、不可逆说明和风险下限。

任意 shell 脚本不属于普通 LOW 操作。若以后提供 `script` 插件，所有写请求必须强制 HIGH、绑定完整脚本摘要、限定解释器和运行身份，并默认不安装。

### 6.3 生命周期

管理员可使用：

```text
a4diag plugin list
a4diag plugin verify <package>
a4diag plugin install <package>
a4diag plugin disable <name>
```

插件更新不得覆盖 `/etc/a4diag` 中的管理员配置。启用新版本前必须完成校验、兼容性探测和配置迁移预检；失败时继续使用原固定版本。

Agent 自身和模型没有插件安装、更新、启用或禁用权限。

## 7. 目标与权限配置

### 7.1 安全默认

首次安装后的状态为：

```yaml
targets: []
global_mode: read_only
auto_execute_low: false
```

管理员必须运行 `sudo a4diag init` 或等价非交互配置命令，才会产生目标配置。

### 7.2 目标模式

支持两类目标：

- `local`：管理 Agent 所在机器，不使用 SSH；绑定本机 machine-id 和系统指纹。
- `ssh`：管理远程机器；绑定 host、port、user、SSH host key 和远端 machine-id。

目标身份在每个写事务开始前重新核验。DNS/IP 变化、host key 变化、machine-id 变化或身份信息缺失时，写事务拒绝执行并要求管理员重新登记。

### 7.3 标准目标配置

目标配置应表达以下内容，不提供目标专用代码或 profile：

```yaml
targets:
  - id: lab-node-1
    mode: ssh
    identity_ref: target/lab-node-1
    write_enabled: true
    auto_execute_low: true
    capabilities:
      files:
        paths:
          - /etc/example-app/**
      services:
        units:
          - example-app.service
    approval:
      high: local_cli
    notifications:
      - flashduty-main
    notification_required: false
```

上例仅描述配置结构，不是默认配置。`t_11` 应通过相同字段注册为普通 SSH 目标；更换目标名、地址和 allowlist 不需要修改、重新编译或发布核心代码。

### 7.4 权限边界

管理员显式开启每个目标的 capability 及其 allowlist。allowlist 应优先使用结构化资源标识，而不是宽泛命令字符串：

- files：规范化绝对路径或受控 glob；
- services：完整 systemd unit 名；
- packages：包名、仓库和可选版本范围；
- processes：用户、PID namespace、可操作进程模式；
- 高风险能力：各自专用资源 Schema。

拒绝 `..` 路径穿越、符号链接逃逸、未固定 host key、通配所有服务、未受限 sudo 和其他可扩大边界的配置。危险的管理员配置必须由初始化器拒绝，而不是仅发出提示。

## 8. 模型提供方

Model 插件使用通用 OpenAI-compatible 配置：`base_url`、`api_key_ref`、`model` 及可选 provider 参数。它应支持 DeepSeek、OpenAI、Azure OpenAI、Ollama、vLLM 和其他兼容端点；provider 差异由插件适配，不写入核心业务流程。

安装过程不预设模型或密钥。初始化时运行能力探测，验证结构化输出、必要上下文长度和错误处理。探测失败时：

- 不允许写操作；
- 保留规则化只读采集；
- 输出 `read_only_no_model` 报告；
- 不使用未经验证的自由文本作为执行计划。

模型只生成类型化意图与参数，核心和 Capability 插件共同将其约束为确定的操作计划。

## 9. LangGraph 工作流

单次事件按下列节点推进：

1. `ingest`：接收告警或 CLI 请求，创建 event ID。
2. `resolve_target`：只从目标注册表解析目标并核验身份。
3. `acquire_read_view`：获取一致的只读诊断视图。
4. `collect`：调用已启用的只读 capability 采集证据。
5. `diagnose`：模型提出原因、置信度和缺失证据。
6. `plan`：模型生成类型化候选步骤。
7. `critic`：独立复核计划、风险、验证和回滚完整性。
8. `policy_gate`：核心执行边界、预算、风险下限和可逆性校验。
9. `freeze_plan`：规范化计划并计算 digest。
10. `approval_gate`：LOW 按配置自动继续；HIGH 进入本地 CLI 审批中断。
11. `prepare`：保存前置状态、创建事务日志和插件 marker。
12. `apply_step`：使用单次操作票据执行一个步骤。
13. `verify_step`：独立验证预期状态和副作用预算。
14. `next_or_undo`：继续下一步，或按逆序回滚已完成步骤。
15. `final_verify`：复查故障症状、目标健康和边界内副作用。
16. `report`：生成事实、命令/操作、结果、剩余风险和人工建议。
17. `close`：释放目标写锁并封存审计记录。

每个持久化节点均保存 checkpoint。恢复只能从明确的可恢复状态继续，不能靠模型猜测上一步是否成功。

## 10. 风险与审批

### 10.1 风险合并

最终风险为以下结果中的最高值：

- capability 清单声明的风险下限；
- 操作固有风险；
- 目标配置中的风险覆盖（只能提高）；
- planner 判断；
- critic 判断；
- 核心规则命中结果。

模型可以把操作升级为更高风险，不能把核心或插件清单的风险下限降级。

### 10.2 自动执行

LOW 只有在以下条件全部满足时才可自动执行：

1. 目标 `write_enabled: true`；
2. 目标 `auto_execute_low: true`；
3. planner 与 critic 都判定为 LOW；
4. 核心风险下限为 LOW；
5. 所有操作在 allowlist 内；
6. prepare、verify、undo 或明确的不可逆策略齐备；
7. 事务预算、并发与身份核验通过。

任一条件失败都不自动执行。

### 10.3 HIGH 审批

本地 CLI 是内置且始终可用的批准机制。批准界面必须显示：

- 目标身份；
- 将执行的完整类型化操作及等价命令展示；
- 风险原因；
- 影响资源；
- 验证条件；
- 回滚步骤；
- plan digest 和过期时间。

批准只对该 digest、目标和有效期生效。拒绝、超时、配置变化、身份变化或计划变化均使其失效。

## 11. 通知

首版支持 CLI、FlashDuty、SMTP 和通用 Webhook。通知是审批信息分发渠道，不替代本地 CLI 的批准动作。

- 未配置外部通知时，HIGH 事务可保持 `pending_approval`，管理员仍可在 CLI 审阅。
- `notification_required: false` 时，通知失败被记录，但不改变已经满足的本地审批规则。
- `notification_required: true` 时，外部通知发送和回执失败会阻止进入可批准/可执行状态。
- 通知内容包含将执行的操作/命令、风险、目标、摘要、验证与回滚说明。
- 密钥、令牌、私钥和环境机密必须在通知前脱敏。

## 12. 事务、验证与回滚

### 12.1 事务模型

同一目标同一时刻最多一个写事务。不同目标可并行，但受全局并发上限、模型调用预算和通知速率限制。

每个步骤记录：

- 前置状态和证据摘要；
- 规范化操作；
- 操作票据和插件 marker；
- 执行开始/结束时间；
- stdout/stderr 或结构化结果的脱敏摘要；
- 验证结果；
- undo 输入与结果。

### 12.2 回滚

优先使用应用级回滚：备份被管理文件、恢复原 mode/owner、恢复服务先前状态、撤销精确包变更。回滚按已成功步骤的逆序执行，并在每一步后验证。

插件必须明确声明操作是否可逆。不可逆操作不能伪装成可回滚；普通能力中的不可逆写操作至少为 HIGH，且批准界面必须显示该事实。

### 12.3 未知状态

若执行插件超时、崩溃或连接中断：

1. 状态标记为 `execution_unknown`；
2. 核心不自动重放操作；
3. 重启后调用插件 `reconcile`，根据 marker 和目标实际状态判断 `not_applied`、`applied`、`partial` 或 `unknown`；
4. 只有 `not_applied` 可在重新校验后重试；
5. `applied` 进入验证；`partial` 尝试安全回滚；`unknown` 停止并要求人工介入。

回滚失败必须报告 `rollback_partial` 或 `rollback_unknown`，不得宣称恢复成功。若目标失联或系统损坏到无法远程修复，Agent 只报告事实和建议；它没有创建、销毁或重建虚拟机的隐含权限。

## 13. 密钥与权限

1. 配置文件只保存 secret reference，不保存明文密钥。
2. 核心按调用向插件注入最小密钥，插件不得枚举其他 secret。
3. SSH 插件使用目标专用密钥和固定 host key；不共享宿主机通用管理员密钥。
4. 本机插件通过受限 sudoers/polkit 或独立 helper 获得精确动作权限，不能获得开放式 root shell。
5. 模型插件只获得模型 API 密钥，不获得 SSH、SMTP 或 FlashDuty 密钥。
6. 通知插件只获得自身渠道密钥，不获得目标执行凭据。
7. 日志、checkpoint、模型上下文和通知必须统一经过脱敏器。

## 14. 安装与发行

### 14.1 在线安装

目标用户流程为：

```bash
git clone <trusted-a4diag-repository>
cd a4diag
sudo ./install.sh
sudo a4diag init
```

`install.sh` 必须验证平台、Python 版本、系统依赖、发行清单和插件摘要。安装失败必须保持原版本可用，不留下半启用服务。

### 14.2 离线安装

离线包包含：

- 核心 wheel；
- 首版内置插件 wheel；
- 完整 Linux/Python 3.11 wheelhouse；
- 锁文件；
- systemd units；
- 配置 Schema；
- 版本化插件清单；
- 顶层 `SHA256SUMS` 和发行签名。

离线安装必须使用 `--no-index --find-links`，在安装前验证所有摘要，并拒绝额外 wheel、sdist、缺失依赖或不兼容平台标签。

### 14.3 初始化向导

`a4diag init` 负责：

1. 配置并探测 Model 插件；
2. 创建 local 或 SSH 目标；
3. 核验并保存目标身份；
4. 选择 capability 和精确 allowlist；
5. 选择是否允许 LOW 自动执行；
6. 固定 HIGH 为本地 CLI 审批；
7. 可选配置 FlashDuty、SMTP 或 Webhook；
8. 选择 `notification_required`；
9. 输出最终有效权限摘要，要求管理员确认；
10. 运行只读验收，写能力保持关闭直到验收通过。

`t_11` 的安装只是在上述第 2 至 8 步填写一组普通参数，不生成专用软件包、专用 profile 或硬编码规则。

## 15. 状态与失败语义

核心至少使用以下可观测状态：

- `read_only`
- `read_only_no_model`
- `policy_denied`
- `pending_approval`
- `approval_expired`
- `notification_blocked`
- `prepared`
- `executing`
- `execution_unknown`
- `verifying`
- `rollback_running`
- `rollback_succeeded`
- `rollback_partial`
- `rollback_unknown`
- `succeeded`
- `failed`

状态迁移由核心定义并持久化。插件只能返回结果，不能直接宣告事务最终成功。

## 16. 测试与验收

### 16.1 核心测试

- 无目标与只读默认状态；
- 未授权目标、能力、资源和参数均拒绝；
- LOW 自动执行所有必要条件；
- HIGH 无批准永不执行；
- 计划改变后批准失效；
- digest、身份、票据、过期和重放防护；
- 同目标单写事务、跨目标受限并发；
- journal、checkpoint、逆序回滚和未知状态恢复；
- 通知屏障两种模式；
- 模型不可修改插件和策略。

### 16.2 插件一致性测试

每个插件必须通过：

- 清单和配置 Schema；
- API 版本兼容；
- 权限声明完整性；
- 类型化输入拒绝未知字段；
- 超时、崩溃、重启和重复请求；
- prepare/apply/verify/undo/reconcile 契约；
- 脱敏和密钥隔离；
- 不接受无效操作票据。

### 16.3 集成与故障注入测试

- local 与 SSH 两种目标；
- Rocky/Alma/RHEL 8/9、Ubuntu 22.04/24.04、Debian 12；
- SSH host key 或 machine-id 变化；
- 插件执行中崩溃、网络超时和半完成操作；
- 模型返回无效 JSON、越权资源、缺失回滚或相互冲突步骤；
- FlashDuty/SMTP/Webhook 失败；
- 插件包篡改、SHA 不符和 API 不兼容；
- LOW 被模型误判但命中核心 HIGH 下限；
- HIGH 被模型试图降级；
- 目标失联时不执行盲目重试。

### 16.4 发行门槛

1. 核心源码与默认配置中不存在 `t_11` 或固定目标 IP 特例。
2. GitHub 在线安装在支持的干净发行版上通过。
3. 离线包在无网络环境完成摘要验证和安装。
4. 所有首版插件通过一致性测试。
5. `HIGH + no approval = zero execution` 有自动化证据。
6. `LOW + out of allowlist = zero execution` 有自动化证据。
7. 插件 crash/timeout 不会自动重复写操作。
8. 回滚失败状态如实暴露，报告不虚报成功。
9. 升级不覆盖管理员配置，失败可保留旧版本。

## 17. 实施影响

后续实施需要把当前应用从单体、目标专用结构重构为：

1. 独立核心包与稳定插件 API；
2. Model、Transport、Capability、Notification 插件包；
3. 插件 supervisor/systemd units 和 Unix socket 权限；
4. 通用目标注册表和 `a4diag init`；
5. 核心策略、票据、审批、事务与恢复机制；
6. 在线/离线统一发行装配；
7. 插件一致性测试工具和发行验收矩阵。

实施必须先建立契约和失败测试，再逐步迁移现有功能。旧的依赖锁、wheelhouse 和 release assembler 可复用，但现有 release candidate 在完成本规范的架构与验收前不得发布为最终版本。

## 18. 完成定义

只有在以下条件全部满足时，v3 通用插件化版本才算完成：

- 本规范的不可变安全条件被自动化测试证明；
- 普通用户能通过 GitHub 在线或离线包安装；
- 管理员能用同一套流程配置任意 local/SSH Linux 目标；
- `t_11` 实验不依赖任何目标专用代码；
- Agent 能在授权范围内自主诊断、执行 LOW 修复、验证并回滚；
- HIGH 始终绑定本地 CLI 人工审批；
- 插件和目标故障产生明确、可恢复或可人工接管的状态；
- 审计记录足以还原每次决策、批准、执行、验证和回滚。
