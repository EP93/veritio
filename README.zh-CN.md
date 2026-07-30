# Veritio

[English](README.md) | [Deutsch](README.de.md) | [한국어](README.ko.md) | **简体中文**

[getveritio.com](https://getveritio.com) · [文档](https://getveritio.com/docs/) · [Veritio Cloud](https://getveritio.com/cloud/)

[![Verify](https://github.com/getveritio/veritio/actions/workflows/verify.yml/badge.svg)](https://github.com/getveritio/veritio/actions/workflows/verify.yml)
[![npm](https://img.shields.io/npm/v/%40veritio%2Fcore?label=%40veritio%2Fcore)](https://www.npmjs.com/package/@veritio/core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> 本文档是英文 [README](README.md) 的翻译版本。如内容有出入，以英文文档为准。

Veritio 是一个协议优先（protocol-first）的开源**证据层（evidence layer）**：
篡改留痕（tamper-evident）的审计追踪、AI 智能体溯源、同意与 DSAR 工作流证据、
数据留存（retention）事件，以及任何人都可以离线验证的合规导出。

Veritio 支持合规证据的采集与验证，但不构成法律意见；使用本工具并不会使应用
自动符合 GDPR、EAA、SOC 2、HIPAA、DORA、NIS2 或任何其他合规框架。

## 为什么选择 Veritio

- **结构上篡改留痕。** 仅追加（append-only）记录，配合规范化 JSON（canonical
  JSON）、SHA-256 哈希链与租户级幂等性。验证可检测出修改、删除与重排。
- **可离线验证。** 导出签名的证据包（`vevb-1`），随处可验 — 无需网络、无需
  厂商、无需账户。
- **是协议，不是锁定。** [`spec/`](spec/) 中的语言中立模式（schema），配合
  TypeScript、Python、Go 三套 SDK 产出逐字节一致的哈希与评分，由跨语言一致性
  （conformance）测试夹具固定。
- **AI 智能体溯源。** 将 Claude Code 会话捕获为哈希链接、已脱敏的证据 —
  提示词、工具调用与文件变更仅以哈希和稳定 ID 记录，绝不保存原始内容。
- **确定性风险评分。** 结构化风险信号在三套 SDK 中评出逐字节相同的分数；
  没有模型调用，查询时也没有启发式规则。
- **默认隐私。** 确定性元数据脱敏（redaction）、以稳定 ID 取代个人数据、
  必填字段缺失时 fail-closed 保证完整性。
- **轻薄边界。** 框架适配器只做上下文转换；存储由宿主注入 — 数据库客户端与
  凭证始终属于你，绝不属于我们。

## 快速开始

```sh
npm install @veritio/core
```

```ts
import { MemoryAuditStore, createAuditEvent } from "@veritio/core";

const store = new MemoryAuditStore();

const record = await store.append(
  createAuditEvent({
    id: "evt_01",
    occurredAt: "2026-06-10T00:00:00.000Z",
    actor: { type: "user", id: "usr_123" },
    action: "org.member.invited",
    target: { type: "organization", id: "org_123" },
    scope: { tenantId: "org_123", environment: "production" },
    purpose: "access_management",
    lawfulBasis: "contract",
    retention: "security_1y",
    metadata: { inviteId: "inv_123", role: "viewer" },
  }),
);
// record.hash 与该租户的上一条记录形成哈希链。
```

需要持久化存储时，通过 [`@veritio/storage`](storage/README.md) 注入你自己的
数据库客户端（Postgres、Neon、MySQL、MariaDB、MongoDB，另有本地文件存储与
Redis 链尾缓存）。Python 与 Go SDK 提供相同的事件、哈希与脱敏语义 — 参见
[`sdks/python`](sdks/python/) 与 [`sdks/go`](sdks/go/)。

**事后举证。** 构建可移植的导出包并离线验证 — 输出 `structure` /
`integrity` / `chains` / `signature` 各关卡结果与最终的 `VALID` / `INVALID`：

```sh
veritio verify-bundle bundle.json --public-key key.hex --require-signature
```

导出包格式在 [`spec/export-bundle.md`](spec/export-bundle.md) 中规范化定义；
`veritio` CLI 目前从本仓库运行，尚未发布到 npm。

## 捕获 AI 智能体活动

[`@veritio/claude-code`](adapters/claude-code/README.md) 将 Claude Code 会话
记录为哈希链接的溯源轨迹 — 通过钩子（hook）带外（out-of-band）采集，证据不
依赖于智能体主动上报：

- 提示词、工具输入与文件内容**仅以哈希和稳定 ID** 捕获 — 原始内容绝不进入
  轨迹。
- 每个事件都带有会话的 `sessionId` 与持久的 `activityEpisodeId`，整个智能体
  会话汇聚为一个可审查的活动片段（episode）。
- Bash 命令与文件变更被归类为结构化的 `metadata.riskSignals`，由 SDK 风险
  模块确定性评分（`veritio.reference.v1` 策略）— 在 TypeScript、Python、Go
  中产出相同字节。参见 [docs/risk-scoring.md](docs/risk-scoring.md)。
- 只读 MCP 服务器让人或其他智能体可以列出会话、检查溯源图谱、导出可验证的
  证据包。

通过 [skills.sh](https://www.skills.sh) 让编码智能体学会使用本 SDK：

```sh
npx skills add getveritio/veritio
```

## 受治理操作（Governed Actions）

当服务器操作或 API 路由变更受治理实体时，一个辅助函数即可派生变更/活动 ID、
租户级幂等哈希、变更路径、修订证据，以及可直接进 outbox 的事件与边输入 —
在 TypeScript 中为 `createGovernedActionDraft`，Python 中为
`create_governed_action_draft`，Go 中为 `CreateGovernedActionDraft`：

```ts
import { createGovernedActionDraft, defineEntity } from "@veritio/core";

const ProjectEntry = defineEntity({
  authority: "app.example",
  type: "project_entry",
  schemaRef: "app.example/project-entry@1",
  fieldSetRef: "project-entry-governed-fields@1",
  identity: (row: { id: string }) => row.id,
  fields: {
    status: { capture: "full" },
    customerEmail: { capture: "keyed_digest" },
    privateNotes: { capture: "omit" },
  },
});
```

受治理操作应记录在服务器端业务变更边界，而不是浏览器表单状态中。TypeScript、
FastAPI、Gin、框架适配器、托管接入（hosted ingest）与事务性 outbox 的完整
方案见 [`docs/integrations.md`](docs/integrations.md)。

## 本地 Workbench

无需任何账户即可运行本地 Workbench 与 MCP 端点：

```sh
veritio dev --mcp --scenario
```

在 `http://127.0.0.1:4983` 上提供事件/边接入、证据图谱查询、链验证、导出
预览、浏览器 UI，以及 `/mcp` 处的 MCP JSON-RPC 端点。除非以
`--allow-write-tools` 启动，写入类工具保持隐藏。

## 生态

| 包 | 状态 | 角色 |
| --- | --- | --- |
| [`@veritio/core`](sdks/typescript/) | npm | TypeScript SDK：事件、边、哈希、脱敏、模板、溯源记录器、风险评分、断言。 |
| [`@veritio/storage`](storage/) | npm | 宿主注入式 Postgres/Neon/MySQL/MariaDB/MongoDB 存储、Redis 链尾缓存、文件存储、一致性测试。 |
| [`@veritio/claude-code`](adapters/claude-code/) | npm | Claude Code 捕获钩子 + 只读 MCP 查询/导出。 |
| [`@veritio/better-auth`](adapters/better-auth/) | npm | Better Auth 服务器端生命周期适配器。 |
| [`@veritio/next`](adapters/next/), [`@veritio/tanstack-start`](adapters/tanstack-start/), [`@veritio/sveltekit`](adapters/sveltekit/) | npm | 服务器端框架适配器。 |
| [`@veritio/react`](adapters/react/), [`@veritio/vue`](adapters/vue/), [`@veritio/svelte`](adapters/svelte/) | npm | 浏览器安全的 UI 意图辅助工具；不做客户端记录。 |
| [`sdks/python`](sdks/python/) | 仓库内 | Python SDK（`pip install -e sdks/python`；尚未发布到 PyPI）。 |
| [`sdks/go`](sdks/go/) | Go 模块 | `go get github.com/getveritio/veritio/sdks/go`。 |
| `veritio` CLI、`@veritio/server`、`@veritio/gateway`、`@veritio/codex`、express/hono/trpc 壳层 | 仓库内 | 本地 Workbench/MCP CLI、自托管服务器模块、实验性 AI 网关，以及尚未发布的适配器表面。 |

## Veritio Cloud

[Veritio Cloud](https://getveritio.com/cloud/) 是托管选项：在同一协议之上
提供托管接入、仪表盘、风险时间线与区域感知导出。本仓库中的一切都可以在没有
账户的情况下完全自托管运行 — 托管交付永远是可选项。

## 了解更多

- [`spec/`](spec/) — 语言中立的模式、哈希规则与一致性测试夹具；协议的唯一
  事实来源。
- [`docs/architecture.md`](docs/architecture.md) — 分层、完整性模型、脱敏、
  风险与托管边界。
- [`docs/integrations.md`](docs/integrations.md) — 集成方案。
- [`docs/ai-integration.md`](docs/ai-integration.md) — AI 智能体捕获与 MCP
  指南。
- [`examples/`](examples/) — 可运行的 Better Auth、FastAPI、Gin、存储与托管
  接入示例。
- 参与贡献：`bun install && bun run verify` 运行完整的跨语言检查门；参见
  [`docs/release-checklist.md`](docs/release-checklist.md)。

## 许可证

Apache-2.0。
