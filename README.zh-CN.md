# Veritio

[English](README.md) | [한국어](README.ko.md) | **简体中文**

[getveritio.com](https://getveritio.com) · [文档](https://getveritio.com/docs/) · [Veritio Cloud](https://getveritio.com/cloud/)

> 本文档是英文 [README](README.md) 的摘要翻译。如内容有出入，以英文文档为准；
> 协议与包的详细信息请参阅英文文档。

Veritio 是一个协议优先（protocol-first）的开源**证据层（evidence layer）**，
覆盖应用审计追踪（audit trail）、同意历史事件、数据主体请求处理证据、
数据留存（retention）事件、处理记录支持、证据图谱，以及可导出的对外提交记录。

它提供语言中立的模式（schema）、TypeScript/Python/Go SDK、轻量框架适配器、
宿主注入式存储辅助工具、本地 Workbench/MCP 工具，以及一致性（conformance）
测试夹具。Veritio 支持证据的采集与验证，但不构成法律意见；使用本工具并不会使
应用自动符合 GDPR、EAA、SOC 2、HIPAA、DORA、NIS2 或任何其他合规框架。

## 已实现的功能

- `spec/` 中语言中立的审计事件与证据边（evidence edge）模式
- 仅追加（append-only）的审计与边记录信封：规范化 JSON（canonical JSON）、
  SHA-256 哈希、前哈希链接（previous-hash link）、租户级幂等性
- 提供事件/边创建、规范化、哈希、敏感信息脱敏（redaction）与共享审计模板的
  TypeScript、Python、Go SDK
- TypeScript 专有的审计存储与溯源辅助工具（含 `createProvenanceRecorder`）
- Better Auth、Next.js、TanStack Start、SvelteKit、React、Vue、Svelte、
  存储辅助工具、Claude Code 捕获以及本地 CLI 的公开包
- 通过 `veritio dev --mcp` 运行的本地 Workbench 与 MCP 开发环路
- 覆盖 Better Auth（各框架）、Python FastAPI、Go Gin、存储适配器等的可运行示例

## 安装

公开包名称已稳定，但本仓库仍处于 1.0 之前的阶段。

```sh
npm install @veritio/core
npm install @veritio/storage
npm install @veritio/better-auth
npm install -D veritio
```

```sh
pip install veritio
go get github.com/getveritio/veritio/sdks/go
```

在本 monorepo 内开发时：

```sh
bun install
bun run verify
```

### 代理技能（Agent Skills）

可从 [skills.sh](https://www.skills.sh) 安装技能，让 Claude Code、Codex、
Cursor、opencode 等编码代理学会使用 Veritio SDK：

```sh
npx skills add getveritio/veritio
```

## TypeScript 快速开始

当你需要规范化的事件/边载荷以及确定性（deterministic）哈希时，使用
`@veritio/core`。内存版 `MemoryAuditStore` 仅持久化审计事件；如需事件与边的
完整链，请使用本地 Workbench/服务器或基于文件的存储。

```ts
import {
  MemoryAuditStore,
  createAuditEvent,
  createEvidenceEdge,
  hashEvidenceEdge,
} from "@veritio/core";

const store = new MemoryAuditStore();

const event = createAuditEvent({
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
});

const record = await store.append(event);

const edge = createEvidenceEdge({
  id: "edge_01",
  occurredAt: "2026-06-10T00:00:01.000Z",
  scope: { tenantId: "org_123", environment: "production" },
  from: { type: "actor", id: "usr_123", actorType: "user" },
  relation: "created",
  to: { type: "runtime_event", id: event.id },
  metadata: { reason: "member_invite" },
});

const edgeHash = hashEvidenceEdge(edge, record.hash);
```

## 本地 Workbench

无需托管账户即可运行 OSS 本地 Workbench 与 MCP 端点：

```sh
veritio dev --mcp --scenario
```

默认服务器绑定 `http://127.0.0.1:4983`，并提供：

- 事件与边的采集（ingest）及查询端点
- 证据图谱查询
- 哈希链验证
- 导出包预览
- 浏览器版 Workbench UI
- 位于 `/mcp` 的 MCP JSON-RPC 端点

MCP 读取工具默认可用。`veritio.record_event` 等写入工具仅在 CLI 以
`--allow-write-tools` 选项启动时才会暴露。

## 更多内容（英文文档）

协议不变式、包一览、存储辅助工具、示例与验证流程等其余内容，请参阅英文文档：

- [协议不变式与模式](README.md#protocol-invariants) — 规范化 JSON 与哈希规则、
  `spec/` 模式、一致性测试夹具
- [包一览](README.md#package-map) — 全部公开/私有包列表
- [存储](README.md#storage) — Postgres/Neon/MySQL/MariaDB/MongoDB 等宿主注入式
  存储辅助工具
- [示例](README.md#examples) — 各框架的可运行示例
- [仓库结构与验证](README.md#repository-layout)
- [docs/architecture.md](docs/architecture.md) — 架构文档

## 翻译说明

本中文文档与仓库一同维护，但更新可能滞后于英文文档。欢迎提交纠错与改进 PR，
也欢迎贡献其他语言（日本語等）的翻译 — 请参阅
[CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

Apache-2.0。
