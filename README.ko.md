# Veritio

[English](README.md) | [Deutsch](README.de.md) | **한국어** | [简体中文](README.zh-CN.md)

[getveritio.com](https://getveritio.com/ko/) · [문서](https://getveritio.com/docs/) · [Veritio Cloud](https://getveritio.com/ko/cloud/)

[![Verify](https://github.com/getveritio/veritio/actions/workflows/verify.yml/badge.svg)](https://github.com/getveritio/veritio/actions/workflows/verify.yml)
[![npm](https://img.shields.io/npm/v/%40veritio%2Fcore?label=%40veritio%2Fcore)](https://www.npmjs.com/package/@veritio/core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> 이 문서는 영어 [README](README.md)의 번역본입니다. 내용이 다를 경우 영어
> 문서가 우선합니다.

Veritio는 프로토콜 우선(protocol-first) 오픈소스 **증적(evidence) 레이어**입니다.
변조가 드러나는(tamper-evident) 감사 추적, AI 에이전트 프로버넌스, 동의·DSAR
워크플로 증적, 보존(retention) 이벤트, 그리고 누구나 오프라인으로 검증할 수 있는
컴플라이언스 내보내기를 제공합니다.

Veritio는 컴플라이언스 증적의 수집과 검증을 지원하는 도구이며, 법률 자문이
아닙니다. 이 도구를 사용한다고 해서 애플리케이션이 GDPR, EAA, SOC 2, HIPAA,
DORA, NIS2 등 어떤 규제 프레임워크를 자동으로 준수하게 되는 것은 아닙니다.

## 왜 Veritio인가

- **구조적으로 변조가 드러납니다.** 정규화 JSON(canonical JSON), SHA-256 해시
  체인, 테넌트 범위 멱등성을 갖춘 추가 전용(append-only) 레코드. 검증 과정에서
  수정·삭제·순서 변경이 탐지됩니다.
- **오프라인 검증.** 서명된 증적 번들(`vevb-1`)을 내보내면 네트워크도, 벤더도,
  계정도 없이 어디서든 검증할 수 있습니다.
- **락인이 아니라 프로토콜.** [`spec/`](spec/)의 언어 중립 스키마와
  TypeScript·Python·Go SDK가 바이트 단위로 동일한 해시와 점수를 생성하며,
  교차 언어 적합성(conformance) 픽스처로 고정됩니다.
- **AI 에이전트 프로버넌스.** Claude Code 세션을 해시 체인으로 연결된, 민감정보가
  마스킹된 증적으로 캡처합니다 — 프롬프트, 도구 호출, 파일 변경은 해시와 안정적인
  ID로만 기록되고 원본 내용은 절대 저장되지 않습니다.
- **결정적 리스크 스코어링.** 구조화된 리스크 신호가 세 SDK 모두에서 동일한
  바이트로 점수화됩니다. 모델 호출도, 조회 시점 휴리스틱도 없습니다.
- **기본값이 프라이버시.** 결정적 메타데이터 마스킹(redaction), 개인정보 대신
  안정적인 ID 사용, 필수 필드 누락 시 fail-closed 무결성.
- **얇은 경계.** 프레임워크 어댑터는 컨텍스트 변환만 담당하고, 스토리지는 호스트
  주입 방식입니다 — 데이터베이스 클라이언트와 자격 증명은 언제나 여러분의 것입니다.

## 빠른 시작

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
// record.hash는 해당 테넌트의 직전 레코드와 체인으로 연결됩니다.
```

내구성 있는 저장이 필요하면 [`@veritio/storage`](storage/README.md)를 통해
직접 데이터베이스 클라이언트를 주입하세요(Postgres, Neon, MySQL, MariaDB,
MongoDB, 로컬 파일 스토어와 Redis 팁 캐시 포함). Python과 Go SDK는 동일한
이벤트·해싱·마스킹 의미론을 제공합니다 — [`sdks/python`](sdks/python/)과
[`sdks/go`](sdks/go/)를 참조하세요.

**나중에 증명하기.** 이동 가능한 내보내기 번들을 만들어 오프라인으로 검증하면
`structure` / `integrity` / `chains` / `signature` 게이트별 결과와 최종
`VALID` / `INVALID`가 출력됩니다:

```sh
veritio verify-bundle bundle.json --public-key key.hex --require-signature
```

번들 형식은 [`spec/export-bundle.md`](spec/export-bundle.md)에 규범적으로
정의되어 있습니다. `veritio` CLI는 현재 이 저장소에서 실행하며 아직 npm에
게시되지 않았습니다.

## AI 에이전트 활동 캡처

[`@veritio/claude-code`](adapters/claude-code/README.md)는 Claude Code 세션을
해시 체인 프로버넌스 추적으로 기록합니다 — 훅(hook)을 통한 out-of-band
방식이므로, 에이전트가 스스로 보고하는지에 증적이 좌우되지 않습니다:

- 프롬프트, 도구 입력, 파일 내용은 **해시와 안정적인 ID로만** 캡처됩니다 —
  원본 내용은 추적에 절대 포함되지 않습니다.
- 모든 이벤트에 세션의 `sessionId`와 영속적인 `activityEpisodeId`가 찍히므로,
  에이전트 세션 전체가 하나의 검토 가능한 에피소드로 묶입니다.
- Bash 명령과 파일 변경은 구조화된 `metadata.riskSignals`로 분류되고, SDK
  리스크 모듈이 결정적으로 점수화합니다(`veritio.reference.v1` 정책) —
  TypeScript, Python, Go에서 동일한 바이트가 나옵니다.
  [docs/risk-scoring.md](docs/risk-scoring.md)를 참조하세요.
- 읽기 전용 MCP 서버를 통해 사람이나 다른 에이전트가 세션을 나열하고,
  프로버넌스 그래프를 살펴보고, 검증 가능한 번들을 내보낼 수 있습니다.

코딩 에이전트에게 SDK 사용법을 가르치려면 [skills.sh](https://www.skills.sh)를
이용하세요:

```sh
npx skills add getveritio/veritio
```

## 거버넌스 액션(Governed Actions)

서버 액션이나 API 라우트가 거버넌스 대상 엔티티를 변경할 때, 헬퍼 하나가
변경/활동 ID, 테넌트 범위 멱등성 해시, 변경 경로, 리비전 증적, 아웃박스용
이벤트·엣지 입력을 도출합니다 — TypeScript의 `createGovernedActionDraft`,
Python의 `create_governed_action_draft`, Go의 `CreateGovernedActionDraft`로
제공됩니다:

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

거버넌스 액션은 브라우저 폼 상태가 아니라 서버 측 비즈니스 변경 경계에서
기록하세요. TypeScript, FastAPI, Gin, 프레임워크 어댑터, 호스티드 인제스트,
트랜잭셔널 아웃박스 전체 레시피는
[`docs/integrations.md`](docs/integrations.md)에 있습니다.

## 로컬 Workbench

계정 없이 로컬 Workbench와 MCP 엔드포인트를 실행할 수 있습니다:

```sh
veritio dev --mcp --scenario
```

`http://127.0.0.1:4983`에서 이벤트/엣지 수집, 증적 그래프 조회, 체인 검증,
내보내기 미리보기, 브라우저 UI, `/mcp` MCP JSON-RPC 엔드포인트를 제공합니다.
쓰기 도구는 `--allow-write-tools`로 시작하지 않는 한 숨겨져 있습니다.

## 생태계

| 패키지 | 상태 | 역할 |
| --- | --- | --- |
| [`@veritio/core`](sdks/typescript/) | npm | TypeScript SDK: 이벤트, 엣지, 해싱, 마스킹, 템플릿, 프로버넌스 레코더, 리스크 스코어링, 어서션. |
| [`@veritio/storage`](storage/) | npm | 호스트 주입식 Postgres/Neon/MySQL/MariaDB/MongoDB 스토어, Redis 팁 캐시, 파일 스토어, 적합성 테스트. |
| [`@veritio/claude-code`](adapters/claude-code/) | npm | Claude Code 캡처 훅 + 읽기 전용 MCP 조회/내보내기. |
| [`@veritio/better-auth`](adapters/better-auth/) | npm | Better Auth 서버 측 라이프사이클 어댑터. |
| [`@veritio/next`](adapters/next/), [`@veritio/tanstack-start`](adapters/tanstack-start/), [`@veritio/sveltekit`](adapters/sveltekit/) | npm | 서버 측 프레임워크 어댑터. |
| [`@veritio/react`](adapters/react/), [`@veritio/vue`](adapters/vue/), [`@veritio/svelte`](adapters/svelte/) | npm | 브라우저 안전 UI 인텐트 헬퍼; 클라이언트 측 기록 없음. |
| [`sdks/python`](sdks/python/) | 저장소 내 | Python SDK(`pip install -e sdks/python`; 아직 PyPI 미게시). |
| [`sdks/go`](sdks/go/) | Go 모듈 | `go get github.com/getveritio/veritio/sdks/go`. |
| `veritio` CLI, `@veritio/server`, `@veritio/gateway`, `@veritio/codex`, express/hono/trpc 셸 | 저장소 내 | 로컬 Workbench/MCP CLI, 셀프 호스티드 서버 모듈, 실험적 AI 게이트웨이, 아직 게시되지 않은 어댑터 표면. |

## Veritio Cloud

[Veritio Cloud](https://getveritio.com/ko/cloud/)는 호스티드 옵션입니다. 동일한
프로토콜 위에서 관리형 인제스트, 대시보드, 리스크 타임라인, 리전 인지
내보내기를 제공합니다. 이 저장소의 모든 것은 계정 없이 완전히 셀프 호스팅으로
동작하며, 호스티드 전달은 언제나 선택 사항입니다.

## 더 알아보기

- [`spec/`](spec/) — 언어 중립 스키마, 해시 규칙, 적합성 픽스처. 프로토콜의
  단일 진실 공급원입니다.
- [`docs/architecture.md`](docs/architecture.md) — 계층, 무결성 모델, 마스킹,
  리스크, 호스티드 경계.
- [`docs/integrations.md`](docs/integrations.md) — 통합 레시피.
- [`docs/ai-integration.md`](docs/ai-integration.md) — AI 에이전트 캡처와 MCP
  가이드.
- [`examples/`](examples/) — 실행 가능한 Better Auth, FastAPI, Gin, 스토리지,
  호스티드 인제스트 예제.
- 기여하기: `bun install && bun run verify`가 전체 교차 언어 게이트를
  실행합니다. [`docs/release-checklist.md`](docs/release-checklist.md)를
  참조하세요.

## 라이선스

Apache-2.0.
