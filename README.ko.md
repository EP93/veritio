# Veritio

[English](README.md) | **한국어** | [简体中文](README.zh-CN.md)

[getveritio.com](https://getveritio.com/ko/) · [문서](https://getveritio.com/docs/) · [Veritio Cloud](https://getveritio.com/ko/cloud/)

> 이 문서는 영어 [README](README.md)의 요약 번역본입니다. 내용이 다를 경우 영어
> 문서가 우선하며, 프로토콜·패키지 세부 사항은 영어 문서를 참조해 주세요.

Veritio는 프로토콜 우선(protocol-first) 오픈소스 **증적(evidence) 레이어**입니다.
애플리케이션 감사 추적(audit trail), 동의 이력 이벤트, 정보주체 요청 처리 증적,
보존(retention) 이벤트, 처리 기록 지원, 증적 그래프, 그리고 외부 제출용 내보내기
레코드를 다룹니다.

언어 중립 스키마, TypeScript/Python/Go SDK, 경량 프레임워크 어댑터, 호스트 주입
방식의 스토리지 헬퍼, 로컬 Workbench/MCP 도구, 적합성(conformance) 픽스처를
제공합니다. Veritio는 증적 수집과 검증을 지원하는 도구이며, 법률 자문이 아닙니다.
이 도구를 사용한다고 해서 애플리케이션이 GDPR, EAA, SOC 2, HIPAA, DORA, NIS2 등
어떤 규제 프레임워크를 자동으로 준수하게 되는 것은 아닙니다.

## 구현된 기능

- `spec/`의 언어 중립 감사 이벤트·증적 엣지 스키마
- 추가 전용(append-only) 감사·엣지 레코드 봉투: 정규화 JSON(canonical JSON),
  SHA-256 해시, 이전 해시 연결(previous-hash link), 테넌트 범위 멱등성
- 이벤트/엣지 생성, 정규화, 해싱, 민감정보 마스킹(redaction), 공용 감사 템플릿을
  제공하는 TypeScript·Python·Go SDK
- TypeScript 전용 감사 스토리지·프로버넌스 헬퍼(`createProvenanceRecorder` 포함)
- Better Auth, Next.js, TanStack Start, SvelteKit, React, Vue, Svelte, 스토리지
  헬퍼, Claude Code 캡처, 로컬 CLI 공개 패키지
- `veritio dev --mcp`로 실행하는 로컬 Workbench 및 MCP 개발 루프
- Better Auth(프레임워크별), Python FastAPI, Go Gin, 스토리지 어댑터 등 실행
  가능한 예제

## 설치

공개 패키지 이름은 안정적이지만, 이 저장소는 아직 1.0 이전 단계입니다.

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

모노레포 내부에서 개발할 때:

```sh
bun install
bun run verify
```

### 에이전트 스킬

Claude Code, Codex, Cursor, opencode 등 코딩 에이전트에게 Veritio SDK 사용법을
가르치는 스킬을 [skills.sh](https://www.skills.sh)에서 설치할 수 있습니다:

```sh
npx skills add getveritio/veritio
```

## TypeScript 빠른 시작

정규화된 이벤트/엣지 페이로드와 결정적(deterministic) 해시가 필요할 때
`@veritio/core`를 사용합니다. 인메모리 `MemoryAuditStore`는 감사 이벤트만
보존하므로, 이벤트·엣지 체인이 함께 필요하면 로컬 Workbench/서버 또는 파일 기반
스토어를 사용하세요.

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

## 로컬 Workbench

호스팅 계정 없이 OSS 로컬 Workbench와 MCP 엔드포인트를 실행할 수 있습니다:

```sh
veritio dev --mcp --scenario
```

기본 서버는 `http://127.0.0.1:4983`에 바인딩되며 다음을 제공합니다:

- 이벤트·엣지 수집(ingest) 및 조회 엔드포인트
- 증적 그래프 질의
- 해시 체인 검증
- 내보내기 번들 미리보기
- 브라우저 Workbench UI
- `/mcp` 경로의 MCP JSON-RPC 엔드포인트

MCP 읽기 도구는 기본으로 활성화됩니다. `veritio.record_event` 등 쓰기 도구는
CLI를 `--allow-write-tools` 옵션으로 시작할 때만 노출됩니다.

## 더 알아보기 (영어 문서)

프로토콜 불변식, 패키지 맵, 스토리지 헬퍼, 예제, 검증 절차 등 나머지 내용은 영어
문서를 참조해 주세요:

- [프로토콜 불변식과 스키마](README.md#protocol-invariants) — 정규화 JSON·해시
  규칙, `spec/` 스키마, 적합성 픽스처
- [패키지 맵](README.md#package-map) — 공개/비공개 패키지 전체 목록
- [스토리지](README.md#storage) — Postgres/Neon/MySQL/MariaDB/MongoDB 등 호스트
  주입 스토리지 헬퍼
- [예제](README.md#examples) — 프레임워크별 실행 가능한 예제
- [저장소 구조와 검증](README.md#repository-layout)
- [docs/architecture.md](docs/architecture.md) — 아키텍처 문서

## 번역 안내

이 한국어 문서는 저장소와 함께 관리되지만 영어 문서보다 늦게 갱신될 수 있습니다.
오역 제보와 개선 PR을 환영합니다. 다른 언어(中文, 日本語 등) 번역 기여도
환영합니다 — [CONTRIBUTING.md](CONTRIBUTING.md)를 참조해 주세요.

## 라이선스

Apache-2.0.
