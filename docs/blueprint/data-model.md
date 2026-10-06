# 데이터 모델

## 저장 위치

```
/var/lib/cert-gen/            0750  certgen:certgen
├── cert-gen.sqlite3          0640  발급 이력·serial·감사 로그 (단일 출처)
├── ca/<slug>/
│   ├── ca.key                0600  cert_gen 이 소유한 CA 개인키 (기본 암호화 PKCS#8)
│   ├── ca.crt                0644
│   └── chain.pem             0644  가져온 CA 가 중간 CA 인 경우
├── bundles/<YYYY>/<id>-<cn>-<serial8>.zip   0600  발급 결과 (개인키 포함)
├── crl/<slug>.crl            0644
├── backups/*.tar.gz          0600  CA 개인키 포함 — 파일 하나가 CA 그 자체
└── tmp/                            원자적 쓰기용 (같은 파일시스템이어야 os.replace 성립)
```

**외부 CA(`is_external=1`)의 개인키는 이 트리에 없다.** `ca.key_path` 가 절대경로로
원래 위치를 가리킨다.

## 스키마 (SQLite)

`PRAGMA journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=10000`, `synchronous=FULL`.

> `RETURNING`(3.35+)·`STRICT`(3.37+) 같은 신문법은 쓰지 않는다. Rocky Linux 9 의 SQLite 가
> **3.34.1** 이라 대상 OS 에서 syntax error 가 난다.

```mermaid
erDiagram
    ca ||--o{ certificate : "발급"
    ca ||--o{ ca : "parent_id (미사용)"
    certificate ||--o| certificate : "renewed_from"

    ca {
        INTEGER id PK
        TEXT slug UK "파일시스템·CLI 식별자"
        INTEGER parent_id FK "NULL=Root"
        TEXT common_name
        TEXT subject_dn "RFC4514"
        TEXT key_algo "rsa2048|ec-p384|..."
        INTEGER key_encrypted
        INTEGER is_external "1=개인키를 복사하지 않음"
        TEXT source_dir "외부 CA 의 원본 디렉터리"
        TEXT key_path "내부=상대, 외부=절대"
        TEXT cert_path
        TEXT chain_path
        TEXT serial_hex
        TEXT fingerprint_sha256 UK "중복 등록 차단"
        TEXT not_before
        TEXT not_after
        INTEGER path_len
        INTEGER next_seq "사람이 읽을 순번 카운터"
        INTEGER crl_number
        TEXT status "active|retired"
        TEXT created_at
    }

    certificate {
        INTEGER id PK
        INTEGER ca_id FK
        INTEGER seq "CA 내 발급 순번"
        TEXT serial_hex "UK(ca_id,serial_hex)"
        TEXT common_name
        TEXT subject_dn
        TEXT sans_json
        TEXT profile "server|client|server+client"
        TEXT key_algo
        TEXT not_before
        TEXT not_after
        TEXT fingerprint_sha256
        TEXT bundle_path "data_dir 기준"
        TEXT bundle_sha256 "번들 무결성"
        INTEGER has_private_key "CSR 서명 건은 0"
        TEXT source "generated|csr"
        TEXT status "valid|revoked|superseded"
        TEXT revoked_at
        TEXT revoke_reason
        INTEGER renewed_from FK
        TEXT note
        TEXT created_at
    }

    audit {
        INTEGER id PK
        TEXT at
        TEXT frontend "cli|tui|web"
        TEXT os_user
        TEXT action
        TEXT target
        TEXT detail_json
        INTEGER ok
    }
```

인덱스: `certificate(common_name)`, `certificate(not_after)`, `certificate(ca_id, status)`,
`audit(at)`.

### 상태 전이

```mermaid
stateDiagram-v2
    [*] --> valid : cert issue / csr sign
    valid --> superseded : cert renew (새 건이 생기면 이전 건)
    valid --> revoked : cert revoke
    superseded --> revoked : cert revoke
    revoked --> [*] : (되돌릴 수 없음)
```

`superseded` 와 `revoked` 를 구분하는 이유: 갱신은 정상 운영이고 폐기는 사고 대응이다.
CRL 에는 `revoked` 만 들어간다.

## serial 과 순번

둘을 분리한다.

| | 값 | 생성 | 용도 |
|---|---|---|---|
| `serial_hex` | 160비트 난수 | `x509.random_serial_number()` | 인증서의 실제 serial. RFC 5280 요구(양수·20옥텟 이하·충분한 엔트로피)를 라이브러리가 보장 |
| `seq` | CA 별 1,2,3… | `BEGIN IMMEDIATE` 안에서 SELECT→UPDATE | "세 번째로 발급한 것" 을 사람이 알 수 있게 |

난수 serial 만으로는 발급 순서를 알 수 없고, 순번만으로는 예측 가능해서 안 된다.

## 발급 트랜잭션 순서

긴 CPU 작업(키 생성·서명)을 트랜잭션 밖으로 빼고, DB 커밋을 파일 쓰기보다 앞세운다.

```mermaid
sequenceDiagram
    participant F as 프런트엔드
    participant S as service
    participant DB as SQLite
    participant FS as 파일시스템

    F->>S: cert_issue(selection, passphrase, ...)
    S->>FS: CA 개인키 읽기 + 패스프레이즈 해제
    S->>S: 키-인증서 짝 검증
    rect rgb(240, 240, 240)
    note right of DB: 짧은 쓰기 트랜잭션
    S->>DB: BEGIN IMMEDIATE
    S->>DB: seq 할당 (SELECT→UPDATE)
    S->>DB: COMMIT
    end
    note right of S: 트랜잭션 밖 — RSA-4096 생성에 수 초가<br/>걸리는데 락을 잡고 있으면 동시 발급이 막힌다
    S->>S: 키 생성
    S->>S: serial 생성 + 인증서 서명
    rect rgb(240, 240, 240)
    note right of DB: 짧은 쓰기 트랜잭션
    S->>DB: BEGIN IMMEDIATE
    S->>DB: INSERT certificate (bundle_path 는 비움)
    S->>DB: COMMIT
    end
    S->>FS: 번들 zip 쓰기 (tmp → os.replace)
    alt 쓰기 성공
        S->>DB: UPDATE bundle_path, bundle_sha256
        S->>DB: INSERT audit
        S-->>F: IssueResult
    else 쓰기 실패
        S->>DB: DELETE certificate (보상 트랜잭션)
        S-->>F: 예외
    end
```

순서를 뒤집으면 어떻게 되는가:

- 번들을 먼저 쓰고 INSERT 하면 → 실패 시 **DB 에 없는 고아 zip** 이 남는다(추적 불가).
- 지금 순서에서 최악은 "행은 있는데 zip 이 없다" 이고, 그건 `cert show` 가 명확히 알려준다.

## CA 선택 2경로

```mermaid
flowchart TD
    A[인증서 발급 요청] --> B{CA 를 어떻게 지정했나}
    B -->|--ca SLUG| C[DB 에서 CA 조회]
    B -->|--ca-dir DIR| D[discover_in_dir]
    B -->|둘 다 없음| E{등록된 CA 가}
    E -->|0개| F["오류 + 1번 안내<br/>cert-gen ca create ..."]
    E -->|1개| C
    E -->|2개 이상| G["오류 + 목록<br/>--ca 로 선택하세요"]

    D --> D1{관례명 ca.key/ca.crt}
    D1 -->|있음| D3[CA:TRUE 확인]
    D1 -->|없음| D2[글로브 후보 수집]
    D2 --> D2a{CA 인증서 후보}
    D2a -->|0개| DX["오류: 찾을 수 없음<br/>--ca-cert 로 지정"]
    D2a -->|2개 이상| DY["오류: 후보 여러 개<br/>추측하지 않는다"]
    D2a -->|1개| D3
    D3 --> D4{지문이 DB 에 있나}
    D4 -->|있음| D5["기존 행 재사용<br/>경로 바뀌면 source_dir 갱신"]
    D4 -->|없음| D6["adopt: is_external=1 로 등록<br/>개인키는 복사하지 않는다"]

    C --> H[CaSelection]
    D5 --> H
    D6 --> H
    H --> I{needs_passphrase}
    I -->|예| J[프런트엔드가 패스프레이즈 입력]
    I -->|아니오| K[load_material]
    J --> K
    K --> L["키-인증서 짝 검증<br/>(암호화 키는 여기서만 가능)"]
    L --> M[발급]
```

암호화된 외부 키는 `discover` 단계에서 공개키를 대조할 수 없다(복호화가 필요하다).
그래서 짝 검증을 `load_material` 로 미뤘다 — 잘못 짝지어진 경우 여기서 반드시 걸린다.
