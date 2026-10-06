# CLI 규격

구성이 최상위 작업 구조와 1:1 이다.

```
cert-gen [-c CONFIG] [--data-dir DIR] [--json] [-q] <command> ...
```

| 전역 옵션 | 설명 |
|---|---|
| `-c, --config` | 설정 TOML 경로 |
| `--data-dir` | 상태 디렉터리. 설정·환경변수보다 우선 |
| `--json` | 결과를 JSON 으로 (스크립트 조합용) |
| `-q, --quiet` | 사람용 출력 생략. 결과 값만 |

## 명령

### 준비

| 명령 | 설명 |
|---|---|
| `init` | `data_dir` 구조·DB 생성. 이미 있는 디렉터리의 권한도 0750 으로 조인다. 멱등 |
| `doctor` | 설정·권한·SQLite·openssl·keytool·만료 임박 점검. 필수 항목 실패 시 종료코드 1 |

### 0. 개인키 — `key`

키 생성과 발급의 수명이 다르다. 미리 만들어 두고 CA·인증서에서 골라 쓸 수 있다.

| 명령 | 주요 옵션 |
|---|---|
| `key create` | `--name --algo --note --passphrase-stdin -o` — **기본은 패스프레이즈 없음** |
| `key import` | `file`(필수) `--name --note --no-copy --passphrase-stdin` |
| `key list` | — 쌍 토큰·짝 인증서·사용처를 함께 표시 |
| `key show` | `ref` `--public` — 짝 인증서 목록 포함 |
| `key export` | `ref` `-o` |
| `key strip` | `ref` `--yes --passphrase-stdin` — 패스프레이즈 제거 |
| `key passphrase` | `ref` — 걸거나 바꾸기(대화형) |
| `key delete` | `ref` `--force --yes` — 쓰이고 있으면 거부 |

### 1. rootCA 생성·관리 — `ca`

| 명령 | 주요 옵션 |
|---|---|
| `ca create` | `--cn`(필수) `--o --ou --c --st --l --email` `--slug` `--key-algo` `--days` `--passphrase-stdin` `--no-passphrase` `--key NAME \| --key-file FILE` |
| `ca adopt` | `--dir`(필수) `--ca-key --ca-cert --slug` — 복사 없이 외부 CA 등록 |
| `ca import` | `--key --cert`(필수) `--chain --slug --passphrase-stdin` — `data_dir` 로 복사 |
| `ca list` | — |
| `ca show` | `ref` `--pem` |
| `ca export` | `ref` `-o` — 신뢰 배포용 `ca.crt`(+`chain.pem`) |
| `ca trust` | `ref` `--apply --remove --os --java --sudo --yes` — 현재 서버의 OS·Java 신뢰 저장소에 등록. **기본은 조회 + 등가 명령 출력** |

### 2. 인증서 발급 — `cert issue`

```
cert-gen cert issue (--ca SLUG | --ca-dir DIR) --cn HOST [옵션]
```

| 옵션 | 설명 |
|---|---|
| `--ca SLUG` | cert_gen 이력의 CA |
| `--ca-dir DIR` | rootCA 가 있는 디렉터리. 개인키를 복사하지 않는다 |
| `--ca-key / --ca-cert` | `--ca-dir` 안에서 파일을 직접 지정(후보가 모호할 때) |
| `--cn` | 호스트명. **자동으로 SAN 에도 들어간다** |
| `--san` | 반복 지정. 타입 자동 판별, `dns:`/`ip:`/`uri:`/`email:` 로 명시 가능 |
| `--profile` | `server`(기본) / `client` / `server+client` |
| `--key NAME` | 등록된 키를 쓴다(즉석 생성하지 않는다). `--key-file FILE` 로 파일 직접 지정 |
| `--key-algo` | 새로 생성할 때의 알고리즘. `rsa2048`(기본) `rsa3072` `rsa4096` `ec-p256` `ec-p384` `ed25519` |
| `--days` | 기본 397. `[cert].max_days` 상한 |
| `--note` | 이력에 남는 메모 |
| `-o` | 번들을 이 디렉터리에도 풀어 놓는다 |

### 3. 인증서 변환 — `export`

대상은 **발급 이력(`ref`)** 또는 **외부 파일(`--cert`/`--key`/`--ca-file`)**.

| 명령 | 주요 옵션 |
|---|---|
| `export p12` | `--alias` `--password-stdin` `-o` |
| `export jks` | `--alias` `--password-stdin` `-o` — keytool 필요, 비밀번호 6자 이상 |
| `export der` | `-o` |
| `export pem` | `-o`(디렉터리) |
| `export k8s` | `--secret-name`(필수) `--namespace \| --namespace-token` `--with-ca` `--ingress-host` `--ingress-service NAME:PORT` `-o` |

### 4. 이력·만료 조회와 수명 관리 — `cert`

| 명령 | 주요 옵션 |
|---|---|
| `cert list` | `--ca` `--status valid\|revoked\|superseded` `--search` `--expiring-in DAYS` `--limit` `--key NAME` |
| `cert show` | `ref` `--pem` `--text` |
| `cert verify` | `ref` `--hostname` |
| `cert bundle` | `ref` `-o` |
| `cert renew` | `ref` `--days` `--key-algo` `--key NAME` `-o` — 기본은 새 키, `--key` 로 같은 키 유지. 이전 건은 `superseded` |
| `cert revoke` | `ref` `--reason` `--yes` |

`ref` 는 **id, serial(콜론 표기 포함), CN** 중 아무것이나 받는다. CN 이 중복이면 가장 최근 것.

### 그 외

| 명령 | 설명 |
|---|---|
| `csr create` | 외부 CA 제출용 CSR + 개인키 생성 |
| `csr sign` | 받은 CSR 을 우리 CA 로 서명. `--san` 으로 SAN 교체 가능. **확장은 CA 프로필로 덮어쓴다** |
| `crl generate` | CA 의 CRL 생성 |
| `crl list` | 폐기된 인증서 목록 |
| `backup create` | 백업 생성 (CA 개인키 포함, 0600) |
| `backup restore` | `--dry-run`(무결성 검사 포함) `--yes` |
| `tui` | 터미널 UI |

## 비밀값 전달

명령행 인자로 받는 옵션이 **없다**(`/proc/<pid>/cmdline` 으로 같은 호스트의 다른 사용자에게
노출된다).

| 용도 | 환경변수 | stdin |
|---|---|---|
| CA 패스프레이즈 | `CERT_GEN_CA_PASSPHRASE` | `--passphrase-stdin` |
| 개인키 패스프레이즈(`--key`/`--key-file`/`key strip`) | `CERT_GEN_KEY_PASSPHRASE` | `--key-passphrase-stdin` / `--passphrase-stdin` |
| 키스토어 비밀번호(p12/jks) | `CERT_GEN_STORE_PASSWORD` | `--password-stdin` |

우선순위: 환경변수 > stdin 플래그 > 대화형 프롬프트. 비대화형인데 아무것도 없으면
"무엇을 쓰면 되는지" 를 알려주는 오류로 끝낸다.

## 종료코드

`errors.py` 의 계층이 그대로 매핑된다.

| 코드 | 의미 | 예외 |
|---|---|---|
| 0 | 성공 | |
| 1 | 일반 오류 | `CertGenError` |
| 2 | 입력 검증 실패 | `ValidationError` |
| 4 | 대상 없음 | `NotFoundError` |
| 5 | 중복(slug·지문) | `ConflictError` |
| 6 | 검증 실패 | `VerificationError` / `cert verify` 실패 |
| 69 | 외부 도구 없음 / TUI 불가 | `ToolMissingError` |
| 74 | 상태·IO·번들·백업 문제 | `StateError` `BundleError` `BackupError` |
| 77 | CA 키를 열 수 없음(패스프레이즈) | `CaKeyUnlockError` |
| 78 | 설정 오류 | `ConfigError` |
| 130 | 사용자 중단(Ctrl-C) | |

스크립트에서 "패스프레이즈 문제" 와 "설정 문제" 를 구분할 수 있게 77/78 을 나눴다.

## 5. 현재 서버에 CA 신뢰 등록 — `ca trust`

```bash
cert-gen ca trust hd-root-ca                     # 조회만 (변경 없음) + 등가 명령
sudo cert-gen ca trust hd-root-ca --apply        # 등록
cert-gen ca trust hd-root-ca --apply --sudo      # 각 명령을 sudo -n 으로 실행
cert-gen ca trust hd-root-ca --apply --remove    # 해제
```

탐지 대상:

| 종류 | 경로 | 갱신 |
|---|---|---|
| RHEL/Rocky/Alma/Fedora | `/etc/pki/ca-trust/source/anchors` | `update-ca-trust extract` |
| Debian/Ubuntu | `/usr/local/share/ca-certificates` | `update-ca-certificates` |
| SUSE | `/etc/pki/trust/anchors` | `update-ca-certificates` |
| Alpine | `/usr/local/share/ca-certificates` | `update-ca-certificates` |
| Java | `$JAVA_HOME/lib/security/cacerts`, keytool 실제 경로, `/usr/lib/jvm/*` | keytool 이 즉시 반영 |

앵커 파일명·keytool alias 는 `cert-gen-<ca-slug>` 다(다른 CA 와 섞이지 않게).

**등가 명령을 항상 출력한다.** 이 작업은 root 가 필요하고 실제로는 cert_gen 이 돌지 않는 다른
호스트에 등록해야 하는 경우가 더 많다. 더해서 OS·Java 신뢰 저장소를 **보지 않는** 런타임의
지정법도 함께 보여준다(`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `curl --cacert`,
`git http.sslCAInfo`).

## 패스프레이즈를 묻지 않게 만드는 조합

서버를 무인 재시작해야 하는 환경에서는 다음 조합을 쓴다.

```bash
# 1) CA 를 패스프레이즈 없이 만든다 → 이후 발급에 프롬프트가 없다
cert-gen ca create --cn "hd Root CA" --no-passphrase

# 2) 서버 키는 기본적으로 패스프레이즈가 없다(별도 조치 불필요)
cert-gen cert issue --ca hd-root-ca --cn web.example.com -o /etc/nginx/tls

# 3) 이미 패스프레이즈가 걸린 키가 있다면 제거한다
cert-gen key strip web-key --yes
```

보호는 파일 권한(0600)과 호스트 접근 통제가 담당한다. `data_dir` 가 0750 이고 전용 계정
소유인지 `cert-gen doctor` 로 확인한다.

## 스크립트 예시

만료 임박 인증서를 자동 갱신:

```bash
#!/usr/bin/env bash
set -euo pipefail
export CERT_GEN_CA_PASSPHRASE="$(cat /run/secrets/ca-passphrase)"

cert-gen --json cert list --expiring-in 30 --status valid \
  | jq -r '.[].id' \
  | while read -r id; do
      echo "갱신: #${id}"
      cert-gen cert renew "${id}" -o "/etc/nginx/tls/${id}"
    done
```
