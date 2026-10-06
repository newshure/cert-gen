# 구현 계획과 진행

## 범위

| 항목 | 결정 |
|---|---|
| 발급 | 로컬 Root CA → leaf (**1단계, Intermediate 생성 제외**), 프로필 server/client/server+client |
| 실행 형태 | **설치 과정 없는 단일 정적 바이너리.** vanilla 실행 + 컨테이너 병행 |
| 대상 OS | RHEL 8·9·10, Debian 12·13, Ubuntu 22·24, Windows (교차 컴파일) |
| 프런트엔드 | **CLI(정본) + TUI(Bubble Tea)** |
| 인증 | 없음(한시적 사용). CA 키 패스프레이즈가 통제 수단 |
| 상태 | SQLite(이력·serial) + zip 번들(키·인증서) + 백업/복원. 실행한 디렉터리의 `cert-gen-data/` |
| 출력 | PEM 기본, PKCS#12/JKS/DER/K8s tls Secret 변환. `.cnf` 입력(apply) |

## 구성 (internal 패키지)

```
cli (flag)              tui (Bubble Tea)
   └────────────┴────────────┘  둘 다 코어를 직접 부르되 같은 일을 같은 순서로
                ▼
  store · ca · issue · csr · crl · export · manifests · bundle · backup ·
  verify · keymgmt · trust · keys · names · profiles · certbuild · osslconf ·
  config · fsops · certerr
```

모듈별 What/Why/How 는 `docs/codes.md`, 메뉴 흐름은 `docs/blueprint/menu-flows.md`,
CLI 규격은 `docs/blueprint/cli-spec.md`, TUI 는 `docs/blueprint/tui-flow.md`.

## 설계를 지배하는 제약

1. **설치 과정이 없어야 한다** → `CGO_ENABLED=0` 정적 링크. C 의존이 하나라도 있으면 glibc
   버전에 묶여 RHEL 8 과 Debian 13 을 한 바이너리로 못 덮는다. SQLite 는 순수 Go 구현
   (`modernc.org/sqlite`). Windows 교차 컴파일도 이 제약에서 나온다.
2. **앱 인증이 없다** → CA 키 패스프레이즈가 사실상 유일한 서명 권한 통제다. 기본값을
   암호화로 두고 패스프레이즈를 argv 로 받지 않는다.
3. **상태 위치 규칙은 하나여야 한다** → `--data-dir` → `CERT_GEN_DATA_DIR` →
   `<현재 디렉터리>/cert-gen-data`. 위로 찾아 올라가지 않는다.
4. **확장은 프로필이 통제한다** → CSR·`.cnf` 가 보낸 keyUsage/EKU/basicConstraints 를 그대로
   믿지 않는다. DN·SAN 만 데이터로 쓰고 확장은 프로필로 새로 만든다.
5. **외부 도구는 선택이다** → PKCS#12·JKS·CRL 을 직접 쓰므로 keytool·JDK 가 필요 없다.
   openssl 은 교차 검증에만 쓰고 없어도 발급·변환은 동작한다.

## 배포

**단일 정적 바이너리.** `deploy/build.sh` 가 linux/amd64 와 windows/amd64 바이너리와
`SHA256SUMS` 를 만든다. 재현 가능(`-trimpath -buildid=`)하고 깨끗한 트리를 요구한다 —
Go 가 바이너리에 git 커밋을 새기므로, 더러운 트리면 `vcs.modified=true` 가 찍혀 출처를
답할 수 없다.

Windows 바이너리는 백신 오탐을 줄이기 위해 버전 리소스(VERSIONINFO)를 넣고 심볼을 남긴다.
`.rsrc` 가 없는 맨 PE 와 스트립된 바이너리는 둘 다 휴리스틱 점수를 올린다. `SIGN_PFX` 로
Authenticode 서명을 지원한다. 자세한 내용은 `docs/manual/antivirus.md`.

컨테이너는 바이너리 하나를 `COPY` 하는 것이 전부이고 빌드 중 네트워크를 쓰지 않는다
(`deploy/container/`). 상태 디렉터리를 볼륨으로 둔다 — 없으면 컨테이너가 사라질 때 CA
개인키도 사라진다.

### 빌드 스크립트에서 잡은 셸 함정 두 개

둘 다 `set -euo pipefail` 과 겹쳐 **조용히** 죽는다.

| 금지 패턴 | 왜 | 대신 |
|---|---|---|
| `grep -q P f && die ...` | 패턴이 없는 정상 경우에 grep 이 1 을 반환해 복합 명령이 실패하고 `set -e` 가 종료시킨다 | `if grep -q P f; then die; fi` |
| `cmd \| head -1` | cmd 가 쓰는 동안 head 가 먼저 닫아 SIGPIPE(141). `pipefail` 이 실패로 본다. 레이스라 간헐적 | 입력을 끝까지 읽는 `awk 'NR==1{...}'` |

## 키-인증서 쌍 표현

공개키(SubjectPublicKeyInfo DER) SHA256 의 **앞 8자를 쌍 토큰**으로 키와 인증서 양쪽에
같게 표시한다. 목록에서 토큰이 같으면 같은 개인키라는 것을 눈으로 알 수 있다.

```
key list :  web-key  rsa2048  평문  808cfb83  인증서 2
cert list:  3  web.example.com  ...  808cfb83
            2  api.example.com  ...  9616b4b7  (즉석 생성)
```

`cert list --ca <식별자>` 로 CA 별로, `key show <이름>` 으로 키 → 짝 인증서(사용처)를 본다.

## 보안 전제 (문서·출력에 반복해 명시)

1. 앱 인증이 없다 → **CA 키 패스프레이즈가 사실상 유일한 서명 권한 통제**다.
   `[ca].encrypt_key = false` 로 두면 상태 디렉터리 읽기 권한자가 곧 CA 다.
2. 비밀값을 argv 로 받지 않는다(`/proc/<pid>/cmdline` 노출). 환경변수·stdin·프롬프트만.
3. **백업 파일 하나가 CA 그 자체다.** 0600, 외부 이동 시 별도 암호화.
4. K8s Secret 의 `tls.key` 는 base64 인코딩일 뿐 암호화가 아니다. 저장소에 커밋하지 않는다.
5. 외부 CA 의 개인키는 복사하지 않고 백업에도 담지 않는다 — 약속을 어느 경로에서도 깨지 않는다.
6. 자가서명 체인은 클라이언트에 `ca.crt` 신뢰 등록이 전제다(`trust` 메뉴가 명령을 만든다).
7. 폐기는 cert-gen 안에서만 즉시 효력이 있다. 실제 차단은 CRL 배포가 필요하다(CDP 는 넣지
   않으므로 검증하는 쪽이 파일을 직접 받아 쓴다).
