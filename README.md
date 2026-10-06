# cert_gen

로컬 Root CA 를 보관하면서 서버·클라이언트 인증서를 발급하고, 발급 이력을 추적하고,
필요한 포맷으로 변환하는 **독립 실행형** 도구. CLI 와 터미널 UI 를 제공한다.

폐쇄망에서 `openssl` 명령을 손으로 조합하던 작업을 대체한다.

- SAN·확장(keyUsage/EKU/basicConstraints)을 **프로필로 고정** → 손으로 쓰다 틀리는 일이 없다
- 발급 이력·serial·만료를 SQLite 로 추적 → "지금 뭐가 있고 언제 만료되나" 를 조회할 수 있다
- PEM / PKCS#12 / JKS / DER / Kubernetes `tls` Secret 으로 변환 → 변환 작업을 반복하지 않는다
- **이미 쓰고 있는 CA 를 그 자리에서 사용** → 개인키를 옮기지 않고 발급할 수 있다

# [사용 예제](https://wiki.theknowledges.net/ko/knowledge/security/certificate/cert-gen-man)

CA 용 private key 생성 -> CA cert 생성 -> Server/client용 private key 생성 -> Server/client용 cert 생성의 기본 작업 흐름에 대한 예제


## 작업 구조

```
0. 개인키 생성·관리    미리 만들어 두고 1·2 에서 골라 쓴다. 패스프레이즈 제거도 여기서
1. rootCA 생성        키 선택 → ① 등록된 키  ② 즉석 생성
2. 인증서 발급        CA 선택 → ① cert_gen 이력에서 고르기  ② rootCA 가 있는 디렉터리 입력
                      키 선택 → ① 등록된 키  ② 즉석 생성
3. 인증서 변환        대상  → ① 발급 이력에서 고르기        ② 외부 인증서 파일 지정
4. 발급 이력·만료 조회  목록 → 상세 / 검증 / 번들 추출 / 갱신 / 폐기 / CRL
5. 서버에 CA 신뢰 등록  OS 신뢰 저장소 + Java 트러스트스토어. 등가 명령도 함께 제공
```

### 패스프레이즈 정책

| 대상 | 기본 | 이유 |
|---|---|---|
| **서버에 올릴 키** (leaf) | **없음** | 걸면 nginx·Tomcat 이 **부팅할 때마다 패스워드를 묻는다.** 무인 재시작이 깨진다. 보호는 파일 권한(0600)과 호스트 접근 통제가 담당한다 |
| **CA 키** | 있음 | 서명할 때만 쓰이고 상시 로드되지 않는다. 앱 인증이 없으므로 이것이 사실상 유일한 서명 권한 통제다 |

둘 다 강제가 아니다. CA 도 `--no-passphrase` 로 패스프레이즈 없이 만들 수 있고(그 CA 로는
발급 시 프롬프트가 없다), 이미 걸려 있는 패스프레이즈는 `cert-gen key strip` 으로 제거할 수 있다.

## 요구 사항

| 항목 | 내용 |
|---|---|
| OS | RHEL 계열 8·9·10, Debian 12·13, Ubuntu 22·24, Windows 10/11·Server 2019+ |
| 런타임 | **없음.** 정적 링크 단일 실행 파일이라 glibc 의존도 없다 |
| 선택 | `openssl` (교차 검증용) |

`openssl` 이 없으면 **교차 검증 항목만** 건너뛴다. 발급·변환·검증은 모두 자체 구현이다.
PKCS#12·JKS·CRL 도 직접 만들므로 **JDK 나 keytool 이 필요하지 않다.**

## 설치

설치 과정이 없다. 바이너리 하나를 받아서 실행한다.

```bash
chmod +x cert-gen
./cert-gen where      # 상태 디렉터리가 어디에 생기는지 확인
./cert-gen init
```

상태는 **실행한 디렉터리**의 `cert-gen-data/` 에 생긴다. Windows 와 리눅스가 같다.
위치를 정하는 규칙은 세 가지뿐이다(위에서부터 우선).

```
1. cert-gen --data-dir <경로> <명령>
2. 환경변수 CERT_GEN_DATA_DIR
3. <현재 디렉터리>/cert-gen-data        ← 기본값
```

찾아 올라가지 않는다. 규칙이 하나뿐이어야 "어디에 생기는지" 가 분명하다.

### 직접 빌드

```bash
bash deploy/build.sh                 # dist/cert-gen + dist/cert-gen.exe + SHA256SUMS
VERSION=0.2.0 bash deploy/build.sh   # 버전 지정
```

재현 가능한 빌드다(`-trimpath -buildid=`). 바이너리에 git 커밋이 새겨지므로 출처를
확인할 수 있다.

```bash
go version -m cert-gen     # vcs.revision 과 vcs.modified=false 를 본다
```

Windows 바이너리는 백신 오탐을 줄이기 위해 버전 리소스를 넣고 심볼을 남긴다.
자세한 내용과 코드 서명은 `docs/manual/antivirus.md`.

### 컨테이너

설치가 필요 없으므로 컨테이너는 필수가 아니다. 클러스터 안에서 Job 으로 발급하거나
호스트에 바이너리를 두지 않는 정책이 있을 때만 쓴다.

```bash
bash deploy/container/build.sh
```

상태 디렉터리를 볼륨으로 두어야 한다. 그러지 않으면 컨테이너가 사라질 때 **CA 개인키도
사라진다.** 자세한 내용: `deploy/container/README.md`

## 사용

### 0. 개인키 미리 만들기 (선택)

키 생성과 인증서 발급의 수명은 다르다. 같은 키로 여러 번 갱신해야 하는 경우(장비가 키 교체를
받지 못하는 경우)나, 키를 먼저 만들어 검토한 뒤 발급만 따로 하는 경우가 있다.

```bash
cert-gen key create --name web-key --algo rsa2048     # 패스프레이즈 없음(기본)
cert-gen key create --name ca-key --algo ec-p384 --passphrase-stdin
cert-gen key import /path/to/existing.key --name legacy
cert-gen key list                                      # 어느 인증서의 짝인지 함께 표시
cert-gen key strip ca-key                              # 패스프레이즈 제거
cert-gen key show web-key                              # 짝 인증서 목록
cert-gen key delete old-key                            # 쓰이고 있으면 거부
```

TUI 에서는 `0. 개인키 생성·관리` 화면에서 같은 일을 한다(생성·가져오기·상세·암호해제·
내보내기·삭제).

**키-인증서 쌍 보기** — 공개키 지문 앞 8자가 `쌍 토큰` 으로 양쪽에 같게 표시된다.

```
$ cert-gen key list
  NAME     알고리즘  보호  쌍 토큰   짝 인증서  출처       사용처
  web-key  rsa2048   없음  808cfb83  2          generated  cert#1 web.example.com, cert#3 web.example.com

$ cert-gen cert list
  ID  CN               CA          용도    알고리즘  키 [쌍]           ...
  3   web.example.com  hd-root-ca  server  rsa2048   web-key 808cfb83  ...
  2   api.example.com  hd-root-ca  server  rsa2048   (즉석) 9616b4b7   ...
```

`cert-gen cert list --key web-key` 로 그 키를 쓰는 인증서만 볼 수 있다.

### 1. rootCA 생성

```bash
cert-gen ca create --cn "hd Root CA" --o HD --c KR            # 키 즉석 생성
cert-gen ca create --cn "hd Root CA" --key ca-key             # 등록된 키 사용
cert-gen ca create --cn "hd Root CA" --no-passphrase          # 패스프레이즈 없이
```

개인키는 패스프레이즈로 암호화된다(기본값). 앱 자체에 인증이 없으므로
**이 패스프레이즈가 사실상 유일한 서명 권한 통제**다.

등록된 키(`--key`)로 만들면 **그 키 파일을 복사하지 않고 참조한다.** 그래서
`key strip` 으로 패스프레이즈를 제거하면 그 CA 에도 즉시 반영된다(상태가 갈라지지 않는다).

### 2. 인증서 발급

```bash
# 이력에 있는 CA 로
cert-gen cert issue --ca hd-root-ca --cn web.example.com \
  --san 10.0.0.5 --san '*.web.example.com'

# 이미 쓰고 있는 CA 로 (개인키를 복사하지 않는다)
cert-gen cert issue --ca-dir /srv/pki/mycorp --cn api.example.com

# 미리 만들어 둔 키로
cert-gen cert issue --ca hd-root-ca --key web-key --cn web.example.com
```

발급되는 개인키에는 **패스프레이즈를 걸지 않는다**(서버가 부팅할 때 패스워드를 묻지 않게).

CN 은 자동으로 SAN 에도 들어간다. `--san` 의 타입(DNS/IP/URI/email)은 값에서 자동 판별된다.
용도는 `--profile server|client|server+client` 로 고른다(기본 `server`).

결과는 zip 번들로 보관되고, 파일로 꺼낼 때는:

```bash
cert-gen cert bundle 1 -o /etc/nginx/tls
# privkey.pem  cert.pem  fullchain.pem  ca.crt  metadata.json  USAGE.txt
```

`USAGE.txt` 에 OS 별 신뢰 등록 절차와 nginx / Nginx Proxy Manager / K8s / Java 적용 예가 들어 있다.

### 3. 인증서 변환

```bash
cert-gen export p12 1 -o web.p12                 # PKCS#12 (Java·Windows)
cert-gen export jks 1 -o web.jks                 # JKS (레거시, keytool 필요)
cert-gen export der 1 -o web.der                 # DER (Windows 가져오기)
cert-gen export pem 1 -o ./pem                   # PEM 세트
cert-gen export k8s 1 --secret-name web-tls --namespace production --with-ca \
  --ingress-host web.example.com --ingress-service web:8080 -o web-tls.yaml

# 이력에 없는 외부 인증서도 변환할 수 있다
cert-gen export p12 --cert cert.pem --key privkey.pem --ca-file ca.crt -o out.p12
```

### 5. 현재 서버에 CA 신뢰 등록

자가서명 체인은 접속하는 쪽이 CA 를 신뢰해야 동작한다. OS 신뢰 저장소와 Java 트러스트스토어
(cacerts)를 찾아 상태를 보여주고, 등록·해제한다.

```bash
cert-gen ca trust hd-root-ca                  # 조회 + 등가 명령 출력 (변경 없음)
sudo cert-gen ca trust hd-root-ca --apply     # 실제 등록
cert-gen ca trust hd-root-ca --apply --sudo   # sudo -n 으로 각 명령 실행
cert-gen ca trust hd-root-ca --apply --remove # 해제
cert-gen ca trust hd-root-ca --java           # Java 트러스트스토어만
```

```
  종류  대상                                  경로                              쓰기             상태
  os    Debian 계열 (update-ca-certificates)  /usr/local/share/ca-certificates  불가(root 필요)  등록되지 않음
  java  Java 트러스트스토어 (temurin-21)      .../lib/security/cacerts          불가(root 필요)  등록되지 않음

등가 명령 (다른 호스트에 등록할 때 그대로 복사해 쓰세요):
  # Debian 계열 (update-ca-certificates) — 등록
  sudo install -m 0644 .../ca.crt /usr/local/share/ca-certificates/cert-gen-hd-root-ca.crt
  sudo update-ca-certificates
  # Java 트러스트스토어 — 등록
  sudo keytool -importcert -trustcacerts -noprompt -alias cert-gen-hd-root-ca \
    -file .../ca.crt -keystore .../cacerts -storepass changeit
```

**명령 문자열을 항상 함께 주는 이유**: 이 작업은 root 권한이 필요하고, 실제로는 cert_gen 이
돌지 않는 다른 호스트에 등록해야 하는 경우가 더 많다. 그대로 복사해 갈 수 있어야 한다.

OS·Java 신뢰 저장소를 보지 않는 런타임(curl, Node.js, git, Python requests)의 지정 방법도
함께 출력한다. 지원 계열: RHEL/Rocky, Debian/Ubuntu, SUSE, Alpine.

### 4. 발급 이력·만료 조회

```bash
cert-gen cert list                      # 전체
cert-gen cert list --expiring-in 30     # 30일 내 만료
cert-gen cert list --search 10.0.0.5    # CN·SAN 부분 일치
cert-gen cert show 1 --text             # openssl x509 -text 형태
cert-gen cert verify 1 --hostname web.example.com
cert-gen cert renew 1                   # 새 키로 재발급, 이전 건은 superseded
cert-gen cert renew 1 --key web-key     # 같은 키를 유지하며 재발급
cert-gen cert revoke 1 --reason keyCompromise
cert-gen crl generate hd-root-ca        # 폐기를 실제로 적용하려면 CRL 을 배포해야 한다
```

모든 조회 명령에 `--json` 이 있어 스크립트로 조합할 수 있다.

### 터미널 UI

```bash
cert-gen tui
```

위 4개 작업을 화면으로 수행한다. 각 화면이 **등가 CLI 명령을 함께 표시**하므로
익힌 작업을 그대로 스크립트로 옮길 수 있다.

### 백업 / 복원

```bash
cert-gen backup create
cert-gen backup restore <파일> --dry-run   # 무엇이 바뀔지만 확인 (무결성 검사 포함)
cert-gen backup restore <파일>
```

**백업 파일은 CA 개인키를 포함한다. 즉 파일 하나가 CA 그 자체다.** 0600 으로 만들어지며,
외부로 옮길 때는 별도 암호화가 필요하다.

### 환경 점검

```bash
cert-gen doctor
```

설정·권한·SQLite·openssl·keytool·만료 임박 건수를 한 화면에 보여준다.

## 비대화형 실행 (스크립트·CI)

패스프레이즈는 **명령행 인자로 받지 않는다**(`/proc/<pid>/cmdline` 으로 노출된다).

```bash
export CERT_GEN_CA_PASSPHRASE='...'           # 또는
echo '...' | cert-gen ca create --passphrase-stdin --cn "..."
export CERT_GEN_STORE_PASSWORD='...'          # p12/jks 키스토어 비밀번호
```

## 설정

`/etc/cert-gen/config.toml` (예제: `deploy/config.example.toml`).
개별 값은 `CERT_GEN_<SECTION>_<KEY>` 환경변수로 덮어쓸 수 있다.
알 수 없는 키·섹션은 조용히 무시하지 않고 오류로 거부한다.

## 알아둘 것

- 자가서명 체인이므로 **접속하는 쪽에 `ca.crt` 를 신뢰 등록해야** 동작한다
  (`cert-gen ca export <slug>` 로 꺼내고, 번들의 `USAGE.txt` 에 OS 별 절차가 있다).
- 기본 유효기간 397일은 공인 CA 관례를 따른 값이며 사설 CA 에 강제되지 않는다.
  더 길게 쓰려면 `--days` 로 명시한다(경고가 뜬다).
- 중간 CA(Intermediate) 생성은 범위 밖이다(Root → leaf 1단계). 단 **외부 CA 가 중간 CA 인
  경우는 그 디렉터리의 `chain.pem` 을 읽어 그대로 체인에 넣는다.**
- 폐기는 cert_gen 안에서 즉시 반영되지만, **실제 차단에는 CRL 을 만들어 배포해야 한다.**

## 문서

| 문서 | 내용 |
|---|---|
| `docs/codes.md` | 모듈별 What / Why / How 색인 |
| `docs/references.md` | 외부 소스·라이선스 검증 기록, 채택하지 않은 것과 그 근거 |
| `docs/requests.md` | 요구사항과 이해·결정 기록 |
| `docs/manual/` | 설치, 빠른 시작, 포맷별 적용, 백업·복원 |
| `docs/blueprint/menu-flows.md` | **메뉴별 동작 흐름** — 입력·검사·변경·출력을 다이어그램으로. 코드를 보지 않고 동작을 파악할 때 |
| `docs/blueprint/` | 데이터 모델, CLI 규격, TUI 흐름 |

웹 UI 는 만들지 않는다(취소). CLI 가 정본이고 TUI 가 그 위의 편의 계층이다.

## 테스트

```bash
go test ./...                     # 전체 (openssl·keytool·kubectl 교차 검증 포함)
go test ./internal/tui/ -v        # TUI (모델을 직접 구동해 키 입력을 흉내낸다)
```

---

© HaeDong · https://theknowledges.net · 출처 명시 시 자유 사용
