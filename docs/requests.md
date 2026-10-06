# requests.md

Request / Understanding / Final. 사용자 요구와 그에 대한 이해·최종 결정을 남긴다.

---

## R-001 자가서명 인증서 생성기 (로컬 CA)

### Request

폐쇄망 Kubernetes 환경에서 TLS 인증서를 `openssl` 명령을 손으로 조합해 만들어 왔다.
그 반복을 없애는 독립 실행형 도구. 명령줄(CLI)과 터미널 UI(TUI) 제공.

### Understanding

핵심은 "openssl 명령 조합을 손으로 반복하는 일" 을 없애는 것이다. 세 가지 결함을 구조로 막는다.

1. **확장 설정 실수** — SAN / keyUsage / EKU / basicConstraints 를 매번 손으로 쓰면 틀린다.
   발급 프로필(`server`·`client`·`server+client`·`root-ca`)로 확장 세트를 한곳에 고정한다.
   CN 은 자동으로 SAN 에도 넣는다(CN-only 인증서는 현대 클라이언트가 거부).
2. **이력 부재** — 어떤 CA 로 무엇을 언제 발급했고 언제 만료되는지 추적이 안 된다.
   SQLite 에 CA·인증서·개인키·감사 로그를 남기고 만료 임박 조회를 1급 기능으로 둔다.
3. **포맷 변환 반복** — nginx / Nginx Proxy Manager / K8s Ingress / Java 가 각각 다른 포맷을
   요구한다. 발급 결과를 zip 번들로 보관하고 PEM·PKCS#12·JKS·DER·K8s Secret YAML 로 내보낸다.

앱 인증이 없다는 점이 설계를 지배한다. **CA 키 패스프레이즈가 사실상 유일한 서명 권한
통제**이므로 기본값을 암호화로 두고, 패스프레이즈는 argv 로 받지 않는다(프로세스 목록 노출).
백업 파일은 CA 개인키를 포함하므로 `0600` 이며 "백업 파일 = CA 그 자체" 를 문서에 명시한다.

CLI 가 정본이고 TUI 는 편의 계층이다. TUI 의 각 화면은 작업 후 '같은 일을 하는 CLI 명령' 을
보여 준다 — TUI 로 익힌 절차를 스크립트로 옮길 수 있어야 한다.

### Final

- **배포: 설치 과정 없는 단일 정적 바이너리.** `CGO_ENABLED=0` 로 glibc 의존조차 없앤다.
  RHEL 8·9·10, Debian 12·13, Ubuntu 22·24 를 한 바이너리로 덮고 Windows 는 교차 컴파일한다.
- 상태는 **실행한 디렉터리의 `cert-gen-data/`** 에 둔다(규칙 하나뿐: `--data-dir` →
  `CERT_GEN_DATA_DIR` → `<cwd>/cert-gen-data`, 위로 찾아 올라가지 않는다).
- X.509·CSR·CRL 은 Go 표준 `crypto/x509`. PKCS#12·JKS 는 라이브러리로 **직접 쓴다**
  (`keytool` 호출 없음). `openssl` 은 교차 검증에만 쓰고 없어도 동작한다.
- 검증은 외부 도구 교차 확인이 핵심이다 — `openssl verify`(+`-crl_check`),
  `keytool -list`, `kubectl apply --dry-run`, 실제 TLS 핸드셰이크.

---

## R-002 최상위 메뉴 구조 (사용자 지정)

### Request

CLI·TUI 의 최상위 흐름을 지정. 개인키 생성·관리 / rootCA 생성 / 인증서 발급(CA 선택:
이력 기반·외부 디렉터리) / 인증서 변환(대상: 발급 이력·외부 파일) / 발급 이력·만료 조회 /
서버에 CA 신뢰 등록.

### Understanding

- CA 선택을 "발급" 의 하위 단계로 둔 것은 맞다. CA 고르기는 그 자체가 목적이 아니라 발급의
  전제다.
- "이력 / 외부 디렉터리" 분기가 핵심이다. 자가서명 도구가 흔히 "CA 는 내가 소유한다" 를
  전제해 **이미 쓰고 있는 CA 로는 발급을 못 한다.** 이 분기로 그 함정을 피한다. 같은 대칭을
  변환(이력 / 외부 파일)에도 적용한다.
- 이력·만료 조회를 넣은 이유: 이력을 SQLite 로 관리하는데 그것을 **보는 입구**가 없으면
  요구가 반쪽이 된다. 실사용 빈도는 발급보다 "지금 뭐가 있고 언제 만료되나" 가 높다.
- 중간 CA(Intermediate)는 범위 밖(Root → leaf 1단계). 단, 외부 CA 가 중간 CA 면 그 디렉터리의
  `chain.pem` 을 읽어 체인에 넣는다(우리가 중간 CA 를 만들지는 않는다).

### Final

메뉴 0~6 과 번호를 고정했다: 0 개인키 관리 / 1 rootCA 생성 / 2 발급 / 3 변환 /
4 이력·만료 / 5 신뢰 등록 / 6 백업·복원. 단계별 흐름은 `docs/blueprint/menu-flows.md`.

---

## R-003 소프트웨어 서명과 백신 오탐

### Request

Windows 에서 바이너리가 백신(`Trojan:Win32/Sabsik.FL.A!ml`)에 걸린다. 서명·오탐 대응.

### Understanding

`Sabsik`+`!ml` 은 Defender 의 제네릭 머신러닝 판정으로, 새로 컴파일한 미서명 정적
바이너리의 전형적 오탐이다. 평판 0 이 큰 가중치를 갖는다. cert-gen 은 **네트워크 코드가 한
줄도 없어** 트로이목마 판정의 근거가 구조적으로 없다.

### Final

정당한 도구가 할 수 있는 것은 넷이다. 점수 낮추기(버전 리소스·심볼 유지, 완료), 오탐 신고,
코드 서명, 평판 축적. 패킹·엔트로피 조작 같은 회피 기법은 오히려 점수를 올리므로 쓰지 않는다.
빌드 스크립트가 Windows 버전 리소스를 넣고 심볼을 남기며, `SIGN_PFX` 로 Authenticode 서명을
지원한다(사내 CA 가능). 자세한 내용·제출 양식은 `docs/manual/antivirus.md`.

---

## R-004 openssl 설정(.cnf)에서 발급

### Request

기존 openssl `.cnf` 형식의 소스를 읽어 인증서를 생성. 단일 파일과 파일 여러 개 모두 지원.

### Understanding

`.cnf` 는 운영자가 쓴 파일이지만, 확장을 그대로 믿으면 cert-gen 의 "확장은 프로필이 통제한다"
원칙이 깨진다. 그래서 **DN·SAN 은 데이터로 읽되 확장은 복사하지 않는다** — `extendedKeyUsage`
는 프로필 추론에만 쓰고, `basicConstraints CA:TRUE` 는 CA 블록으로 분류한다.

사용자 파일은 `.cnf` 블록 둘을 `---` 로 구분한 형식이었다(첫째 Root CA, 둘째 leaf). 즉 단일
leaf 발급이 아니라 "이 PKI 를 이렇게 만들어라" 를 한 파일로 실행하는 것이다.

### Final

- `cert issue --config <파일>` — 단일 leaf `.cnf` 하나로 발급(CA 블록은 거부).
- `cert-gen apply <파일>...` — `---` 로 나눈 블록, 또는 파일 여러 개를 읽어 CA 생성 + 발급을
  한 번에. 파일은 명령행 순서대로, 각 파일 안의 블록도 순서대로 모은다.
- **apply 한 번은 CA 하나만 다룬다(1 CA / 1회). CA : 서버·클라이언트 = 1 : N.** CA 블록이
  둘 이상이면 거부한다 — 한 번에 여러 CA 를 만들면 어느 leaf 가 어느 CA 아래인지 파일 순서에
  숨고, CA 생성은 되돌리기 어렵다. CA 가 여럿이면 CA 마다 따로 돌린다.
- CA 는 파일의 CA 블록 하나, 또는 `--ca`, 또는 등록된 유일한 CA 에서 정한다. 멱등: 같은 CN 의
  CA 가 있으면 재사용한다. 예시: `docs/examples/pki.cnf`.
