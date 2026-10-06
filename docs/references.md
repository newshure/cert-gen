# references.md

cert_gen 이 참조·재사용하는 외부 소스와 라이선스 검증 기록.

라이선스 우선순위 정책: 1순위 무제약(CC0/Unlicense/0BSD) → 2순위 MIT/BSD/Apache-2.0/ISC →
3순위 약한 copyleft(사전 승인 필요) → 강한/네트워크 copyleft 및 상업제한 라이선스는 사용 금지.

## 1. 라이브러리 의존성

Go 재작성의 목적은 **설치 과정 없는 단일 실행 파일**이다. 그래서 두 가지가 선택 기준에
추가된다. (a) `CGO_ENABLED=0` 으로 정적 링크가 되어야 한다 — C 의존이 하나라도 있으면
glibc 버전에 묶여 RHEL 8 과 Debian 13 을 한 바이너리로 못 덮는다. (b) Windows 교차 컴파일이
되어야 한다.

| 대상 | 출처 | 라이선스 | SPDX | 용도 | 검증 |
|---|---|---|---|---|---|
| Go 표준 `crypto/x509` | https://go.dev | BSD-3-Clause | `BSD-3-Clause` | 인증서·CSR·CRL 생성과 파싱, 경로 검증 | 2순위. X.509 의 거의 전부를 stdlib 로 해결한다 |
| modernc.org/sqlite | https://gitlab.com/cznic/sqlite | BSD-3-Clause | `BSD-3-Clause` | 발급 이력·serial 저장 | 2순위. **순수 Go 로 번역된 SQLite** 라 cgo 가 필요 없다. `mattn/go-sqlite3` 는 cgo 라서 정적 링크·교차 컴파일 목표와 충돌해 탈락 |
| github.com/BurntSushi/toml | https://github.com/BurntSushi/toml | MIT | MIT | 설정 파일 파싱 | 2순위. `md.Undecoded()` 로 오타난 키를 거부할 수 있어 채택 |
| github.com/youmark/pkcs8 | https://github.com/youmark/pkcs8 | MIT | MIT | **암호화된** PKCS#8 개인키 쓰기 | 2순위. stdlib 는 암호화 PKCS#8 을 *읽지도 쓰지도* 않는다(`x509.MarshalPKCS8PrivateKey` 는 평문 전용). CA 키 패스프레이즈 보호에 필수 |
| software.sslmate.com/src/go-pkcs12 | https://github.com/SSLMate/go-pkcs12 | BSD-3-Clause | `BSD-3-Clause` | PKCS#12 생성·파싱 | 2순위. `golang.org/x/crypto/pkcs12` 는 **읽기 전용**이라 쓸 수 없다. 이쪽은 쓰기를 지원하고 알고리즘 세대를 명시적으로 고를 수 있다 |
| github.com/pavlo-v-chernykh/keystore-go/v4 | https://github.com/pavlo-v-chernykh/keystore-go | MIT | MIT | **JKS 생성** | 2순위. 이것으로 `keytool` 외부 호출을 완전히 제거했다(아래 참조) |

### TUI (Bubble Tea)

| 대상 | 출처 | 라이선스 | SPDX | 용도 | 검증 |
|---|---|---|---|---|---|
| bubbletea | https://github.com/charmbracelet/bubbletea | MIT | MIT | TUI 런타임(Elm 구조) | 2순위. v1.3.10 확인 |
| lipgloss | https://github.com/charmbracelet/lipgloss | MIT | MIT | 스타일·레이아웃 | 2순위. v1.1.0 확인 |
| bubbles | https://github.com/charmbracelet/bubbles | MIT | MIT | textinput 위젯 | 2순위. v1.0.0 확인 |
| atotto/clipboard | https://github.com/atotto/clipboard | BSD-3-Clause | `BSD-3-Clause` | bubbles/textinput 의 간접 의존 | 2순위 |

직접 만든 위젯과 그 이유:

| 위젯 | 기성품을 쓰지 않은 이유 |
|---|---|
| 드롭다운(`selectField`) | 닫힌 상태에서 **화살표로는 열리지 않고 스페이스로만** 열려야 한다(사용자 요청). 기성 select 는 화살표에 반응해 펼쳐지고, 그러면 항목 간 이동과 값 변경이 섞여 실수로 설정이 바뀐다 |
| 여러 줄 입력(`areaField`) | SAN 입력에서 **Enter 가 줄바꿈**이어야 한다. 한 줄 입력 위젯은 Enter 를 제출로 먹어 줄바꿈이 안 된다 |
| 표 | 동아시아 문자 폭(2칸)을 세야 한다. 한글 CN 이 섞이면 열이 어긋난다 |

반칸 블록 글리프(`▔▁▊▎█` 등)는 쓰지 않는다. 폰트에 따라 `ㅁ` 로 깨지고, 깨지지 않아도
화면이 어지러워진다. 테두리는 가는 선(`─│┌`)만 쓰고 강조는 배경색으로 한다.
회귀 테스트로 모든 화면에 블록 문자가 없음을 확인한다.

### 빌드 시점에만 쓰는 도구

| 대상 | 출처 | 라이선스 | 용도 | 비고 |
|---|---|---|---|---|
| goversioninfo | https://github.com/josephspurrier/goversioninfo | MIT | Windows PE 의 버전 리소스(VERSIONINFO) 생성 | 2순위. **빌드 시점 도구이고 go.mod 의 런타임 의존이 아니다.** `.syso` 를 만들어 링커가 집어넣는다 |
| osslsigncode | https://github.com/mtrojnar/osslsigncode | GPL-3.0 | Authenticode 서명 (선택) | **별도 프로세스 호출만.** 우리 바이너리에 링크되지 않으므로 라이선스가 전파되지 않는다. 서명하지 않으면 쓰지 않는다 |

버전 리소스를 넣는 이유는 백신 오탐이다. Go 는 `.rsrc` 섹션이 없는 맨 PE 를 만드는데,
정상 소프트웨어는 거의 예외 없이 회사명·제품명·설명을 담고 있어서 그것이 없는 것 자체가
휴리스틱 점수를 올린다. 같은 이유로 Windows 빌드는 심볼을 스트립하지 않는다.
자세한 내용은 `docs/manual/antivirus.md`.

### keytool 의존 제거

JKS 를 `keystore-go` 로 **직접 쓴다.** `keytool`(OpenJDK)을 부르지 않으므로 JDK 가 없는
서버에서도 동작하고, 키스토어 비밀번호가 외부 프로세스의 argv(`/proc/<pid>/cmdline`)로
노출되지 않는다. 검증은 **Java 자신에게** 맡겼다 — 우리가 쓴 JKS·p12 를 `keytool -list` 가
읽는지 테스트로 확인한다(OpenJDK 21.0.12 로 통과, JDK 없는 환경에서는 skip).

### PKCS#12 알고리즘 세대 고정

`go-pkcs12` 의 `Modern` 별칭은 **버전이 오르면 가리키는 대상이 바뀌도록** 설계돼 있다
(현재 `Modern2023`, 라이브러리에는 이미 `Modern2026` 이 있다). 별칭을 쓰면 의존성만 올려도
산출물의 호환 범위가 조용히 달라진다. 그래서 `Modern2023` 을 **명시적으로 고정**했다.

| 세대 | 알고리즘 | 읽을 수 있는 소비자 |
|---|---|---|
| `Modern2023` (채택) | PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC, MAC = HMAC-SHA2 | OpenSSL 1.1.1+, Java 12+, Windows Server 2019+ |
| `Modern2026` (미채택) | 위 + MAC 이 PBMAC1 | OpenSSL 3.4+, **Java 26+** — 폐쇄망 레거시에 너무 앞선다 |
| `LegacyDES` (옵트인) | 3DES + SHA-1 | 구형 Java 8·옛 Windows. 약하다는 경고를 반드시 함께 낸다 |

고정이 유지되는지는 `openssl pkcs12 -info` 가 AES-256-CBC 를 보고하는지로 테스트한다.

## 2. 외부 실행 바이너리로 사용 (OS 패키지, 링크 아님)

별도 프로세스 호출이므로 라이선스가 전파되지 않는다.

| 대상 | 라이선스 | 용도 | 없을 때 |
|---|---|---|---|
| `openssl` | Apache-2.0 | 체인 검증 교차 확인(`openssl verify`), `cert show --text` | 해당 검사만 건너뜀 |
| `keytool` (OpenJDK) | GPL-2.0 WITH Classpath-exception-2.0 | **선택적 교차 검증**(테스트에서 `keytool -list` 로 JKS·p12 되읽기 확인) | 해당 테스트만 skip. JKS 생성 자체는 `keytool` 없이 한다 |

## 3. 조사했으나 채택하지 않은 것 (판단 근거)

| 대상 | 라이선스 | 판단 | 근거 |
|---|---|---|---|
| **step-ca** https://github.com/smallstep/certificates | Apache-2.0 | 미채택 | ACME·자동 갱신이 강력하지만 상시 구동 서버가 필요하다. 요구사항은 "파드 아님, 한시적 사용, 독립 실행형" 이라 상충한다. 컨트롤 레이어가 2개가 되는 비용도 크다 |
| **cfssl** https://github.com/cloudflare/cfssl | BSD-2-Clause | 미채택 | CLI 는 적합하지만 Go 바이너리라 폐쇄망 반입·빌드 체인이 별도로 생기고, 발급 이력·포맷 변환·TUI 를 어차피 우리가 얹어야 한다 |
| **mkcert** https://github.com/FiloSottile/mkcert | BSD-3-Clause | 미채택(설계 참조) | 로컬 개발용으로 훌륭하지만 CA 를 OS 신뢰 저장소에 자동 등록하는 전제이고, 발급 이력·CRL·포맷 변환이 없다. "CN 을 SAN 에 자동 포함" 같은 기본값 판단은 참조했다 |
| **easy-rsa** https://github.com/OpenVPN/easy-rsa | GPL-2.0 | 미채택 | 강한 copyleft 이고, 허용 라이선스 대안(위)이 존재하므로 정책상 사용하지 않는다 |

## 3-1. 배포 방식

**설치 과정 없는 단일 정적 바이너리**다. `CGO_ENABLED=0` 로 빌드해 glibc 를 포함한 어떤
동적 의존도 없다 — RHEL 8·9·10, Debian 12·13, Ubuntu 22·24 를 한 바이너리로 덮고, Windows 는
교차 컴파일한다(`GOOS=windows`). 모든 라이브러리가 바이너리에 정적으로 들어가므로 실행
호스트에는 아무것도 반입하지 않는다.

빌드는 재현 가능하다(`-trimpath -buildid=`). Windows 바이너리는 백신 오탐을 줄이기 위해
버전 리소스를 넣고 심볼을 남긴다 → `docs/manual/antivirus.md`. 컨테이너는 바이너리 하나를
`COPY` 하는 것이 전부이고 빌드 중 네트워크를 쓰지 않는다 → `deploy/container/`.

## 4. 설계·규격 참조 (문서)

| 대상 | 참조 내용 |
|---|---|
| RFC 5280 | 인증서·CRL 프로파일. serial 은 양수·20옥텟 이하, `basicConstraints`/`keyUsage`/`extendedKeyUsage`/SKI/AKI 의 의미, CRL `reasonCode`(`unspecified` 는 확장을 넣지 않는 관례) |
| RFC 6125 | 호스트명 검증. **CN 폴백 폐기** → leaf 에 SAN 필수, 와일드카드는 최좌측 레이블 하나만 대체 |
| RFC 5890 / IDNA | 국제화 호스트명은 A-label(punycode)로 넣어야 한다 |
| CA/Browser Forum Baseline Requirements | leaf 유효기간 관례(398일 상한 → 기본값 397일). **사설 CA 에 강제되지는 않으며** 상한을 넘기면 경고만 띄운다 |
| Oracle keytool 문서 | "In JDK 9 and later, the default keystore implementation is PKCS12" → JKS 는 레거시. keytool 자신도 PKCS#12 로 이전하라고 경고한다 |
| Kubernetes `kubernetes.io/tls` Secret | `tls.crt` 에는 fullchain 을 넣는다. `ca.crt` 는 표준 필드가 아니지만 nginx ingress 의 `auth-tls-secret` 이 읽는다 |
