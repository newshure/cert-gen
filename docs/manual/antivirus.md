## 백신 오탐 (Windows)

Windows 에서 `cert-gen.exe` 가 바이러스로 탐지되는 경우가 있다. 이 문서는 (1) 공급망이
안전한지 확인하는 방법, (2) 왜 탐지되는지, (3) 무엇을 하면 되는지를 정리한다.

## 1\. 먼저 확인할 것 — 진짜인가

오탐이라고 단정하기 전에 확인해야 한다. 아래는 2026-10-04 기준 실측 결과다.

| 확인 항목 | 명령 | 결과 |
| --- | --- | --- |
| 의존성이 체크섬 DB 와 일치하는가 | `go mod verify` | `all modules verified` |
| 체크섬 검증을 우회했는가 | `go env GOPRIVATE GONOSUMDB GOFLAGS` | 모두 비어 있음 |
| 체크섬 DB·프록시 | `go env GOSUMDB GOPROXY` | `sum.golang.org` / `proxy.golang.org` |
| 빌드가 재현되는가 | `deploy/build.sh` 두 번 실행 후 해시 비교 | 동일 |
| 네트워크로 통신하는 코드가 있는가 | `grep -rn "net/http|net\.Dial|\.Listen("` | **없음** |
| 외부 프로세스를 실행하는 곳 | `grep -rn "exec\.Command"` | 1곳 (`internal/verify` 의 openssl 교차 검증, 옵트인) |

cert-gen 은 **네트워크를 전혀 쓰지 않는다.** 통신하는 코드가 한 줄도 없다. 따라서
"정보를 외부로 보낸다" 류의 탐지는 구조적으로 성립할 수 없다.

### 받은 파일이 그 소스에서 나왔는지 확인

두 가지 방법이 있다.

**(1) 바이너리에 새겨진 커밋을 읽는다.** Go 는 빌드할 때 git 커밋을 바이너리에 자동으로
새긴다. 별도 도구 없이 확인할 수 있다.

```plaintext
go version -m cert-gen.exe
```

```plaintext
  build  vcs.revision=&lt;커밋 해시&gt;
  build  vcs.time=&lt;커밋 시각&gt;
  build  vcs.modified=false     ← false 여야 한다
```

`vcs.modified=true`(또는 버전에 `+dirty`)면 **커밋되지 않은 변경이 섞인 빌드**다.
릴리스 바이너리가 이 상태면 어느 소스에서 나왔는지 답할 수 없으므로 신뢰하지 않는다.
`deploy/build.sh` 는 트리가 깨끗하지 않으면 빌드를 거부한다.

**(2) 직접 빌드해 해시를 비교한다.** 빌드는 재현 가능하다(`-trimpath`, `-buildid=`).

```plaintext
git checkout <vcs.revision 의="" 커밋="">
git status --porcelain      # 비어 있어야 한다
VERSION=0.1.0 bash deploy/build.sh
cat dist/SHA256SUMS
```

\> 재현성의 정확한 범위: **같은 커밋 + 깨끗한 트리**에서 바이트 단위로 동일하다.
\> 커밋이 다르면 새겨진 `vcs.revision` 이 달라 해시도 달라진다 — 의도된 동작이다.
\> 따라서 "해시가 다르다" 가 곧 "변조" 는 아니고, 먼저 커밋이 같은지를 봐야 한다.

Windows 에서 받은 파일의 해시:

```plaintext
Get-FileHash .\cert-gen.exe -Algorithm SHA256
```

## 1-1. 실제 보고된 탐지 — `Trojan:Win32/Sabsik.FL.A!ml`

2026-10-04, Windows Defender. 이 이름을 분해해 읽으면 성격이 드러난다.

| 부분 | 뜻 |
| --- | --- |
| `Trojan:Win32` | 분류와 플랫폼 |
| `Sabsik` | Defender 의 **제네릭 버킷**이다. 특정 악성코드 패밀리를 지목하는 이름이 아니다 |
| `FL.A` | 변종 구분자 |
| `!ml` | **머신러닝 판정.** 시그니처가 일치한 것이 아니라 추론으로 분류했다는 표시다 |

`Sabsik`+`!ml` 조합은 Go·Rust·Nim 으로 빌드한 실행 파일에
대해 오탐으로 가장 많이 보고되는 판정이다. 새로 컴파일한 미서명 정적 링크 바이너리가
전형적인 대상이다.

이 판정은 클라우드 전달 보호(cloud-delivered protection)의 ML 모델에서 나온다.
파일의 평판(세상에 얼마나 퍼져 있는가)이 큰 가중치를 갖기 때문에, 방금 만든 파일은
내용과 무관하게 불리하다.

### 판정 출처 확인

```plaintext
Get-MpThreatDetection | Select-Object -Property ThreatName, Resources, InitialDetectionTime
Get-MpThreat | Select-Object -Property ThreatName, SeverityID, CategoryID
```

## 2\. 왜 탐지되는가

Go 로 만든 Windows 바이너리는 휴리스틱·머신러닝 기반 엔진에서 오탐이 잦다. Microsoft
Defender 가 내는 이름은 보통 `Trojan:Win32/Wacatac.B!ml`, `Program:Win32/Wacapew.C!ml`
처럼 끝에 `!ml`(machine learning)이 붙는다. **이름에** `**!ml**` **이 있으면 시그니처가 일치한**
**것이 아니라 추론으로 판정한 것**이고, 오탐일 가능성이 높다.

cert-gen 에 해당하는 요인:

| 요인 | 내용 | 대응 |
| --- | --- | --- |
| 평판(prevalence) 0 | 방금 만든 파일이라 세상에 전례가 없다. Defender 의 ML 은 이것을 크게 본다 | 서명 + 오탐 신고 |
| 버전 리소스 없음 | Go 는 `.rsrc` 섹션이 없는 맨 PE 를 만든다. 정상 소프트웨어는 거의 예외 없이 회사명·제품명·설명을 담는다 | **해결됨** (아래 3절) |
| 미서명 | Authenticode 서명이 없다 | 서명 (아래 3절) |
| 심볼 제거 | `-s -w` 로 스트립하면 분석 방해 신호로 읽힌다 | **해결됨** — Windows 빌드는 스트립하지 않는다 |
| 동작 자체 | 키를 생성하고, 파일을 쓰고, 외부 프로세스를 띄운다 | 랜섬웨어 휴리스틱과 표면이 겹친다. 피할 수 없다 |
| 정적 링크 | 단일 파일에 런타임 전체가 들어가 크고 엔트로피가 높다 | 단일 실행 파일 요구사항상 피할 수 없다 |

## 3\. 이미 적용한 완화

`deploy/build.sh` 가 Windows 빌드에 두 가지를 다르게 한다.

**버전 리소스(VERSIONINFO) 포함** — `deploy/windows/versioninfo.json` 의 내용을
`goversioninfo`(MIT)가 `.syso` 로 만들고 링커가 집어넣는다. 결과적으로 `.rsrc` 섹션에
CompanyName·ProductName·FileDescription·LegalCopyright 가 들어간다. 확인:

**심볼 유지** — Windows 바이너리는 `-s -w` 를 주지 않는다. 11MB → 16MB 로 커지지만,
휴리스틱 점수를 낮추고 오탐 신고를 받은 분석자가 들여다볼 단서를 남긴다.

리눅스 빌드는 그대로 스트립한다(오탐 문제가 사실상 없고 크기가 3MB 가까이 줄어든다).

## 4\. 남은 근본 해결 — Authenticode 서명

위 완화는 점수를 낮출 뿐이고, 평판 0 인 미서명 실행 파일이라는 사실은 그대로다.
**확실한 해결은 코드 서명이다.**

`deploy/build.sh` 가 지원한다. 비밀번호는 argv 로 받지 않고 환경변수에서 읽는다.

```plaintext
export SIGN_PFX=/path/to/codesign.pfx
export SIGN_PFX_PASSWORD='...'
VERSION=0.1.0 bash deploy/build.sh
```

`osslsigncode` 가 필요하다(Rocky: `dnf install osslsigncode`).

### 사내 CA 로 서명할 수 있는가

할 수 있다. 다만 그 CA 를 각 Windows 의 **두 곳**에 등록해야 효력이 있다.

*   신뢰할 수 있는 루트 인증 기관 (Trusted Root Certification Authorities)
*   **신뢰할 수 있는 발행자 (Trusted Publishers)** — 이것을 빠뜨리면 서명이 있어도 경고가 난다

GPO 로 배포하면 된다. 폐쇄망에서는 이 방법이 현실적이다.

\> 주의: cert-gen 으로 만든 인증서는 **코드 서명용이 아니다.** 프로필이 serverAuth /
\> clientAuth 라서 Authenticode(codeSigning EKU, `1.3.6.1.5.5.7.3.3`)로는 쓸 수 없다.
\> 코드 서명 인증서는 별도로 준비해야 한다.

인터넷에 공개 배포한다면 공인 코드서명 인증서(OV/EV)가 필요하다. EV 는 SmartScreen
평판을 즉시 얻는다.

## 5\. 오탐 신고

제출하면 보통 며칠 안에 정의 파일이 갱신된다.

*   **Microsoft**: https://www.microsoft.com/en-us/wdsi/filesubmission
    → "Software developer" 로 제출. 탐지 이름과 SHA256 을 함께 적는다.
*   그 외 엔진: 해당 벤더의 false positive 제출 창구

제출 양식에 붙여 넣을 내용(값은 빌드할 때마다 갱신한다):

영문으로 쓰는 편이 처리가 빠르다.

## 6\. 임시 조치 (내부망에서 지금 써야 할 때)

오탐임을 위 1절로 확인한 뒤에만 한다.

```plaintext
# 관리자 PowerShell. 경로 하나만 예외로 둔다 — 드라이브 전체를 제외하지 않는다.
Add-MpPreference -ExclusionPath "C:\tools\cert-gen\cert-gen.exe"
```

경로 예외는 **그 경로에 놓이는 다른 파일까지 허용**한다는 점을 알고 써야 한다.
가능하면 파일 해시로 제한하는 편이 안전하다.

```plaintext
# SHA256 으로 예외를 둔다 (Defender 플랫폼 4.18.2211 이상)
Add-MpPreference -ThreatIDDefaultAction_Ids 0 -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionExtension $null -ErrorAction SilentlyContinue
# 해시 기반은 조직 정책(Intune/GPO)의 "허용된 위협" 또는 WDAC 규칙으로 등록한다.
# 단일 호스트에서는 아래처럼 탐지를 허용 목록에 넣는다.
Get-MpThreatDetection | Where-Object { $_.Resources -match "cert-gen" }
```

조직 전체라면 **WDAC 또는 AppLocker 에 해시 규칙**을 넣는 것이 정석이다. Defender 의
경로 예외보다 범위가 좁고 감사 기록이 남는다. 해시는 `dist/SHA256SUMS` 에 있다.

\> 예외를 두기 전에 반드시 1절의 확인을 거친다. 특히 `go version -m` 으로
\> `vcs.modified=false` 와 커밋 해시를 확인하고, 그 커밋이 저장소에 있는지 본다.

대안: 리눅스 바이너리를 쓴다. 같은 소스에서 나오고 오탐 문제가 없다.
\</vcs.revision>

```plaintext
(Get-Item .\cert-gen.exe).VersionInfo
```
