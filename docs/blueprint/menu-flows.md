# 메뉴별 동작 흐름

메뉴를 고르면 **무엇을 입력받고 → 무엇을 검사하고 → 어떤 파일·DB 가 바뀌고 → 무엇이 나오는지**
를 적었다. 코드를 보지 않고 동작을 파악하는 것이 목적이다.

읽는 방법:

- `입력` 사용자가 채우는 값
- `검사` 틀리면 여기서 멈춘다(무엇이 왜 거부되는지)
- `변경` 디스크·DB 에 실제로 생기는 변화
- `출력` 화면에 나오는 것, 만들어지는 파일

TUI 와 CLI 는 같은 동작을 한다(둘 다 `service.py` 를 호출한다). 각 절 끝에 등가 CLI 를 적었다.

```
0. 개인키 생성·관리     키를 미리 만들어 두고 1·2 에서 골라 쓴다
1. rootCA 생성          서명할 CA 를 만든다
2. 인증서 발급          CA 로 서버·클라이언트 인증서를 만든다
3. 인증서 변환          PEM → PKCS#12 / JKS / DER / K8s Secret
4. 발급 이력·만료 조회   목록에서 상세·검증·갱신·폐기·CRL
5. 서버에 CA 신뢰 등록   OS·Java 신뢰 저장소에 등록(+등가 명령)
   환경 점검            무엇이 되고 무엇이 안 되는지
   백업 / 복원          CA 개인키를 포함한 전체 백업
```

## 전체 지도

처음 쓰는 사람의 경로는 **1 → 2 → 5** 다. 0 번은 선택이고, 3·4 는 운영 중에 쓴다.

```mermaid
flowchart LR
    S([시작]) --> Q{CA 가 있나}
    Q -->|없다| C1[1. rootCA 생성]
    Q -->|이미 쓰는 CA 가 있다| C2A[2. 발급: CA 디렉터리 지정]
    C1 --> C2[2. 인증서 발급]
    C2A --> C2
    C2 --> OUT[번들 zip: key·cert·fullchain·ca]
    OUT --> SRV[서버에 적용<br/>nginx·K8s·Java]
    OUT --> T[5. 클라이언트에 CA 신뢰 등록]
    T --> OK([TLS 동작])
    SRV --> OK
    OK --> M{운영}
    M -->|포맷이 다르다| C3[3. 변환]
    M -->|만료가 다가온다| C4[4. 조회 → 갱신]
    M -->|키가 유출됐다| C4R[4. 조회 → 폐기 → CRL]
    K0[0. 개인키 미리 생성] -.선택.-> C1
    K0 -.선택.-> C2
```

---

## 0. 개인키 생성·관리

키 생성과 인증서 발급의 **수명이 다르다**. 같은 키로 여러 번 갱신해야 하거나(장비가 키 교체를
못 받는 경우), 키를 먼저 만들어 검토한 뒤 발급만 따로 하는 경우에 쓴다.
생략하면 발급할 때 즉석 생성된다 — 그래도 아무 문제 없다.

```mermaid
flowchart TD
    A[0번 화면] --> B{무엇을 하나}

    B -->|새로 만든다| N1["입력: 이름·알고리즘·메모<br/>보호: 패스프레이즈 없음(기본) / 걸기"]
    N1 --> N2{패스프레이즈 걸기}
    N2 -->|예| N3[패스프레이즈 2회 입력]
    N2 -->|아니오| N4
    N3 --> N4["검사: 이름 중복 → -2 를 붙여 회피<br/>검사: 같은 공개키가 이미 있으면 거부"]
    N4 --> N5["변경: data_dir/keys/이름.key (0600)<br/>변경: private_key 행 추가"]
    N5 --> N6["출력: 쌍 토큰(공개키 지문 앞 8자)·경로<br/>패스프레이즈 없으면 '서버가 부팅 때 묻지 않음' 안내"]

    B -->|기존 키를 등록| I1["입력: 키 파일 경로<br/>복사: data_dir 로 복사 / 원래 자리 참조"]
    I1 --> I2{파일이 암호화?}
    I2 -->|예| I3[패스프레이즈 입력]
    I2 -->|아니오| I4
    I3 --> I4["검사: 키가 열리는지<br/>검사: 같은 공개키 중복 거부"]
    I4 --> I5[변경: private_key 행 추가<br/>복사 선택 시 keys/ 로 복사]

    B -->|상세| D1["출력: 알고리즘·보호·쌍 토큰·공개키 지문<br/>이 키를 담은 인증서 목록"]

    B -->|암호해제| X1{패스프레이즈가 있나}
    X1 -->|없다| X2[출력: 변경 없음]
    X1 -->|있다| X3["확인 모달<br/>CA 가 쓰는 키면 경고"]
    X3 --> X4[현재 패스프레이즈 입력]
    X4 --> X5["변경: 키 파일을 평문으로 다시 씀(0600)<br/>변경: private_key.encrypted = 0"]
    X5 --> X6[출력: 서버가 부팅 때 패스워드를 묻지 않음]

    B -->|내보내기| E1[출력: 현재 디렉터리에 이름.key 0600]

    B -->|삭제| R1{이 키를 쓰는 CA·인증서가 있나}
    R1 -->|있다| R2["확인 모달에 그 대상을 보여준다<br/>그래도 지우면 인증서가 개인키를 잃는다"]
    R1 -->|없다| R3[확인 모달]
    R2 --> R4[변경: 키 파일 삭제 + 행 삭제]
    R3 --> R4
```

### 알아둘 것

- **서버에 올릴 키는 패스프레이즈를 걸지 않는 것이 기본**이다. 걸면 nginx·Tomcat 이 부팅할
  때마다 패스워드를 묻고 무인 재시작이 깨진다. 보호는 파일 권한(0600)과 호스트 접근 통제다.
- 등록된 키로 CA 를 만들면 그 키를 **복사하지 않고 참조**한다. 그래서 암호해제가 그 CA 에도
  즉시 반영된다(상태가 갈라지지 않는다).
- 원래 자리를 참조(`--no-copy`)하면 그 경로가 사라지면 쓸 수 없다. 백업에도 담기지 않는다.

```bash
cert-gen key create --name web-key --algo rsa2048     # 패스프레이즈 없음
cert-gen key create --name ca-key --passphrase-stdin  # 걸기
cert-gen key import /path/to/existing.key --name legacy [--no-copy]
cert-gen key list / show <이름> / export <이름> / strip <이름> / delete <이름>
```

---

## 1. rootCA 생성

서명할 주체를 만든다. 한 번 만들면 계속 쓴다.

```mermaid
flowchart TD
    A[1번 화면] --> B["입력: CN(필수)·조직·국가<br/>키: 등록된 키 / 새로 생성(알고리즘)<br/>유효기간(기본 10년)"]
    B --> C{"검사: CN 이 비었나"}
    C -->|비었다| CE[거부: CN 은 필수]
    C -->|있다| D{"검사: 국가 코드가 2자인가"}
    D -->|아니다| DE[거부: ISO 3166-1 2자]
    D -->|맞다| E{키를 어떻게}

    E -->|등록된 키| E1["그 키를 **참조**한다(복사 안 함)<br/>보호 수준을 그대로 물려받음<br/>→ CA 패스프레이즈를 묻지 않는다"]
    E -->|새로 생성| E2{설정 encrypt_key}
    E2 -->|true 기본| E3[패스프레이즈 2회 입력]
    E2 -->|false 또는 --no-passphrase| E4["경고: data_dir 읽기 권한자가 곧 CA 가 된다"]
    E1 --> F
    E3 --> F
    E4 --> F

    F["자기서명 인증서 생성<br/>serial = 160비트 난수<br/>확장: CA:TRUE, pathLen=0,<br/>keyCertSign·cRLSign, SKI"]
    F --> G["변경: ca 행 추가(slug 선점)<br/>slug 중복이면 -2 를 붙인다"]
    G --> H["변경: data_dir/ca/slug/ca.crt (0644)<br/>새 키면 ca.key (0600)"]
    H --> I{파일 쓰기 성공?}
    I -->|실패| IE[ca 행을 되돌린다<br/>반쪽 상태를 남기지 않는다]
    I -->|성공| J["출력: slug·Subject·키·유효기간·serial·지문·경로<br/>다음 단계 안내(2번으로)"]
```

### 알아둘 것

- CN 은 호스트명이 아니라 **조직을 알아볼 이름**으로 둔다(예: `hd Root CA`). 클라이언트의
  신뢰 목록에 이 이름이 보인다.
- 앱에 로그인이 없다 → **CA 키 패스프레이즈가 사실상 유일한 서명 권한 통제**다.
- 중간 CA 는 만들지 않는다(Root → leaf 1단계). 단 **남이 만든 중간 CA 는 2번에서 쓸 수 있다**.

```bash
cert-gen ca create --cn "hd Root CA" --o HD --c KR    # 새 키 + 패스프레이즈
cert-gen ca create --cn "hd Root CA" --key ca-key     # 등록된 키 사용
cert-gen ca create --cn "hd Root CA" --no-passphrase  # 패스프레이즈 없이
cert-gen ca adopt --dir /srv/pki/mycorp               # 외부 CA 를 복사 없이 등록
cert-gen ca import --key ca.key --cert ca.crt         # data_dir 로 복사해 등록
```

---

## 2. 인증서 발급

가장 많이 쓰는 화면. **CA 선택이 두 갈래**인 것이 핵심이다.

```mermaid
flowchart TD
    A[2번 화면] --> B{CA 를 어떻게 지정}

    B -->|이력에서 고르기| B1[DB 의 CA 목록에서 선택]
    B -->|디렉터리 경로 입력| B2["그 디렉터리에서 CA 를 찾는다<br/>ca.key/ca.crt 관례명 우선<br/>없으면 글로브로 후보 수집"]
    B2 --> B3{"CA:TRUE 인 인증서가 몇 개"}
    B3 -->|0개| B3E["거부: 찾을 수 없음<br/>--ca-cert 로 지정하라고 안내"]
    B3 -->|2개 이상| B3M["거부: 후보가 여러 개<br/>추측하지 않는다"]
    B3 -->|1개| B4{지문이 DB 에 있나}
    B4 -->|있다| B5["기존 행 재사용<br/>경로가 바뀌었으면 source_dir 갱신"]
    B4 -->|없다| B6["등록: is_external=1<br/>**개인키를 복사하지 않는다**"]
    B -->|아무것도 없음| B0{등록된 CA 가}
    B0 -->|0개| B0E["거부 + 1번으로 가는 명령 안내"]
    B0 -->|1개| B1
    B0 -->|2개 이상| B0M[거부: --ca 로 고르라고 안내]

    B1 --> C
    B5 --> C
    B6 --> C
    C["입력: CN(필수)·조직<br/>SAN(여러 줄, 타입 자동 판별)<br/>용도: server/client/server+client<br/>키: 등록된 키 / 새로 생성<br/>유효기간(기본 397일)·메모"]

    C --> D["SAN 정규화<br/>CN 을 **항상 SAN 선두에** 넣는다<br/>소문자화·IDN→punycode·중복 제거"]
    D --> E{"검사: SAN 이 비었나"}
    E -->|비었다| EE["거부: leaf 는 SAN 필수<br/>(CN 폴백은 RFC 6125 이후 폐기)"]
    E -->|있다| F{"검사: 와일드카드 형태"}
    F -->|'*.com' 등| FE[거부: 레이블 3개 이상 필요]
    F -->|다중 '*'| FE2[거부: 최좌측 하나만]
    F -->|정상| G{"검사: 유효기간 ≤ max_days"}
    G -->|초과| GE[거부: 상한 초과]
    G -->|397일 초과| GW[경고만: 공인 CA 관례를 넘음]
    G -->|정상| H
    GW --> H

    H{CA 키에 패스프레이즈가 있나}
    H -->|있다| H1[패스프레이즈 입력]
    H -->|없다| H2
    H1 --> H2["CA 키 로드<br/>검사: 키-인증서 짝이 맞는지<br/>(외부 CA 에서 파일을 추측했으면 여기서 걸린다)"]
    H2 --> I{"검사: CA 가 만료됐나"}
    I -->|만료| IE2[거부: 이 CA 로는 발급 불가]
    I -->|CA 가 leaf 보다 먼저 만료| IW[경고: CA 만료 후 이 인증서도 실패한다]
    I -->|정상| J
    IW --> J

    J["순번(seq) 할당 — 짧은 트랜잭션"]
    J --> K["serial 생성(160비트 난수)<br/>키 생성·서명 — **트랜잭션 밖**<br/>(RSA-4096 생성 중 락을 잡으면 동시 발급이 막힌다)"]
    K --> L[변경: certificate 행 INSERT → 커밋]
    L --> M["변경: 번들 zip 작성<br/>bundles/연도/id-cn-serial8.zip (0600)"]
    M --> N{zip 쓰기 성공?}
    N -->|실패| NE[certificate 행 삭제<br/>고아 zip·고아 행을 남기지 않는다]
    N -->|성공| O["변경: bundle_path·sha256 기록<br/>변경: audit 행 추가"]
    O --> P["출력: CN·용도·SAN·키[쌍 토큰]·유효기간·serial·지문·번들 경로<br/>경고가 있으면 함께"]
```

### 번들 zip 내용

발급 결과를 파일 여러 개로 흩뿌리지 않는다. 흩어지면 어느 키가 어느 인증서의 짝인지 잃는다.

| 파일 | 내용 | 서버 설정에 쓰는 것 |
|---|---|---|
| `privkey.pem` | 개인키(패스프레이즈 없음) | ✔ |
| `cert.pem` | 이 서비스의 인증서 | |
| `chain.pem` | 상위 CA 체인(Root 제외). Root 직접 발급이면 없음 | |
| `fullchain.pem` | `cert.pem` + `chain.pem` | ✔ 보통 이것 |
| `ca.crt` | Root CA | 클라이언트 신뢰 등록용 |
| `metadata.json` | DN·SAN·알고리즘·유효기간·지문·발급시각 | |
| `USAGE.txt` | OS 별 신뢰 등록, nginx·NPM·K8s·Java 적용 예 | |

zip 안의 `privkey.pem` 에 0600 을 심어 둔다 — `unzip` 이 그 권한을 복원하므로 받은 쪽에서
chmod 를 잊어도 개인키가 0644 로 풀리지 않는다.

```bash
cert-gen cert issue --ca hd-root-ca --cn web.example.com --san 10.0.0.5 --san '*.web.example.com'
cert-gen cert issue --ca-dir /srv/pki/mycorp --cn api.example.com     # 외부 CA
cert-gen cert issue --ca hd-root-ca --key web-key --cn web.example.com # 미리 만든 키
cert-gen cert bundle <ID> -o /etc/nginx/tls                            # 파일로 꺼내기
```

---

## 3. 인증서 변환

**대상이 두 갈래**다(2번의 CA 선택과 같은 대칭). 실무에서 변환을 가장 많이 쓰는 경우가
"남이 준 PEM 을 p12 로" 이므로 외부 파일 경로도 받는다.

```mermaid
flowchart TD
    A[3번 화면] --> B{변환 대상}
    B -->|발급 이력| B1["번들 zip 을 읽는다<br/>검사: bundle_sha256 일치(변조 탐지)"]
    B -->|외부 파일| B2["입력: 인증서·개인키·CA 파일 경로<br/>검사: 키-인증서 짝이 맞는지"]
    B1 --> C{형식}
    B2 --> C

    C -->|PKCS#12| P1{비밀번호}
    P1 -->|입력| P2["cryptography 로 생성<br/>PBESv2 + AES-256 + SHA-256 HMAC"]
    P1 -->|비움| P3[경고: 개인키가 평문으로 들어간다]
    P2 --> P4["출력: 이름.p12 (0600)<br/>체인과 Root 포함 → Java 에서 체인 구성 불필요"]
    P3 --> P4

    C -->|JKS| J1{keytool 이 있나}
    J1 -->|없다| J1E["거부: 이 기능만 비활성<br/>'JDK 9+ 기본은 PKCS#12' 안내"]
    J1 -->|있다| J2{"비밀번호 6자 이상인가"}
    J2 -->|아니다| J2E[거부: keytool 제약]
    J2 -->|맞다| J3["PKCS#12 를 만든 뒤 keytool 로 변환<br/>비밀번호는 **stdin 으로 주입**<br/>(argv 는 /proc 로 노출된다)"]
    J3 --> J4[출력: 이름.jks + 레거시 경고]

    C -->|DER| D1[출력: 이름.der<br/>Windows certutil 가져오기용]

    C -->|PEM 세트| M1[출력: cert·fullchain·chain·privkey·ca.crt]

    C -->|K8s tls Secret| K1["입력: Secret 이름·네임스페이스<br/>선택: ca.crt 포함, Ingress 함께 생성"]
    K1 --> K2["tls.crt 에 **fullchain** 을 넣는다<br/>(leaf 단독이면 중간 CA 체인이 끊긴다)<br/>base64 한 줄(K8s 는 줄바꿈 거부)"]
    K2 --> K3["출력: YAML (+ Ingress, ingressClassName: nginx)<br/>경고: tls.key 는 인코딩일 뿐 암호화가 아니다"]
```

### 어떤 포맷을 쓰나

| 쓰는 곳 | 포맷 |
|---|---|
| nginx·Apache·HAProxy·Nginx Proxy Manager | PEM (`fullchain.pem` + `privkey.pem`) |
| Kubernetes Ingress | tls Secret YAML |
| Java (Tomcat·Spring Boot·Kafka·Elasticsearch) | **PKCS#12** |
| JKS 를 명시적으로 요구하는 레거시 | JKS |
| Windows 인증서 저장소·일부 장비 | DER |

```bash
cert-gen export p12 <ID> -o web.p12
cert-gen export jks <ID> -o web.jks
cert-gen export k8s <ID> --secret-name web-tls --namespace production --with-ca
cert-gen export p12 --cert cert.pem --key privkey.pem --ca-file ca.crt -o out.p12
```

---

## 4. 발급 이력·만료 조회

실제 사용 빈도가 가장 높은 화면이다. 발급보다 "지금 뭐가 있고 언제 만료되나" 를 더 자주 본다.

```mermaid
flowchart TD
    A[4번 화면] --> B["필터: 검색(CN·SAN 부분일치)·만료 N일 내<br/>CA·상태·키"]
    B --> C["목록: ID·CN·CA·용도·알고리즘·키[쌍]·만료·남은일·상태·SAN"]
    C --> D{행을 고르고}

    D -->|상세| D1["출력: Subject·SAN·발급 CA·용도·키·쌍 토큰<br/>유효기간·serial·순번·지문·상태·번들 경로·메모"]

    D -->|검증| V1["① 유효기간<br/>② CA 유효기간(먼저 만료되면 실패)<br/>③ 체인 경로 검증(프로필에 맞는 verifier)<br/>④ 호스트명 SAN 매칭<br/>⑤ openssl verify 교차 확인<br/>⑥ 폐기 상태<br/>⑦ 키-인증서 짝"]
    V1 --> V2["출력: 항목별 OK/FAIL/SKIP<br/>SKIP 은 도구가 없어 건너뛴 것(통과 아님)"]

    D -->|번들 추출| B1["출력: 지정 디렉터리에 7개 파일<br/>privkey.pem 은 0600"]

    D -->|갱신| R1{CA 패스프레이즈}
    R1 --> R2["기본은 **새 키**를 만든다<br/>(키 재사용은 갱신의 의미를 없앤다)<br/>--key 로 같은 키를 유지할 수도 있다"]
    R2 --> R3["DN·SAN 은 그대로<br/>변경: 새 certificate 행(renewed_from 연결)<br/>변경: 이전 건 status = superseded"]
    R3 --> R4[출력: 이전 → 신규 ID·만료·번들]

    D -->|폐기| X1["확인 모달(되돌릴 수 없다)"]
    X1 --> X2["변경: status = revoked, 시각·사유 기록"]
    X2 --> X3["출력 + 중요 안내:<br/>**cert_gen 안에서만 즉시 효력**<br/>실제 차단에는 CRL 배포가 필요"]

    D -->|CRL 생성| L1{CA 패스프레이즈}
    L1 --> L2["폐기된 인증서 목록으로 CRL 생성<br/>crl_number 증가, nextUpdate = 설정값"]
    L2 --> L3["변경: data_dir/crl/slug.crl<br/>출력: 경로·CRL 번호·폐기 건수<br/>안내: 클라이언트가 읽을 곳에 배포해야 적용"]
```

### 상태 세 가지

| 상태 | 언제 | CRL 에 들어가나 |
|---|---|---|
| `valid` | 정상 | |
| `superseded` | 갱신해서 새 건이 생김(정상 운영) | 아니오 |
| `revoked` | 사고 대응으로 폐기 | **예** |

`superseded` 와 `revoked` 를 나눈 이유는 갱신이 사고가 아니기 때문이다.

### 키-인증서 쌍 보기

공개키 지문 앞 8자를 **쌍 토큰**으로 키와 인증서 양쪽에 같게 표시한다. 토큰이 같으면 같은
개인키다.

```
key list :  web-key  rsa2048  없음  808cfb83  짝 인증서 2건
cert list:  3  web.example.com  ...  web-key 808cfb83
            2  api.example.com  ...  (즉석) 9616b4b7
```

```bash
cert-gen cert list --expiring-in 30 / --search 10.0.0.5 / --key web-key
cert-gen cert show <ID> [--pem|--text]
cert-gen cert verify <ID> --hostname web.example.com
cert-gen cert renew <ID> [--key <이름>]
cert-gen cert revoke <ID> --reason keyCompromise
cert-gen crl generate <CA-slug>
```

---

## 5. 서버에 CA 신뢰 등록

자가서명 체인은 **접속하는 쪽이 CA 를 신뢰해야** 동작한다. 그 절차가 OS 계열마다 다르고
Java 는 별도 저장소를 쓴다.

```mermaid
flowchart TD
    A[5번 화면] --> B[CA 선택]
    B --> C["탐지<br/>OS: /etc/os-release 의 ID·ID_LIKE 로 계열 판정<br/>  못 알아보면 앵커 디렉터리 존재로 추론<br/>Java: JAVA_HOME → keytool 실제 경로 → /usr/lib/jvm/*<br/>  같은 cacerts 를 링크로 공유하면 중복 제거"]
    C --> D["상태 확인<br/>OS: 앵커 파일의 지문 비교<br/>Java: keytool 전체 목록에서 **지문** 검색<br/>  (메시지 파싱은 로케일에 따라 깨진다)"]
    D --> E["표: 종류·대상·경로·쓰기 가능·상태<br/>패널: **등가 셸 명령**(복사해 쓰는 용도)<br/>      + 신뢰 저장소를 보지 않는 런타임 지정법"]
    E --> F{무엇을 하나}
    F -->|명령만 복사| F1["다른 호스트에서 root 로 실행<br/>대부분 이 경로를 쓴다"]
    F -->|등록| G{쓰기 권한}
    G -->|없다| GE["거부 + 그 대상의 명령을 보여준다<br/>조용히 실패하지 않는다"]
    G -->|있다| H[확인 모달: 시스템 신뢰 저장소를 변경한다]
    H --> I["OS: 앵커 디렉터리에 복사 → 갱신 명령 실행<br/>Java: keytool -importcert (비밀번호는 stdin)"]
    I --> J[출력: 결과. 실패하면 그 대상의 명령]
    F -->|해제| K[같은 경로로 제거]
```

### 계열별 경로

| 계열 | 앵커 디렉터리 | 갱신 명령 |
|---|---|---|
| RHEL·Rocky·Alma·Fedora | `/etc/pki/ca-trust/source/anchors` | `update-ca-trust extract` |
| Debian·Ubuntu | `/usr/local/share/ca-certificates` | `update-ca-certificates` |
| SUSE | `/etc/pki/trust/anchors` | `update-ca-certificates` |
| Alpine | `/usr/local/share/ca-certificates` | `update-ca-certificates` |
| Java | `cacerts` (JAVA_HOME 등에서 탐지) | keytool 이 즉시 반영 |

앵커 파일명·keytool alias 는 `cert-gen-<ca-slug>` 다(다른 CA 와 섞이지 않게).

### 신뢰 저장소를 보지 않는 런타임

OS·Java 저장소에 등록해도 이쪽은 따로 지정해야 한다. 화면이 경로까지 채워 보여준다.

```
REQUESTS_CA_BUNDLE   Python requests/httpx
NODE_EXTRA_CA_CERTS  Node.js
curl --cacert         일회성
git http.sslCAInfo    Git
```

```bash
cert-gen ca trust <slug>                      # 조회 + 등가 명령 (변경 없음)
sudo cert-gen ca trust <slug> --apply         # 등록
cert-gen ca trust <slug> --apply --remove     # 해제
```

---

## 환경 점검

무엇이 되고 무엇이 안 되는지를 한 화면에 모은다. 문제를 추측하기 전에 여기를 본다.

| 항목 | FAIL 이면 |
|---|---|
| 설정 파일 | 경로·문법 확인 |
| data_dir / DB | `cert-gen init` |
| data_dir 쓰기 권한 | 실행 계정 확인 |
| data_dir 권한 | `init` 이 0750 으로 조인다 |
| SQLite | 3.8 이상 필요 |
| openssl *(선택)* | 교차 검증만 건너뜀 |
| keytool *(선택)* | JKS 내보내기만 비활성 |
| CA 개인키 암호화 | `false` 면 data_dir 읽기 권한자가 곧 CA |
| 등록된 CA / CA 키 존재 | 외부 CA 경로가 마운트됐는지 |
| 발급 인증서 / 30일 내 만료 | 갱신 대상 |

선택 항목은 없어도 나머지가 모두 동작한다. 그래서 `SKIP` 을 `OK` 와 구분해 표시한다.

---

## 백업 / 복원

```mermaid
flowchart TD
    A[백업 화면] --> B{무엇을}

    B -->|백업 생성| C["DB 는 파일 복사가 아니라 sqlite 온라인 스냅샷<br/>(WAL 모드에서 파일만 복사하면 최신 커밋이 빠진다)"]
    C --> D["담는 것: DB · ca/ · bundles/ · crl/<br/>+ MANIFEST(스키마 버전·멤버별 sha256)"]
    D --> E["**외부 CA 개인키는 담지 않는다**<br/>(복사하지 않는다는 약속을 백업이 깨면 안 된다)<br/>대신 경로를 보고서에 남긴다"]
    E --> F["출력: tar.gz (0600) + 경고<br/>'이 파일 하나가 CA 그 자체다'"]

    B -->|복원 계획| G["무결성을 **전부** 검사한다<br/>(복원 시점으로 미루면 쓰기 시작한 뒤 실패해<br/> 반쪽 복원이 된다)"]
    G --> H{검사}
    H -->|손상·변조| HE[거부: 어느 멤버의 해시가 다른지]
    H -->|스키마가 더 새 버전| HE2[거부: cert_gen 을 올리라고 안내]
    H -->|경로 탈출·링크 포함| HE3[거부: 외부에서 온 파일일 수 있다]
    H -->|정상| I["출력: 새로 생김·덮어씀·백업에 없는 현재 파일 수<br/>아무것도 바꾸지 않는다"]

    B -->|복원 실행| J[계획 검사를 다시 통과]
    J --> K["현재 data_dir 를 .bak-타임스탬프 로 **복사**<br/>(이동하면 복원 실패 시 원본도 사라진다)"]
    K --> L[파일 전개 → DB 가 열리는지 확인]
    L --> M[출력: 복원 수 + 보존 사본 경로]
```

### 복원되지 않는 것

| 항목 | 이유 | 대응 |
|---|---|---|
| 외부 CA 개인키 | `data_dir` 밖이라 담지 않는다 | 따로 백업하고 같은 경로에 둔다 |
| `/etc/cert-gen/config.toml` | 호스트 설정이라 담지 않는다 | 수정했다면 따로 보관 |
| CA 패스프레이즈 | 저장하지 않는다 | 비밀 관리 체계에 보관 |

**패스프레이즈를 잃으면 CA 키를 복구할 수 없다.** 백업만으로는 부족하다.

```bash
cert-gen backup create
cert-gen backup restore <파일> --dry-run    # 무결성 검사 포함, 변경 없음
cert-gen backup restore <파일>
```

---

## 공통 규칙

읽다가 "왜 이렇게 동작하지?" 싶을 때 여기를 보면 대부분 답이 있다.

| 규칙 | 이유 |
|---|---|
| CN 을 항상 SAN 에 넣는다 | CN 만 있는 인증서는 현대 클라이언트가 거부한다(RFC 6125) |
| leaf 에 SAN 이 없으면 발급을 거부한다 | 위와 같은 이유. 발급 시점에 막는 편이 낫다 |
| 비밀값을 명령행 인자로 받지 않는다 | `/proc/<pid>/cmdline` 으로 같은 호스트의 다른 사용자에게 노출된다 |
| 서버용 키는 패스프레이즈 없음이 기본 | 걸면 서버가 부팅할 때마다 패스워드를 묻는다 |
| CA 키는 암호화가 기본 | 서명할 때만 쓰이고, 앱 인증이 없어 이것이 유일한 통제다 |
| 개인키 파일은 0600, 권한을 먼저 좁힌 뒤 쓴다 | 만든 다음 chmod 하면 그 사이에 읽힐 수 있다 |
| DB 커밋 → 그 다음 파일 쓰기 | 역순이면 DB 에 없는 고아 파일이 남아 추적이 안 된다 |
| 키 생성·서명은 트랜잭션 밖에서 | RSA-4096 생성 중 쓰기 락을 잡으면 동시 발급이 모두 막힌다 |
| 추측하지 않고 거부한다 | 외부 CA 후보가 여러 개면 고르지 않고 지정하라고 안내한다 |
| `SKIP` 을 `OK` 와 구분한다 | 도구가 없어 건너뛴 것을 통과로 보이면 안 된다 |
| 폐기는 CRL 을 배포해야 효력이 있다 | 그 사실을 감추면 "폐기했는데 왜 접속되나" 가 된다 |
| 자가서명은 클라이언트에 `ca.crt` 등록이 전제 | 5번 화면이 그 절차를 담당한다 |
