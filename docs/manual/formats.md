# 포맷별 적용

cert_gen 은 PEM 을 기본으로 보관하고 필요할 때 변환한다.
변환 대상은 **발급 이력** 또는 **외부 파일** 둘 다 지정할 수 있다.

```bash
cert-gen export <형식> <ID>                                   # 이력 기반
cert-gen export <형식> --cert cert.pem --key privkey.pem      # 외부 파일
```

## 어떤 포맷을 쓸 것인가

| 쓰는 곳 | 포맷 | 명령 |
|---|---|---|
| nginx, Apache, HAProxy, Nginx Proxy Manager | PEM | `cert-gen cert bundle <ID> -o <디렉터리>` |
| Kubernetes Ingress | tls Secret YAML | `cert-gen export k8s <ID> --secret-name <이름>` |
| Java (Tomcat, Spring Boot, Kafka, Elasticsearch) | **PKCS#12** | `cert-gen export p12 <ID>` |
| Java (JKS 를 요구하는 레거시) | JKS | `cert-gen export jks <ID>` |
| Windows 인증서 저장소, 일부 네트워크 장비 | DER | `cert-gen export der <ID>` |

## PEM

```
cert.pem        leaf 단독
chain.pem       상위 CA 체인 (Root 제외). Root 가 직접 발급했으면 없다
fullchain.pem   cert + chain   ← 서버 설정에는 이것을 쓴다
ca.crt          Root CA        ← 클라이언트 신뢰 등록용. 서버 설정에 넣지 않는다
privkey.pem     개인키 (PKCS#8, 0600)
```

`fullchain` 에 Root 를 넣지 않는 이유: 클라이언트가 이미 Root 를 신뢰하고 있어야 하므로
서버가 보내도 의미가 없고 핸드셰이크 바이트만 늘어난다.

### Nginx Proxy Manager

SSL Certificates → Add SSL Certificate → Custom

| 항목 | 파일 |
|---|---|
| Certificate Key | `privkey.pem` |
| Certificate | `fullchain.pem` |
| Intermediate | `chain.pem` (없으면 생략) |

## Kubernetes

```bash
cert-gen export k8s 1 --secret-name web-tls --namespace production --with-ca \
  --ingress-host web.example.com --ingress-service web:8080 -o web-tls.yaml
kubectl apply -f web-tls.yaml
```

- `tls.crt` 에는 **fullchain** 이 들어간다. leaf 단독을 넣으면 중간 CA 가 있는 경우
  클라이언트가 체인을 완성하지 못한다.
- `--with-ca` 는 `ca.crt` 필드를 추가한다. 표준 필드는 아니지만 nginx ingress 의
  클라이언트 인증(`nginx.ingress.kubernetes.io/auth-tls-secret`)이 이 키를 읽는다.
- `--namespace-token` 을 쓰면 네임스페이스를 `__NAMESPACE__` 로 두어 `deploy.sh` 가
  렌더링하게 할 수 있다(워크스페이스 컨벤션).

> **`tls.key` 는 base64 로 인코딩된 것이지 암호화된 것이 아니다.** 생성된 YAML 을 저장소에
> 그대로 커밋하지 말 것. Sealed-Secrets / SOPS / External-Secrets 중 하나를 쓴다.

## PKCS#12 (.p12)

```bash
cert-gen export p12 1 --alias web -o web.p12
```

- JDK 9 이후 **기본 키스토어 형식**이고 Java 8u60+ 도 직접 읽는다.
- Windows 는 더블클릭으로 가져온다.
- 비밀번호를 비우면 개인키가 평문으로 들어간다(경고가 뜬다).
- 체인과 Root CA 가 함께 들어가므로 Java 쪽에서 신뢰 체인을 따로 구성하지 않아도 된다.

Spring Boot:

```properties
server.ssl.key-store=/etc/app/web.p12
server.ssl.key-store-type=PKCS12
server.ssl.key-store-password=${KEYSTORE_PASSWORD}
server.ssl.key-alias=web
```

확인:

```bash
openssl pkcs12 -in web.p12 -info -nokeys
keytool -list -keystore web.p12 -storetype PKCS12   # JDK 가 있는 곳에서만
```

## JKS (.jks)

```bash
cert-gen export jks 1 --alias web -o web.jks
```

- **레거시 형식이다.** keytool 자신이 "PKCS#12 로 이전하라" 고 경고한다.
  JKS 를 명시적으로 요구하는 오래된 애플리케이션에만 쓴다.
- **JDK 나 `keytool` 이 필요하지 않다.** cert-gen 이 JKS 포맷을 직접 쓴다. 덕분에 JDK 가
  없는 서버에서도 되고, 키스토어 비밀번호가 다른 프로세스의 argv 로 노출되지 않는다.
- 비밀번호는 **6자 이상 필수**다(Java 제약). 더 짧으면 keytool 로 다시 열 수 없는 파일이
  되므로 cert-gen 이 미리 거부한다. 빈 비밀번호도 쓸 수 없다.

확인(JDK 가 있는 곳에서):

```bash
keytool -list -keystore web.jks -storetype JKS
```

## DER (.der / .cer)

```bash
cert-gen export der 1 -o web.der
certutil -addstore -f Root web.der     # Windows
```

PEM 과 같은 내용의 바이너리 표현이다. 개인키는 들어가지 않는다.

## 비밀번호 전달 (스크립트)

키스토어 비밀번호를 명령행 인자로 받지 않는다(`/proc/<pid>/cmdline` 노출).

```bash
export CERT_GEN_STORE_PASSWORD='...'
# 또는
echo '...' | cert-gen export p12 1 --password-stdin -o web.p12
```

## openssl 설정(.cnf)에서 발급

기존 `openssl req -config` 자산을 그대로 넣어 발급한다. 손으로 쌓아 둔 DN·SAN 을 다시
타이핑하지 않아도 된다.

```bash
cert-gen cert issue --config req.cnf --ca hd-root-ca
```

읽는 범위:

| .cnf 항목 | 처리 |
|---|---|
| `[req] distinguished_name` → DN 섹션 | DN(CN·O·OU·C·ST·L·email)을 읽는다. 짧은·긴 형식 모두 |
| `subjectAltName`(인라인 또는 `@alt_names`) | `DNS`·`IP`·`email`·`URI` 를 읽는다 |
| `extendedKeyUsage` | **프로필을 추론한다**: serverAuth→server, clientAuth→client, 둘 다→server+client |
| `prompt = no` / prompt 모드 | 둘 다 처리한다(`_default` 가 있으면 그것이 값) |

```ini
# req.cnf
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = web.hd.local
O  = HaeDong
C  = KR

[v3_req]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = web.hd.local
DNS.2 = *.hd.local
IP.1  = 10.0.0.5
```

### 읽지 않는 것 — 확장은 프로필이 통제한다

**`keyUsage`·`basicConstraints` 는 그대로 복사하지 않는다.** cert-gen 은 확장을 프로필로
통제해 실수를 구조적으로 막는다. `.cnf` 의 확장을 자유롭게 반영하면 그 안전장치가 사라진다.

- `extendedKeyUsage` 는 **프로필 추론에만** 쓴다(값을 그대로 넣지 않는다).
- `basicConstraints CA:TRUE` 는 **무시하고 경고한다** — CA 는 `cert-gen ca create` 로 만든다.
- 반영하지 않는 `keyUsage`·알 수 없는 EKU 는 경고로 알린다(조용히 버리지 않는다).
- `$var` 치환, `.include`, `otherName`/`RID`/`dirName` SAN 은 지원하지 않는다(경고).

### 플래그가 .cnf 를 덮어쓴다

"설정을 바탕으로 하되 이번만 바꾼다" 가 되게 한다.

```bash
# req.cnf 의 O·OU·C 는 유지하고 CN·SAN·프로필만 바꾼다
cert-gen cert issue --config req.cnf --cn api.hd.local --san ip:10.0.0.9 --profile client
```

명령행으로 준 값이 항상 이긴다. CN 을 바꾸면 그 CN 이 SAN 에 자동 포함된다.

## 한 파일로 CA·인증서 한 번에 — apply

openssl `.cnf` 블록을 **`---` 로 구분**해 한 파일에 적으면, CA 생성부터 발급까지 한 번에
한다. "이 PKI 를 이렇게 만들어라" 를 선언적으로 적는 방식이다. 예시: `docs/examples/pki.cnf`.

```ini
# pki.cnf — 첫 블록은 CA, 둘째 블록부터 그 CA 아래 발급
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca
prompt             = no
[ v3_ca ]
basicConstraints   = critical, CA:TRUE, pathlen:0
keyUsage           = critical, keyCertSign, cRLSign
[ req_distinguished_name ]
countryName        = KR
organizationName   = HaeDong Inc.
commonName         = HaeDong Root CA

---

[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no
[ v3_req ]
basicConstraints   = CA:FALSE
extendedKeyUsage   = serverAuth, clientAuth
subjectAltName     = @alt_names
[ alt_names ]
DNS.1 = example.com
DNS.2 = *.example.com
IP.1  = 192.0.2.10
[ req_distinguished_name ]
countryName        = KR
commonName         = example.com
```

```bash
cert-gen apply pki.cnf --dry-run      # 먼저 계획을 본다
cert-gen apply pki.cnf -o ./out       # CA 생성 + 발급
```

### 단일 파일 / 각각 파일 모두 된다

한 파일에 `---` 로 블록을 나눠도 되고, 파일을 여러 개 줘도 된다. 둘을 섞어도 된다.

```bash
# 한 파일에 CA + leaf 들 (--- 구분)
cert-gen apply pki.cnf

# CA 파일 하나 + leaf 파일 여러 개 (각각)
cert-gen apply ca.cnf web.cnf api.cnf

# leaf 파일만 주고 기존 CA 아래로
cert-gen apply web.cnf api.cnf --ca hd-root-ca
```

파일은 명령행 순서대로, 각 파일 안의 블록도 순서대로 처리한다. 즉 CA 파일을 먼저,
그 CA 아래로 발급할 leaf 파일을 뒤에 둔다.

### 한 번에 CA 하나 (1 CA / 1회)

apply 한 번은 **CA 하나만** 다룬다. CA 와 서버·클라이언트 인증서는 **1 : N** 이다 —
CA 하나에 leaf 는 몇 개든 둘 수 있지만, CA 블록이 둘 이상이면 거부한다.

```
CA 생성: hd-root-ca
[1/3] 발급: #1 web.hd.local   (server)
[2/3] 발급: #2 agent.hd.local (client)
[3/3] 발급: #3 both.hd.local  (server+client)
완료: CA hd-root-ca 생성, 인증서 3건 발급.
```

CA 가 둘이면:

```
오류: CA 블록이 2개입니다(…). apply 한 번은 CA 하나만 만듭니다(1 CA / 1회).
      CA 마다 따로 실행하세요
```

이유: 한 번에 여러 CA 를 만들면 "어느 leaf 가 어느 CA 아래인가" 가 파일 순서에 숨어
헷갈리고, CA 생성은 되돌리기 어려운 일이라 한 번에 하나씩 분명히 하는 편이 안전하다.
CA 가 여럿 필요하면 CA 마다 apply 를 따로 돌린다.

leaf 블록·파일의 **순서나 위치는 상관없다.** CA 가 하나뿐이므로 모든 leaf 가 그 아래로
간다(파일에서 leaf 가 CA 보다 먼저 와도 된다).

```
설정 블록 2개:
  [1] CA 생성   HaeDong Root CA (rsa4096, pathlen:0)
  [2] 발급      example.com [server+client] SAN dns:example.com, …
[1/2] CA 생성: haedong-root-ca
[2/2] 발급: #1 example.com (server+client)
완료: CA 1개 생성, 인증서 1건 발급.
```

동작:

- **CA 블록**(`CA:TRUE`) → CA 를 만든다. `default_bits` → 키 알고리즘(4096→rsa4096),
  `pathlen` → pathLenConstraint. CA 키 패스프레이즈는 파일에 두지 않는다 —
  `CERT_GEN_CA_PASSPHRASE` 나 프롬프트로 받는다(`--no-passphrase` 로 생략).
- **leaf 블록**(`CA:FALSE`) → **직전 CA 아래**로 발급한다. 파일에 CA 블록이 없으면
  `--ca <식별자>` 로 지정하거나, 등록된 CA 가 하나뿐이면 그것을 쓴다.
- **멱등성**: 같은 CN 의 CA 가 이미 있으면 다시 만들지 않고 재사용한다. apply 를 다시 돌려도
  CA 가 중복되지 않는다(발급은 매번 새 serial 이라 새로 만들어진다).
- 한 블록이 실패하면 거기서 멈춘다. 그 앞까지 만든 것은 되돌리지 않는다 — CA·인증서는
  그 자체로 쓸 수 있는 산출물이고, 어디까지 됐는지 분명히 보고한다.

확장 처리는 `--config` 와 같다 — DN·SAN 은 그대로, keyUsage/EKU 는 프로필로 통제한다.
단일 leaf 설정 하나만 발급하려면 `cert issue --config <파일>` 을 쓴다.
