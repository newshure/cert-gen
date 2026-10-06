# 빠른 시작

## 0. 설치 확인

```bash
cert-gen doctor
```

`data_dir 권한`이 FAIL 이면 `cert-gen init` 을 다시 실행한다(0750 으로 조인다).
`openssl`·`keytool` 은 선택 항목이며 없으면 해당 기능만 비활성화된다.

## 1. rootCA 만들기

```bash
cert-gen ca create --cn "hd Root CA" --o HD --c KR
```

- CN 은 호스트명이 아니라 **조직을 알아볼 수 있는 이름**으로 둔다. 클라이언트의 신뢰 저장소
  목록에 이 이름이 보인다.
- 패스프레이즈를 두 번 입력한다. 앱 인증이 없으므로 이것이 사실상 유일한 서명 권한 통제다.
- 기본 키는 `ec-p384`, 유효기간 10년이다.

### 이미 쓰고 있는 CA 가 있다면

두 가지 방법이 있다.

| 방법 | 명령 | 개인키 위치 |
|---|---|---|
| 그 자리에서 쓰기 | `cert-gen ca adopt --dir /srv/pki/mycorp` | 원래 디렉터리에 그대로 |
| cert_gen 이 소유 | `cert-gen ca import --key ca.key --cert ca.crt` | `data_dir` 로 복사 |

`adopt` 는 발급할 때마다 그 디렉터리가 있어야 한다. 원본을 치울 계획이면 `import` 를 쓴다.
`cert issue --ca-dir <경로>` 로 바로 발급하면 `adopt` 가 자동으로 일어난다.

## 2. 서버 인증서 발급

```bash
cert-gen cert issue --ca hd-root-ca --cn web.example.com --o HD \
  --san 10.0.0.5 --san '*.web.example.com'
```

- CN 은 자동으로 SAN 에 들어간다. 따로 `--san web.example.com` 을 쓸 필요가 없다.
- `--san` 의 타입은 값에서 판별된다. 명시하려면 `dns:`/`ip:`/`uri:`/`email:` 접두어를 쓴다.
- 와일드카드는 `*.example.com` 형태만 된다(레이블 하나만 대체). `*.com` 은 거부된다.
- 셸에서 `*` 는 반드시 따옴표로 감싼다.

클라이언트 인증서(mTLS)는 `--profile client`, 양쪽에 쓰려면 `--profile server+client`.

## 3. 서버에 적용

```bash
cert-gen cert bundle 1 -o /etc/nginx/tls
```

```
privkey.pem     개인키 (0600)
cert.pem        이 서비스의 인증서
fullchain.pem   cert + 상위 체인  ← 서버 설정에는 보통 이것을 쓴다
ca.crt          Root CA           ← 클라이언트에 신뢰 등록할 대상
metadata.json   DN·SAN·유효기간·지문
USAGE.txt       적용 예시
```

nginx:

```nginx
ssl_certificate     /etc/nginx/tls/fullchain.pem;
ssl_certificate_key /etc/nginx/tls/privkey.pem;
```

`privkey.pem` 은 root 소유 0600 으로 둔다.

## 4. 클라이언트에 CA 신뢰 등록

자가서명 체인은 이 단계를 하지 않으면 동작하지 않는다.

```bash
cert-gen ca export hd-root-ca -o ./trust   # ca.crt 를 꺼낸다
```

| 대상 | 명령 |
|---|---|
| Rocky / RHEL | `sudo cp ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust` |
| Debian / Ubuntu | `sudo cp ca.crt /usr/local/share/ca-certificates/ca.crt && sudo update-ca-certificates` |
| Windows | `certutil -addstore -f Root ca.crt` |
| Java | `keytool -importcert -trustcacerts -alias cert-gen-ca -file ca.crt -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit` |
| curl | `curl --cacert ca.crt https://web.example.com/` |
| Python requests/httpx | `export REQUESTS_CA_BUNDLE=/path/to/ca.crt` |
| Node.js | `export NODE_EXTRA_CA_CERTS=/path/to/ca.crt` |

컨테이너 안에서 쓸 때는 이미지에 `ca.crt` 를 넣고 위 명령을 Dockerfile 에서 실행하거나,
K8s 에서는 ConfigMap 으로 마운트한 뒤 신뢰 등록한다.

## 5. 확인

```bash
cert-gen cert verify 1 --hostname web.example.com
```

```
[ OK ] 유효기간: 396일 남음
[ OK ] CA 유효기간: 만료 2036-09-28Z
[ OK ] 체인 검증: serverAuth 경로 검증 통과
[ OK ] 호스트명 매칭: web.example.com == SAN DNS:web.example.com
[ OK ] openssl 교차 확인: OK
[ OK ] 폐기 상태: 폐기되지 않음
[ OK ] 키-인증서 짝: 일치
```

실제 서버에 붙여 확인하려면:

```bash
openssl s_client -connect web.example.com:443 -CAfile ca.crt -servername web.example.com </dev/null
# 끝에 "Verify return code: 0 (ok)" 가 나와야 한다
```

## 6. 운영

```bash
cert-gen cert list --expiring-in 30     # 만료 임박 점검 (cron 에 걸어 두면 좋다)
cert-gen cert renew 1                   # 새 키로 재발급
cert-gen backup create                  # CA 개인키 포함. 0600
```

만료 점검을 자동화하는 예:

```bash
# /etc/cron.d/cert-gen-expiry
0 9 * * 1 certgen /usr/local/bin/cert-gen --json cert list --expiring-in 30 | \
  grep -q '"id"' && echo "만료 임박 인증서가 있습니다: cert-gen cert list --expiring-in 30"
```

## 터미널 UI

```bash
cert-gen tui
```

| 키 | 동작 |
|---|---|
| `1`~`4` | 작업 이동 (입력 필드에 포커스가 없을 때) |
| `Esc` | 뒤로 / 모달 닫기 |
| `F5` | 새로고침 |
| `q` | 종료 |

각 화면 하단에 등가 CLI 명령이 표시된다.
