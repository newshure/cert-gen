# 설치

설치 과정이 없다. 바이너리 하나를 받아서 실행하면 된다.

| 항목 | 내용 |
|---|---|
| 런타임 요구사항 | **없음.** 정적 링크(`CGO_ENABLED=0`)라 glibc 의존조차 없다 |
| 지원 OS | RHEL 계열 8·9·10, Debian 12·13, Ubuntu 22·24, Windows 10/11·Server 2019+ |
| 선택 의존성 | `openssl` — 교차 검증용. 없으면 그 검사만 건너뛴다 |

**JDK·keytool 은 필요하지 않다.** PKCS#12·JKS·CRL 을 모두 직접 만든다.

---

## 1. 받아서 실행

```bash
chmod +x cert-gen
./cert-gen --version
./cert-gen where          # 상태 디렉터리가 어디에 생기는지 먼저 확인한다
./cert-gen init
```

Windows:

```powershell
.\cert-gen.exe where
.\cert-gen.exe init
```

바이너리를 PATH 에 두고 싶으면 그냥 복사한다. 설치 스크립트가 필요 없다.

```bash
sudo install -m 0755 cert-gen /usr/local/bin/cert-gen
```

---

## 2. 상태 디렉터리

CA 개인키·인증서·발급 이력이 들어가는 곳이다. **이 디렉터리가 곧 CA 다.**

위치를 정하는 규칙은 세 가지뿐이다(위에서부터 우선).

```
1. cert-gen --data-dir <경로> <명령>
2. 환경변수 CERT_GEN_DATA_DIR
3. <현재 디렉터리>/cert-gen-data        ← 기본값. Windows·리눅스가 같다
```

찾아 올라가지 않는다. 규칙이 하나뿐이어야 "어디에 생기는지" 가 분명하다.
지금 어디를 쓰는지는 `cert-gen where` 가 알려 준다.

```bash
# 한곳에 고정해 두기
export CERT_GEN_DATA_DIR=/srv/pki/cert-gen-data     # Windows: set CERT_GEN_DATA_DIR=...
cert-gen init
```

`init` 이 만드는 것:

```
<상태 디렉터리>/
├── cert-gen.sqlite3     0600   발급 이력·serial
├── config.toml                 설정 (없어도 기본값으로 동작한다)
├── ca/<slug>/ca.key     0600   CA 개인키  ← 이 파일이 CA 다
├── ca/<slug>/ca.crt     0644
├── keys/<이름>.key      0600   미리 만들어 둔 개인키
├── bundles/<연도>/*.zip 0600   발급 결과
├── crl/<slug>.crl       0644
├── backups/*.tar.gz     0600   백업 (CA 키 포함)
└── tmp/                        원자적 쓰기용
```

디렉터리 자체는 `0750` 이다. 여러 사람이 쓰는 호스트라면 전용 계정을 만들고 그 계정
소유로 두는 편이 안전하다.

```bash
sudo useradd -r -M -d /srv/pki -s /sbin/nologin certgen
sudo install -d -m 0750 -o certgen -g certgen /srv/pki
sudo -u certgen env CERT_GEN_DATA_DIR=/srv/pki/cert-gen-data cert-gen init
```

---

## 3. 설정

설정 파일은 **상태 디렉터리 안**에 `config.toml` 로 둔다. 없어도 동작한다.

```bash
cp deploy/config.example.toml "$CERT_GEN_DATA_DIR/config.toml"
```

상태 디렉터리 경로는 설정에 없다. 설정 파일이 그 안에 있으므로 순환이 된다.

개별 값은 환경변수로 덮어쓸 수 있다: `CERT_GEN_<섹션>_<키>`

```bash
CERT_GEN_CERT_DEFAULT_DAYS=90 cert-gen cert issue --cn web.hd.local
```

모르는 키·섹션은 조용히 무시하지 않고 **오류로 거부한다**(오타 방지).

---

## 4. 직접 빌드

Go 1.26 이상이 필요하다. 빌드 호스트에만 필요하고 실행 호스트에는 필요 없다.

```bash
bash deploy/build.sh                 # dist/cert-gen, dist/cert-gen.exe, SHA256SUMS
VERSION=0.2.0 bash deploy/build.sh
```

빌드는 재현 가능하다(`-trimpath -buildid=`). 깨끗한 트리에서만 빌드한다
(`ALLOW_DIRTY=1` 로 무시할 수 있지만 릴리스에는 쓰지 않는다).

바이너리에 git 커밋이 새겨지므로 받은 파일의 출처를 확인할 수 있다.

```bash
go version -m cert-gen
#   build  vcs.revision=<커밋>
#   build  vcs.modified=false      ← false 여야 한다
```

Windows 바이너리는 백신 오탐을 줄이기 위해 버전 리소스를 넣고 심볼을 남긴다.
`SIGN_PFX` 를 주면 Authenticode 서명도 한다. → `docs/manual/antivirus.md`

---

## 5. 컨테이너

설치가 필요 없으므로 필수가 아니다. 클러스터 안에서 Job·CronJob 으로 발급하거나,
호스트에 바이너리를 두지 않는 정책이 있을 때만 쓴다.

```bash
bash deploy/container/build.sh
```

상태 디렉터리를 반드시 볼륨으로 둔다. 그러지 않으면 컨테이너가 사라질 때 CA 개인키도
사라진다. → `deploy/container/README.md`

---

## 6. 확인

```bash
cert-gen where
cert-gen ca create --cn "HD Root CA" --org HaeDong --country KR
cert-gen cert issue --cn web.hd.local --san ip:10.0.0.5 -o ./out
cert-gen cert verify 1
```

`cert verify` 가 항목별로 결과를 낸다. `openssl` 이 있으면 교차 검증 항목도 함께 나오고,
없으면 그 항목만 `[건너뜀]` 이 된다.

다음: `docs/manual/quickstart.md`
