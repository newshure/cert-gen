# 백업과 복원

## 먼저 알아야 할 것

**백업 파일은 CA 개인키를 포함한다. 즉 파일 하나가 CA 그 자체다.**
이 파일을 가진 사람은 (패스프레이즈를 안다면) 무엇이든 발급할 수 있다.

- 생성되는 파일 권한은 `0600` 이다.
- 외부로 옮길 때는 **별도 암호화가 필요하다**(예: `gpg -c`).
- 백업 보관 위치를 CA 운영 호스트와 분리한다.

## 백업

```bash
cert-gen backup create                       # 기본 위치(data_dir/backups)
cert-gen backup create -o /srv/backup/cert-gen-20261001.tar.gz
```

담기는 것:

| 내용 | 비고 |
|---|---|
| `cert-gen.sqlite3` | 발급 이력·serial·감사 로그. **온라인 일관 스냅샷** |
| `ca/<slug>/` | cert_gen 이 소유한 CA 의 개인키·인증서 |
| `bundles/` | 발급한 인증서 zip 번들 (개인키 포함) |
| `crl/` | 생성한 CRL |
| `MANIFEST.json` | 스키마 버전, 생성 시각, 멤버별 sha256 |

DB 를 파일 복사가 아니라 `sqlite3` 의 온라인 백업으로 뜬다. WAL 모드에서 `.sqlite3` 파일만
복사하면 `-wal` 에 있는 최신 커밋이 빠진 반쪽 스냅샷이 된다.

### 담기지 않는 것: 외부 CA 의 개인키

`ca adopt` / `cert issue --ca-dir` 로 등록한 외부 CA 는 개인키가 `data_dir` 밖에 있고,
cert_gen 은 그것을 복사하지 않는다는 약속을 백업에서도 지킨다.

백업 생성 시 해당 CA 의 경로를 출력하고 `MANIFEST.json` 에도 기록하므로, 그 키는 **따로
챙겨야 한다**. 챙기지 않으면 복원 후 그 CA 로 발급할 수 없다(이력 조회는 된다).

## 복원

### 드라이런 먼저

```bash
cert-gen backup restore /srv/backup/cert-gen-20261001.tar.gz --dry-run
```

```
복원 계획: ...
  백업 생성             : 2026-10-01T06:00:00Z
  백업의 CA             : 2
  백업의 인증서          : 12
  새로 생김              : 0
  덮어씀                : 15
  백업에 없는 현재 파일   : 3
```

드라이런은 **전체 무결성까지 검사한다**(멤버별 sha256). 해시 검사를 복원 시점으로 미루면
이미 파일을 쓰기 시작한 뒤에 실패해 반쪽 복원이 되기 때문이다. 손상·변조된 백업은 여기서 걸린다.

### 실제 복원

```bash
cert-gen backup restore /srv/backup/cert-gen-20261001.tar.gz
```

복원 순서는 이렇다.

```
검증 → 임시 위치에 전개 → 기존 것을 옆으로 치움 → 제자리로
```

기존 상태 디렉터리는 **지우지 않고 옮긴다**(`<상태 디렉터리>.bak-<타임스탬프>`).
마지막 단계가 실패하면 치워 둔 것을 되돌린다. 전개를 먼저 끝내고 기존 것을 치우는 이유는,
반대 순서로 하다 전개가 실패하면 양쪽을 다 잃기 때문이다.

복원 후 DB 가 실제로 열리는지 확인하고, 문제가 없으면 보관된 디렉터리를 지운다.

```bash
cert-gen doctor
cert-gen cert list
rm -rf ./cert-gen-data.bak-20261001-060000
```

### 다른 호스트로 옮기기

```bash
# 원래 호스트
sudo -u certgen cert-gen backup create -o /tmp/move.tar.gz
gpg -c /tmp/move.tar.gz && shred -u /tmp/move.tar.gz
scp /tmp/move.tar.gz.gpg new-host:/tmp/

# 새 호스트 (설치 과정이 없다 — 바이너리만 두면 된다)
sudo install -m 0755 cert-gen /usr/local/bin/cert-gen
gpg -d /tmp/move.tar.gz.gpg > /tmp/move.tar.gz
sudo -u certgen cert-gen backup restore /tmp/move.tar.gz --dry-run
sudo -u certgen cert-gen backup restore /tmp/move.tar.gz
shred -u /tmp/move.tar.gz /tmp/move.tar.gz.gpg
```

외부 CA 를 쓰고 있었다면 그 디렉터리도 새 호스트의 **같은 경로**에 두어야 한다
(경로가 달라지면 `cert issue --ca-dir <새 경로>` 로 한 번 지정하면 기록이 갱신된다).

## 복원되지 않는 것

| 항목 | 이유 | 대응 |
|---|---|---|
| 외부 CA 개인키 | `data_dir` 밖이라 담지 않는다 | 따로 백업하고 같은 경로에 둔다 |
| `/etc/cert-gen/config.toml` | 호스트 설정이라 담지 않는다 | 설치 스크립트가 다시 만든다. 수정했다면 따로 보관 |
| CA 패스프레이즈 | 저장하지 않는다 | 비밀 관리 체계에 따로 보관 |

**패스프레이즈를 잃으면 CA 키를 복구할 수 없다.** 백업만으로는 부족하다.

## 점검 주기 제안

| 주기 | 할 일 |
|---|---|
| CA 생성·변경 직후 | `backup create` |
| 매주 | `cert list --expiring-in 30` |
| 매월 | `backup create` + 다른 호스트에서 `restore --dry-run` 으로 복원 가능성 확인 |

복원을 한 번도 해 보지 않은 백업은 백업이 아니다. 임시 `--data-dir` 로 실제 복원까지
해 보는 것을 권한다.

```bash
cert-gen --data-dir /tmp/restore-test backup restore <백업> --yes
cert-gen --data-dir /tmp/restore-test cert list
rm -rf /tmp/restore-test
```
