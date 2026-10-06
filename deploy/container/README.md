# 컨테이너로 실행

cert-gen 은 설치가 필요 없는 단일 실행 파일이므로 컨테이너가 필수는 아니다. 그래도
이미지를 두는 이유는 두 가지다. (a) 클러스터 안에서 Job·CronJob 으로 인증서를 발급하는
경우, (b) 호스트에 바이너리를 두지 않는 정책이 있는 경우.

## 빌드

```bash
bash deploy/container/build.sh          # 바이너리가 없으면 먼저 빌드한다
```

이미지 빌드 중에는 네트워크를 쓰지 않는다. 컴파일은 호스트에서 끝내고 결과물만 COPY 한다.

## 실행

상태 디렉터리를 볼륨으로 둔다. 그러지 않으면 컨테이너가 사라질 때 **CA 개인키도 사라진다.**

```bash
podman volume create certgen-data

# 초기화 → CA 생성 → 발급
podman run --rm -v certgen-data:/var/lib/cert-gen IMAGE init
podman run --rm -v certgen-data:/var/lib/cert-gen \
  -e CERT_GEN_CA_PASSPHRASE \
  IMAGE ca create --cn "HD Root CA" --org HaeDong
podman run --rm -v certgen-data:/var/lib/cert-gen \
  -e CERT_GEN_CA_PASSPHRASE \
  IMAGE cert issue --cn web.hd.local --san ip:10.0.0.5

# TUI 는 TTY 가 필요하다
podman run --rm -it -v certgen-data:/var/lib/cert-gen IMAGE tui
```

패스프레이즈는 `-e CERT_GEN_CA_PASSPHRASE` 로 **값 없이** 넘긴다(호스트의 같은 이름
변수를 전달한다). `-e NAME=value` 로 쓰면 그 값이 `podman inspect` 와 셸 이력에 남는다.

## 산출물 꺼내기

발급 결과는 볼륨 안에 있다. 꺼낼 때는 출력 디렉터리를 따로 마운트한다.

```bash
podman run --rm \
  -v certgen-data:/var/lib/cert-gen \
  -v "$PWD/out:/out:Z" \
  IMAGE cert bundle 1 -o /out
```

## 주의

- 이미지에 CA 키를 담지 않는다. 볼륨에만 둔다. 이미지에 담으면 레지스트리에 CA 가 올라간다.
- `USER certgen`(UID 10001)로 돌린다. 볼륨 권한이 맞지 않으면 호스트에서
  `chown 10001:10001` 로 맞춘다.
- Kubernetes 에서 쓸 때는 상태를 PVC 에 둔다. 영속 데이터이므로 **retain 계열 StorageClass**(삭제돼도 볼륨이 남는)를 쓴다 — CA 를 잃으면 발급한 인증서 전부를 다시 만들어야 한다.
