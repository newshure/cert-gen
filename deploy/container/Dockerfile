# cert-gen 컨테이너 이미지.
#
# 바이너리 하나를 COPY 하는 것이 전부다. 폐쇄망에서 빌드할 수 있어야 하므로 빌드 중에
# 네트워크를 쓰지 않는다 — 컴파일은 호스트에서 deploy/build.sh 로 미리 하고, 여기서는
# 결과물만 담는다(워크스페이스 규칙: "Simply COPY $EDITED_CODE /PATH/TO/TARGET").
#
# 빌드:
#   bash deploy/build.sh                 # dist/cert-gen 생성
#   bash deploy/container/build.sh       # 이미지 생성
#
# 베이스 이미지는 폐쇄망에 이미 반입된 완성형 이미지를 쓴다. ARG 로 바꿀 수 있다.
# 폐쇄망이면 반입해 둔 내부 레지스트리 이미지로 바꾼다: --build-arg BASE_IMAGE=...
ARG BASE_IMAGE=rockylinux:9
FROM ${BASE_IMAGE}

# 바이너리는 정적 링크(CGO_ENABLED=0)라 런타임 의존이 없다.
# openssl 은 교차 검증에만 쓰이고 없어도 발급·변환은 동작한다. 베이스에 있으면 그대로 쓴다.
COPY dist/cert-gen /usr/local/bin/cert-gen

# 전용 계정으로 돌린다. CA 개인키를 다루므로 root 로 띄울 이유가 없다.
# UID 를 고정해 두면 볼륨 권한을 호스트에서 미리 맞출 수 있다.
ARG UID=10001
ARG GID=10001
RUN set -eu; \
    groupadd -g "${GID}" certgen 2>/dev/null || true; \
    useradd -u "${UID}" -g "${GID}" -M -d /var/lib/cert-gen -s /sbin/nologin certgen 2>/dev/null || true; \
    install -d -m 0750 -o certgen -g certgen /var/lib/cert-gen; \
    chmod 0755 /usr/local/bin/cert-gen

# 상태 디렉터리. cert-gen 은 기본적으로 **실행한 디렉터리**에 cert-gen-data/ 를 만들지만,
# 컨테이너에서는 경로가 분명해야 하므로 환경변수로 고정한다.
ENV CERT_GEN_DATA_DIR=/var/lib/cert-gen/cert-gen-data
VOLUME /var/lib/cert-gen

USER certgen
WORKDIR /var/lib/cert-gen

# 기본은 CLI 다. TUI 는 TTY 가 필요하므로 -it 로 명시해 띄운다.
#   podman run --rm -v certgen-data:/var/lib/cert-gen <image> cert list
#   podman run --rm -it -v certgen-data:/var/lib/cert-gen <image> tui
ENTRYPOINT ["/usr/local/bin/cert-gen"]
CMD ["--help"]
