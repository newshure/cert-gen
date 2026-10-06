#!/usr/bin/env bash
# cert-gen 컨테이너 이미지 빌드.
#
# 바이너리를 먼저 만든다. 이미지 빌드 중에는 컴파일하지 않는다 — 폐쇄망에서 Go 모듈을
# 받을 수 없고, 빌드 캐시도 호스트에 두는 편이 빠르다.
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$(pwd)
VERSION=${VERSION:-0.1.0}
DATE=$(date +%Y%m%d)
# 폐쇄망이면 내부 레지스트리로: REGISTRY=registry.example.com bash deploy/container/build.sh
REGISTRY=${REGISTRY:-registry.example.com}
IMAGE=${IMAGE:-$REGISTRY/library/cert-gen/cert-gen}
BASE_IMAGE=${BASE_IMAGE:-rockylinux:9}

ENGINE=${ENGINE:-}
if [ -z "$ENGINE" ]; then
  for candidate in podman docker nerdctl; do
    if command -v "$candidate" >/dev/null; then ENGINE=$candidate; break; fi
  done
fi
[ -n "$ENGINE" ] || { echo "podman·docker·nerdctl 중 하나가 필요합니다." >&2; exit 69; }

if [ ! -x "$ROOT/dist/cert-gen" ]; then
  echo "==> 바이너리가 없어 먼저 빌드합니다"
  VERSION="$VERSION" bash deploy/build.sh
fi

TAG="$VERSION-$DATE"
echo "==> $ENGINE build ($IMAGE:$TAG)"
"$ENGINE" build \
  --build-arg "BASE_IMAGE=$BASE_IMAGE" \
  -f deploy/container/Dockerfile \
  -t "$IMAGE:$TAG" -t "$IMAGE:latest" \
  "$ROOT"

echo
echo "==> 확인"
"$ENGINE" run --rm "$IMAGE:$TAG" --version

echo
echo "완료: $IMAGE:$TAG (latest 동시 태깅)"
echo
echo "push 는 요청이 있을 때만 합니다:"
echo "  $ENGINE push $IMAGE:$TAG"
echo "  $ENGINE push $IMAGE:latest"
