#!/usr/bin/env bash
# cert-gen 릴리스 빌드. linux/amd64 와 windows/amd64 바이너리, 그리고 SHA256SUMS 를 만든다.
#
# 빌드를 스크립트로 고정하는 이유가 두 가지다.
#
# 1. 재현 가능해야 한다. -trimpath 와 -buildid= 로 같은 소스가 항상 같은 바이트를 내게
#    한다. 그러면 공개한 해시로 "내가 받은 파일이 그 소스에서 나왔는가" 를 확인할 수 있다.
#
# 2. Windows 바이너리는 백신 오탐을 줄이는 처리가 필요하다. 아래 주석 참조.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
VERSION=${VERSION:-0.1.0}
OUT=${OUT:-$ROOT/dist}
PKG=./cmd/cert-gen
LDPATH=github.com/newshure/cert-gen/internal/cli.Version

command -v go >/dev/null || { echo "go 를 찾을 수 없습니다. PATH 를 확인하세요." >&2; exit 69; }

# 릴리스 빌드는 깨끗한 트리에서만 의미가 있다. Go 는 바이너리에 git 커밋을 새기고
# (vcs.revision/vcs.time), 트리가 더러우면 vcs.modified=true 와 +dirty 를 붙인다.
# 그 상태로 배포하면 "이 바이너리가 어느 소스에서 나왔는가" 를 답할 수 없다.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "경고: 작업 트리가 깨끗하지 않습니다. 바이너리에 +dirty 가 찍힙니다." >&2
  echo "      릴리스라면 커밋한 뒤 다시 빌드하세요. (ALLOW_DIRTY=1 로 무시)" >&2
  if [ -z "${ALLOW_DIRTY:-}" ]; then
    git status --short >&2
    exit 2
  fi
fi

mkdir -p "$OUT"
rm -f "$OUT"/cert-gen "$OUT"/cert-gen.exe "$OUT"/SHA256SUMS

# --- Linux -------------------------------------------------------------------
# 심볼을 떼어 낸다(-s -w). 리눅스에서는 오탐 문제가 사실상 없고 크기가 3MB 가까이 줄어든다.
echo "==> linux/amd64"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -ldflags "-s -w -buildid= -X $LDPATH=$VERSION" \
  -o "$OUT/cert-gen" "$PKG"

# --- Windows -----------------------------------------------------------------
# 백신 오탐(Defender 의 Wacatac/Wacapew 계열 ML 판정)을 줄이기 위해 두 가지를 다르게 한다.
#
# (a) 버전 리소스(VERSIONINFO)를 넣는다. Go 는 기본적으로 .rsrc 섹션이 없는 맨 PE 를
#     만드는데, 정상 소프트웨어는 거의 예외 없이 회사명·제품명·설명을 담고 있다. 이것이
#     없는 것 자체가 휴리스틱 점수를 올린다. goversioninfo 가 .syso 를 만들어 주고
#     링커가 집어넣는다. 파일명을 _windows_amd64 로 두어 리눅스 빌드에는 섞이지 않게 한다.
#
# (b) 심볼을 떼지 않는다(-s -w 없음). 스트립된 바이너리는 분석을 방해하려는 신호로 읽혀
#     점수가 올라가고, 오탐 신고를 받은 분석자가 들여다볼 단서도 사라진다. 2~3MB 를 더
#     쓰더라도 남겨 두는 편이 낫다.
#
# 근본 해결은 Authenticode 서명이다. 아래 SIGN_PFX 참조.
echo "==> windows/amd64"
SYSO="$ROOT/cmd/cert-gen/resource_windows_amd64.syso"
if command -v goversioninfo >/dev/null; then
  goversioninfo -o "$SYSO" \
    -platform-specific=false \
    -product-version "$VERSION" -file-version "$VERSION" \
    "$ROOT/deploy/windows/versioninfo.json"
else
  echo "   경고: goversioninfo 가 없어 버전 리소스를 넣지 못합니다(오탐 가능성 증가)." >&2
  echo "   설치: go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest" >&2
fi
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
  -trimpath -ldflags "-buildid= -X $LDPATH=$VERSION" \
  -o "$OUT/cert-gen.exe" "$PKG"
rm -f "$SYSO"

# --- Authenticode 서명 (선택) -------------------------------------------------
# SIGN_PFX 에 코드서명 인증서(.pfx) 경로를 주면 서명한다. 비밀번호는 argv 로 받지 않고
# SIGN_PFX_PASSWORD 환경변수에서 읽는다.
#
# 사설 CA 로 발급한 코드서명 인증서도 쓸 수 있다. 단, 그 CA 를 각 Windows 의
# "신뢰할 수 있는 루트 인증 기관" 과 "신뢰할 수 있는 발행자" 에 등록해야 효력이 있다
# (GPO 로 배포하면 된다). 인터넷 공개 배포라면 공인 코드서명 인증서가 필요하다.
if [ -n "${SIGN_PFX:-}" ]; then
  if command -v osslsigncode >/dev/null; then
    echo "==> Authenticode 서명"
    osslsigncode sign -pkcs12 "$SIGN_PFX" -readpass /dev/stdin \
      -n "cert-gen" -i "https://theknowledges.net" \
      -ts http://timestamp.digicert.com \
      -in "$OUT/cert-gen.exe" -out "$OUT/cert-gen-signed.exe" \
      <<< "${SIGN_PFX_PASSWORD:-}"
    mv "$OUT/cert-gen-signed.exe" "$OUT/cert-gen.exe"
  else
    echo "   경고: osslsigncode 가 없어 서명을 건너뜁니다." >&2
  fi
fi

# --- 해시 --------------------------------------------------------------------
# 받은 쪽이 파일 무결성을 확인할 수 있게 공개한다. 백신 오탐 신고 때도 이 해시를 쓴다.
cd "$OUT"
sha256sum cert-gen cert-gen.exe > SHA256SUMS
echo
echo "완료: $OUT"
ls -lh cert-gen cert-gen.exe
echo
cat SHA256SUMS
echo
# 바이너리에 새겨진 출처. 받은 쪽이 'go version -m <파일>' 로 같은 값을 읽을 수 있다.
echo "출처(바이너리에 새겨짐):"
go version -m cert-gen | grep -E "vcs\.(revision|time|modified)" | sed "s/^/  /"
