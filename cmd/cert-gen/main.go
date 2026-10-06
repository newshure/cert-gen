// cert-gen — 자가서명 인증서 생성기 (로컬 CA).
//
// 단일 실행 파일이다. 설치 과정이 없고, 상태는 실행한 디렉터리의 cert-gen-data/ 에 둔다.
package main

import (
	"os"

	"github.com/newshure/cert-gen/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
