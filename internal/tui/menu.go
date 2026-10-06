package tui

// 좌측 최상위 메뉴. 사용자가 지정한 구조 그대로다.
//
//	0. 개인키 생성·관리
//	1. rootCA 생성
//	2. 인증서 발급        CA 선택 → ① 이력 기반 ② rootCA 디렉터리 입력
//	3. 인증서 변환        대상 → ① 발급 이력 ② 외부 파일
//	4. 발급 이력·만료 조회
//	5. 서버에 CA 신뢰 등록
//	6. 백업 · 복원          (사용자 지정 5개 뒤에 덧붙였다)
//
// 숫자키로 바로 이동할 수 있게 번호를 고정한다. 순서를 바꾸면 손에 익은 번호가 달라지므로
// 항목을 추가할 때도 기존 번호는 유지한다.

type screenID int

const (
	screenKeys screenID = iota
	screenCACreate
	screenIssue
	screenConvert
	screenHistory
	screenTrust
	screenBackup
	screenCount
)

type menuItem struct {
	id    screenID
	num   rune
	label string
	// hint 는 그 화면이 무엇을 하는지 한 줄 설명이다.
	hint string
}

var menuItems = []menuItem{
	{screenKeys, '0', "개인키 생성·관리", "키를 먼저 만들어 두고 CA·발급에서 고른다"},
	{screenCACreate, '1', "rootCA 생성", "로컬 Root CA 를 만든다"},
	{screenIssue, '2', "인증서 발급", "CA 를 골라 서버·클라이언트 인증서를 발급한다"},
	{screenConvert, '3', "인증서 변환", "PKCS#12 · JKS · DER · K8s Secret 으로 바꾼다"},
	{screenHistory, '4', "발급 이력·만료 조회", "발급 목록, 만료 임박, 검증·갱신·폐기"},
	{screenTrust, '5', "서버에 CA 신뢰 등록", "OS · Java 신뢰 저장소 등록 명령을 만든다"},
	{screenBackup, '6', "백업 · 복원", "상태 디렉터리 전체를 묶고 되돌린다"},
}

func menuIndexOf(id screenID) int {
	for i, item := range menuItems {
		if item.id == id {
			return i
		}
	}
	return 0
}
