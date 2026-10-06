package names

import (
	"strings"
	"testing"
)

// 경계값: 와일드카드 규칙, IDN, CN 자동 포함, 중복 제거.
// 손으로 설정을 쓸 때 가장 많이 틀리는 지점이라 촘촘히 둔다.
func TestParseSAN(t *testing.T) {
	cases := []struct {
		raw       string
		wantType  string
		wantValue string
	}{
		{"a.example.com", TypeDNS, "a.example.com"},
		{"Host.Example.COM.", TypeDNS, "host.example.com"}, // 소문자화 + 끝점 제거
		{"*.example.com", TypeDNS, "*.example.com"},
		{"dns:10.0.0.5", TypeDNS, "10.0.0.5"}, // 접두어가 자동 판별을 이긴다
		{"10.0.0.5", TypeIP, "10.0.0.5"},
		{"2001:db8::1", TypeIP, "2001:db8::1"},
		{"ip:192.168.1.0/24", TypeIP, "192.168.1.0/24"},
		{"admin@example.com", TypeEmail, "admin@example.com"},
		{"https://svc.example.com/x", TypeURI, "https://svc.example.com/x"},
		{"한글.example.com", TypeDNS, "xn--bj0bj06e.example.com"}, // IDNA A-label
	}
	for _, c := range cases {
		got, err := ParseSAN(c.raw)
		if err != nil {
			t.Errorf("ParseSAN(%q) 오류: %v", c.raw, err)
			continue
		}
		if got.Type != c.wantType || got.Value != c.wantValue {
			t.Errorf("ParseSAN(%q) = %s:%s, 기대 %s:%s", c.raw, got.Type, got.Value, c.wantType, c.wantValue)
		}
	}
}

func TestParseSANRejects(t *testing.T) {
	bad := []string{
		"*.com",            // 레이블이 부족한 와일드카드 — 클라이언트가 거부한다
		"*.*.example.com",  // 다중 와일드카드
		"a*b.example.com",  // 레이블 일부만 와일드카드
		"a_b.example.com",  // 밑줄은 LDH 위반
		"-bad.example.com", // 하이픈으로 시작
		"ip:999.1.1.1",
		"",
		strings.Repeat("a", 300) + ".com",
	}
	for _, raw := range bad {
		if _, err := ParseSAN(raw); err == nil {
			t.Errorf("ParseSAN(%q) 가 거부되지 않았다", raw)
		}
	}
}

func TestCNIsAddedToSANFirst(t *testing.T) {
	// CN 만 있는 인증서는 현대 클라이언트가 거부한다. CN 은 항상 SAN 선두에 있어야 한다.
	got, err := BuildSANs("web.example.com", []string{"10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0].Type != TypeDNS || got[0].Value != "web.example.com" {
		t.Fatalf("CN 이 SAN 선두에 없다: %+v", got)
	}
}

func TestNonHostnameCNNotAdded(t *testing.T) {
	// CA 이름처럼 호스트명이 아닌 CN 은 SAN 에 넣지 않는다.
	got, err := BuildSANs("test Root CA", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("호스트명이 아닌 CN 이 SAN 에 들어갔다: %+v", got)
	}
}

func TestBuildSANsDedupesAndSplits(t *testing.T) {
	got, err := BuildSANs("web.example.com", []string{"web.example.com", "10.0.0.5, 10.0.0.5\n10.0.0.6"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"web.example.com", "10.0.0.5", "10.0.0.6"}
	if len(got) != len(want) {
		t.Fatalf("개수 다름: %+v", got)
	}
	for i, w := range want {
		if got[i].Value != w {
			t.Errorf("[%d] = %q, 기대 %q", i, got[i].Value, w)
		}
	}
}

func TestSubjectOrderAndCountry(t *testing.T) {
	name, err := BuildSubject(Subject{
		CommonName: "web.example.com", Organization: "HD", OrganizationalUnit: "Infra",
		Country: "kr", State: "Seoul", Locality: "Gangnam",
	})
	if err != nil {
		t.Fatal(err)
	}
	// RFC4514 순서여야 한다(CN 이 뒤).
	want := "CN=web.example.com,OU=Infra,O=HD,L=Gangnam,ST=Seoul,C=KR"
	if got := DNString(name); got != want {
		t.Errorf("DN = %q, 기대 %q", got, want)
	}

	if _, err := BuildSubject(Subject{CommonName: "x", Country: "KOR"}); err == nil {
		t.Error("3자 국가코드가 통과했다")
	}
	if _, err := BuildSubject(Subject{CommonName: ""}); err == nil {
		t.Error("빈 CN 이 통과했다")
	}
	if _, err := BuildSubject(Subject{CommonName: strings.Repeat("a", 65)}); err == nil {
		t.Error("65자 CN 이 통과했다")
	}
}

func TestSlugifyNeutralizesShellHazards(t *testing.T) {
	// 와일드카드·점이 그대로 파일명에 들어가면 글로빙·숨김파일 사고가 난다.
	if got := Slugify("*.web.example.com", "x"); got != "wildcard-web-example-com" {
		t.Errorf("Slugify = %q", got)
	}
	if got := Slugify("...", "fallback"); strings.HasPrefix(got, ".") {
		t.Errorf("점으로 시작한다: %q", got)
	}
	if got := Slugify("", "fallback"); got != "fallback" {
		t.Errorf("빈 입력에 fallback 이 안 쓰였다: %q", got)
	}
}
