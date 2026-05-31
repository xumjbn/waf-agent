package engine

import (
	"testing"

	"github.com/waf-agent/internal/config"
)

// 一条真实形态的 Coraza(CRS v4) JSON 审计日志：libinjection 命中 SQLi 并拦截。
// 字段名核实自 corazawaf/coraza internal/auditlog/auditlog.go（response.status、
// messages[].data.id / data / tags、transaction.is_interrupted）。
const corazaSQLiLine = `{"transaction":{"timestamp":"02/Jan/2026:15:04:20 +0000","id":"abc123","client_ip":"203.0.113.7","is_interrupted":true,"request":{"method":"GET","uri":"/product?id=1%27%20OR%20%271%27=%271","headers":{"User-Agent":["sqlmap/1.7"],"Host":["shop.example.com"]}},"response":{"status":403},"highest_severity":"critical"},"messages":[{"message":"SQL Injection Attack Detected via libinjection","data":{"id":942100,"msg":"SQL Injection Attack Detected via libinjection","data":"Matched Data: 1' OR '1'='1 found within ARGS:id","tags":["application-multi","language-multi","platform-multi","attack-sqli","paranoia-level/1","OWASP_CRS"],"severity":5}}]}`

func newCaddyTestEngine() *CaddyEngine {
	return NewCaddyEngine(&config.Config{})
}

func TestCaddyParseAuditLine_SQLi(t *testing.T) {
	rec, ok := newCaddyTestEngine().ParseAuditLine([]byte(corazaSQLiLine))
	if !ok {
		t.Fatal("期望解析成功，得到 ok=false")
	}
	if rec.SrcIP != "203.0.113.7" {
		t.Errorf("SrcIP = %q, 期望 203.0.113.7", rec.SrcIP)
	}
	if rec.AttackType != "SQLi" {
		t.Errorf("AttackType = %q, 期望 SQLi（应从 tag attack-sqli 分类）", rec.AttackType)
	}
	if rec.RuleID != "942100" {
		t.Errorf("RuleID = %q, 期望 942100", rec.RuleID)
	}
	if !rec.Blocked || rec.Action != "block" {
		t.Errorf("Blocked=%v Action=%q, 期望 is_interrupted=true → 拦截", rec.Blocked, rec.Action)
	}
	if rec.UserAgent != "sqlmap/1.7" {
		t.Errorf("UserAgent = %q, 期望 sqlmap/1.7（headers 是 map[string][]string）", rec.UserAgent)
	}
	if rec.Method != "GET" || rec.URI == "" {
		t.Errorf("Method=%q URI=%q, 期望 GET + 非空 URI", rec.Method, rec.URI)
	}
}

func TestCaddyParseAuditLine_XSSByTag(t *testing.T) {
	line := `{"transaction":{"client_ip":"198.51.100.9","is_interrupted":false,"request":{"method":"POST","uri":"/comment"},"response":{"status":200}},"messages":[{"message":"XSS Attack Detected","data":{"id":941100,"data":"<script>","tags":["attack-xss"]}}]}`
	rec, ok := newCaddyTestEngine().ParseAuditLine([]byte(line))
	if !ok {
		t.Fatal("期望解析成功")
	}
	if rec.AttackType != "XSS" {
		t.Errorf("AttackType = %q, 期望 XSS", rec.AttackType)
	}
	if rec.Blocked || rec.Action != "log" {
		t.Errorf("Blocked=%v Action=%q, 期望仅记录（未拦截）", rec.Blocked, rec.Action)
	}
}

func TestCaddyParseAuditLine_Skips(t *testing.T) {
	cases := map[string]string{
		"非 JSON 行":        "this is a plain access log line",
		"空 messages（纯访问）": `{"transaction":{"client_ip":"1.2.3.4","request":{"method":"GET","uri":"/"}},"messages":[]}`,
		"无 client_ip":     `{"transaction":{"is_interrupted":true},"messages":[{"message":"x","data":{"id":1}}]}`,
		"空行":              "   ",
	}
	eng := newCaddyTestEngine()
	for name, line := range cases {
		if _, ok := eng.ParseAuditLine([]byte(line)); ok {
			t.Errorf("%s: 期望跳过(ok=false)，却解析成功", name)
		}
	}
}

func TestCaddyExtractDomain(t *testing.T) {
	cases := map[string]string{
		"shop.example.com {\n  reverse_proxy app:8080\n}":         "shop.example.com",
		"# 注释\nhttps://api.example.com {\n  coraza\n}":             "api.example.com",
		"a.example.com, www.a.example.com {\n  reverse_proxy x\n}": "a.example.com",
	}
	for payload, want := range cases {
		if got := caddyExtractDomain([]byte(payload)); got != want {
			t.Errorf("caddyExtractDomain(%q) = %q, 期望 %q", payload, got, want)
		}
	}
}

func TestSumPromMetric(t *testing.T) {
	text := `# HELP caddy_http_requests_total Counter
# TYPE caddy_http_requests_total counter
caddy_http_requests_total{handler="reverse_proxy",server="srv0"} 1200
caddy_http_requests_total{handler="coraza",server="srv0"} 800
caddy_http_requests_total_bytes{server="srv0"} 999999
caddy_http_requests_in_flight{server="srv0"} 3`
	if got := sumPromMetric(text, "caddy_http_requests_total"); got != 2000 {
		t.Errorf("sumPromMetric total = %v, 期望 2000（两 series 求和，且不误吃 _total_bytes）", got)
	}
	if got := sumPromMetric(text, "caddy_http_requests_in_flight"); got != 3 {
		t.Errorf("sumPromMetric in_flight = %v, 期望 3", got)
	}
}
