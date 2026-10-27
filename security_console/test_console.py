#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
보안 콘솔 자동 시험.  실행:  python3 test_console.py

하는 일: 임시 폴더에 샘플 데이터를 복사하고, 서버를 따로 띄운 뒤 사람이 브라우저에서 하는 동작
(로그인 → 목록 → 상세 → 승인/거절/오탐 → 보고서)을 코드로 대신 해 보고 결과가 맞는지 확인한다.
원래 data/ 폴더나 sample_data/ 는 건드리지 않는다.
"""
import hashlib, http.server, json, os, re, shutil, socket, subprocess, sys, tempfile, threading, time
import http.client
from urllib.parse import urlencode

HERE = os.path.dirname(os.path.abspath(__file__))
PW = "test-password-123"
passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(("  통과  " if cond else "  실패  ") + name + ((" → " + str(extra)) if (extra and not cond) else ""))


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Client:
    """브라우저 흉내: 쿠키를 기억하고, 리다이렉트는 따라가지 않고 그대로 돌려준다."""
    def __init__(self, port): self.port, self.cookie, self.csrf = port, "", ""

    def req(self, method, path, form=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        headers = {"Cookie": self.cookie} if self.cookie else {}
        body = None
        if form is not None:
            body = urlencode(form); headers["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, path, body, headers)
        r = c.getresponse(); data = r.read().decode("utf-8", "replace")
        sc = r.getheader("Set-Cookie")
        if sc and sc.startswith("sid="): self.cookie = sc.split(";")[0]
        res = (r.status, data, dict(r.getheaders())); c.close(); return res

    def login(self, name="tester", pw=PW):
        return self.req("POST", "/login", {"username": name, "password": pw})

    def page_csrf(self):
        _, html, _ = self.req("GET", "/")
        self.csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1); return self.csrf

    def post(self, path, **kw):
        kw.setdefault("csrf", self.csrf); return self.req("POST", path, kw)


def start_server(tmp, extra_cfg=None, name="cfg.json"):
    port = free_port()
    cfg = {"host": "127.0.0.1", "port": port, "log_path": os.path.join(tmp, "app.log"),
           "detections_path": os.path.join(tmp, "detections.json"), "resigned_path": os.path.join(tmp, "resigned.json"),
           "data_dir": os.path.join(tmp, "data_" + name), "dry_run": True, "ai_enabled": False}
    cfg.update(extra_cfg or {})
    cp = os.path.join(tmp, name); json.dump(cfg, open(cp, "w"))
    env = dict(os.environ, CONSOLE_CONFIG=cp); env.pop("ANTHROPIC_API_KEY", None)
    subprocess.run([sys.executable, os.path.join(HERE, "app.py"), "--add-admin", "tester"], input=PW + "\n" + PW + "\n",
                   text=True, env=env, capture_output=True, check=True)
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "app.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(50):
        try: socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); break
        except OSError: time.sleep(0.1)
    return proc, port, cfg


def sha(path): return hashlib.sha256(open(path, "rb").read()).hexdigest()


def main():
    tmp = tempfile.mkdtemp(prefix="console_test_")
    for f in ("app.log", "detections.json", "resigned.json"):
        shutil.copy(os.path.join(HERE, "sample_data", f), os.path.join(tmp, f))
    # 시험용 잘못된 데이터: 옛 칸 이름(id/time/score), 점수 범위 밖, <script> 가 든 규칙 이름
    det = json.load(open(os.path.join(tmp, "detections.json"), encoding="utf-8"))
    det.append({"id": "EVT-010", "time": "2026-11-02 04:00:00", "rule": "<script>alert(1)</script>", "event_type": "MALICIOUS_IP",
                "user": "emp6", "src_ip": "192.168.30.15", "score": 40, "evidence": ["2026-11-02 04:00:00"]})
    det.append({"event_id": "BAD-1", "detected_at": "x", "rule": "r", "event_type": "t", "user": "u", "src_ip": "999.1.1.1", "risk_score": 50})
    det.append({"event_id": "BAD-2", "detected_at": "x", "rule": "r", "event_type": "t", "user": "u", "src_ip": "1.1.1.1", "risk_score": 500})
    json.dump(det, open(os.path.join(tmp, "detections.json"), "w", encoding="utf-8"), ensure_ascii=False)
    log_hash_before = sha(os.path.join(tmp, "app.log"))

    proc, port, cfg = start_server(tmp)
    try:
        print("[1] 접근 제어")
        c = Client(port)
        st, _, _ = c.req("GET", "/"); check("로그인 없이 목록 접근 → 로그인으로 이동", st == 303)
        st, _, _ = c.req("GET", "/event/EVT-001"); check("로그인 없이 상세 접근 → 이동", st == 303)
        st, _, h = c.login(pw="틀린비번"); check("틀린 비밀번호 → 401", st == 401)
        st, _, h = c.login(); check("올바른 로그인 → 이동 + 쿠키", st == 303 and c.cookie.startswith("sid="))
        check("쿠키에 HttpOnly·SameSite", "HttpOnly" in h.get("Set-Cookie", "") and "SameSite=Strict" in h.get("Set-Cookie", ""))
        c.page_csrf()
        st, html, h = c.req("GET", "/")
        check("보안 헤더(CSP, nosniff)", "default-src 'none'" in h.get("Content-Security-Policy", "") and h.get("X-Content-Type-Options") == "nosniff")
        check("서버 종류 문구에 파이썬 버전이 안 보임", "Python" not in h.get("Server", ""))

        print("[2] F1 경고 목록")
        check("시험 모드 배너", "DRY_RUN" in html)
        ids = re.findall(r'href="/event/([A-Z0-9-]+)"', html)
        scores = [int(x) for x in re.findall(r'<td class="num">(\d+)</td>', html)]
        check("점수 높은 순", scores == sorted(scores, reverse=True) and scores[0] == 99, scores)
        check("정상 10건만 표시(옛 칸 이름 EVT-010 포함, 잘못된 2건 제외)", len(ids) == 10 and "EVT-010" in ids and "BAD-1" not in ids, ids)
        check("형식 오류 2건 안내", "2건은 건너뛰었습니다" in html)
        check("등급 글자 4종 표시", all(w in html for w in ("심각", "높음", "주의", "낮음")))
        check("등급 구분이 색뿐 아니라 글자", 'class="badge g-critical">심각' in html)
        check("<script> 규칙 이름이 escape 됨", "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html)
        _, html_c, _ = c.req("GET", "/?grade=critical")
        check("등급 필터(심각)", len(re.findall(r'<tr class="row-', html_c)) == 4, len(re.findall(r'<tr class="row-', html_c)))

        print("[3] F2 사건 상세")
        _, d, _ = c.req("GET", "/event/EVT-001")
        check("근거 로그 2건(시각·사용자 일치)", d.count("password mismatch") == 2)
        check("다른 사용자의 같은 시각 로그가 섞이지 않음", "emp4" not in d.split("근거 원본 로그")[1].split("같은 사용자")[0])
        check("같은 사용자의 다른 탐지(EVT-009)", "EVT-009" in d.split("같은 사용자의 다른 탐지")[1])
        check("점수 이유 표시", "점수 이유" in d and "90점" in d)
        _, d8, _ = c.req("GET", "/event/EVT-008")
        check("퇴사자 명단 표시 + 새 유형", "퇴사자 명단에 있음" in d8 and "퇴사자 접근" in d8)
        st, _, _ = c.req("GET", "/event/NOPE"); check("없는 사건 → 404", st == 404)
        st, _, _ = c.req("GET", "/event/..%2f..%2fetc"); check("경로 조작 → 404", st == 404)

        print("[4] F3·F4 승인과 OCC 요청")
        st, body, _ = c.post("/event/EVT-001/approve", action="lock_account", note="확인함")
        check("승인 → 이동", st == 303)
        _, d, _ = c.req("GET", "/event/EVT-001")
        check("상태: 승인·시험 모드", "승인 · 시험 모드" in d)
        check("누가 눌렀는지 기록(tester)", "tester" in d and "승인 · 요청 조치 lock_account" in d)
        check("DRY_RUN 결과 문구", "실제 요청 없이 기록만" in d)
        st, _, _ = c.post("/event/EVT-001/approve", action="lock_account")
        _, d, _ = c.req("GET", "/event/EVT-001")
        check("같은 사건 두 번 승인 불가", d.count("승인 · 요청 조치") == 1)
        st, _, _ = c.post("/event/EVT-002/approve", action="rm -rf")
        check("허용되지 않은 조치 이름 거부", "EVT-002" and c.req("GET", "/event/EVT-002")[1].count("대기") >= 1)

        print("[5] F3 거절 / F7 오탐")
        c.post("/event/EVT-003/reject", note="업무상 접속")
        _, d, _ = c.req("GET", "/event/EVT-003"); check("거절 기록", "거절" in d and "업무상 접속" in d)
        c.post("/event/EVT-001/falsepositive", note="본인 확인")
        _, d, _ = c.req("GET", "/event/EVT-001")
        check("오탐 처리 + unlock_account 되돌리기 요청 생성", "unlock_account" in d and "오탐" in d)
        c.post("/event/EVT-004/falsepositive")
        _, d, _ = c.req("GET", "/event/EVT-004"); check("조치 전 오탐은 되돌리기 요청 없음", "unlock_account" not in d and "오탐" in d)

        print("[6] F6 처리 이력")
        _, h, _ = c.req("GET", "/history")
        check("승인·거절·조치·오탐·되돌리기가 모두 이력에 있음", all(w in h for w in ("승인", "거절", "조치 요청", "오탐 처리", "되돌리기 요청")))
        _, h2, _ = c.req("GET", "/history?order=asc")
        check("정렬 전환", h.index("EVT-004") != h2.index("EVT-004"))

        print("[7] F5 보고서")
        _, r, _ = c.req("GET", "/event/EVT-001/report"); check("만들기 전 안내", "아직 만든 보고서가 없습니다" in r)
        c.post("/event/EVT-001/report/create")
        st, r, _ = c.req("GET", "/event/EVT-001/report")
        check("보고서 5개 구성", all(f"{i}." in r for i in ("1", "2", "3", "4", "5")) and all(w in r for w in ("사고 개요", "탐지 근거", "조치 내역", "현재 상태", "후속 조치")))
        check("사실이 그대로(사용자·IP·점수·시각)", all(w in r for w in ("emp3", "192.168.30.12", "90점", "2026-11-02 02:10:11")))
        check("AI 미사용 사유 안내", "AI 키(ANTHROPIC_API_KEY)가 없어" in r or "AI 사용 안 함" in r)
        st, md, h = c.req("GET", "/event/EVT-001/report.md")
        check("내려받기(.md, attachment)", st == 200 and "attachment" in h.get("Content-Disposition", "") and md.startswith("# 초동 대응 보고서"))
        c.post("/event/EVT-009/report/create")
        _, r9, _ = c.req("GET", "/event/EVT-009/report"); check("대기 상태 사건의 후속 조치 문구", "승인·거절·오탐 중 하나로 판단" in r9)

        print("[8] CSRF·로그아웃")
        st, body, _ = c.req("POST", "/event/EVT-005/reject", {"note": "x"})
        check("CSRF 토큰 없이 POST → 403", st == 403)
        st, body, _ = c.req("POST", "/event/EVT-005/reject", {"csrf": "가짜"})
        check("틀린 CSRF 토큰 → 403", st == 403)
        _, d, _ = c.req("GET", "/event/EVT-005"); check("거부된 요청은 상태를 바꾸지 않음", "대기" in d)
        c.post("/logout"); st, _, _ = c.req("GET", "/"); check("로그아웃 뒤 접근 불가", st == 303)

        print("[9] 로그인 시도 제한")
        c2 = Client(port)
        for _ in range(5): c2.login(pw="x" * 12)
        st, _, _ = c2.login(); check("5번 실패 뒤에는 맞는 비밀번호도 잠김(429)", st == 429)

        print("[10] 원본 로그 읽기 전용")
        check("원본 로그 파일이 하나도 안 바뀜", sha(os.path.join(tmp, "app.log")) == log_hash_before)

        print("[11] 감사 로그")
        audit = [json.loads(l) for l in open(os.path.join(cfg["data_dir"], "audit.log"), encoding="utf-8")]
        kinds = {a["kind"] for a in audit}
        check("로그인 성공/실패/CSRF/이력이 감사 로그에 있음", {"login_ok", "login_fail", "csrf_reject", "history", "logout"} <= kinds, kinds)
        check("비밀번호가 감사 로그에 없음", PW not in open(os.path.join(cfg["data_dir"], "audit.log"), encoding="utf-8").read())
    finally:
        proc.terminate(); proc.wait(timeout=5)

    print("[12] 허용 대역 밖 접속 차단")
    proc2, port2, _ = start_server(tmp, {"allowed_networks": ["10.99.0.0/16"]}, "cfg_block.json")
    try:
        st, body, _ = Client(port2).req("GET", "/login"); check("허용 대역 밖 → 403, 로그인 화면도 안 보임", st == 403 and "로그인" not in body)
    finally:
        proc2.terminate(); proc2.wait(timeout=5)

    print("[13] 실제 모드: OCC 성공 / 실패 / 재시도")
    received = []

    class Stub(http.server.BaseHTTPRequestHandler):
        mode = "ok"
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0)); received.append((json.loads(self.rfile.read(n)), self.headers.get("Authorization")))
            self.send_response(200 if Stub.mode == "ok" else 500); self.send_header("Content-Length", "0"); self.end_headers()
        def log_message(self, *a): pass
    stub_port = free_port(); stub = http.server.HTTPServer(("127.0.0.1", stub_port), Stub)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    os.environ["OCC_TOKEN"] = "stub-token"
    proc3, port3, _ = start_server(tmp, {"dry_run": False, "occ_url": "http://127.0.0.1:%d/occ" % stub_port}, "cfg_live.json")
    try:
        c3 = Client(port3); c3.login(); c3.page_csrf()
        _, page, _ = c3.req("GET", "/"); check("실제 조치 모드 배너", "실제 조치 모드" in page)
        c3.post("/event/EVT-005/approve", action="block_ip")
        _, d, _ = c3.req("GET", "/event/EVT-005")
        check("OCC 성공 → 조치 성공 표시", "승인 · 조치 성공" in d and "OCC 응답 HTTP 200" in d)
        check("OCC가 받은 요청 내용", received and received[0][0]["action"] == "block_ip" and received[0][0]["src_ip"] == "192.168.30.16" and received[0][0]["requested_by"] == "tester")
        check("OCC 토큰은 환경변수에서 헤더로 전달", received[0][1] == "Bearer stub-token")
        Stub.mode = "fail"
        c3.post("/event/EVT-006/approve", action="lock_account")
        _, d, _ = c3.req("GET", "/event/EVT-006")
        check("OCC 실패 → 조치 실패 표시 + 다시 요청 버튼", "승인 · 조치 실패" in d and "다시 요청" in d)
        Stub.mode = "ok"
        c3.post("/event/EVT-006/retry")
        _, d, _ = c3.req("GET", "/event/EVT-006"); check("다시 요청 → 성공", "승인 · 조치 성공" in d)
        c3.post("/event/EVT-007/approve", action="lock_account")
        Stub.mode = "fail"; c3.post("/event/EVT-007/falsepositive")
        _, d, _ = c3.req("GET", "/event/EVT-007"); check("되돌리기 실패가 화면에 표시됨", "되돌리기 실패" in d)
        Stub.mode = "ok"; c3.post("/event/EVT-007/retry")
        _, d, _ = c3.req("GET", "/event/EVT-007"); check("되돌리기 다시 요청 → 성공", "되돌리기 실패" not in d and received[-1][0]["action"] == "unlock_account")
    finally:
        proc3.terminate(); proc3.wait(timeout=5); stub.shutdown()

    shutil.rmtree(tmp, ignore_errors=True)
    print("\n통과 %d건 / 실패 %d건" % (len(passed), len(failed)))
    if failed: print("실패 목록:", failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
