import json
def read_log(filename):
    with open(filename, "r", encoding="utf-8") as file:
        logs = json.load(file)
    return (logs)

def make_report(ticket, logs):
    lines = []
    lines.append("이벤트 ID:" +  ticket["event"]["event_id"])
    lines.append("유형:" + ticket["event"]["event_type"])
    lines.append("사용자:" + ticket["event"]["user"])
    lines.append("IP:" + ticket["event"]["src_ip"])
    lines.append("자산:" + ticket["event"]["asset"])
    lines.append("영향 범위:" + ticket["event"]["impact_scope"])
    lines.append("우선순위:" + ticket["event"]["priority"])
    lines.append("위험 점수:"  + str(ticket["event"]["risk_score"]))
    
                
    lines.append("탐지 규칙:" + ticket ["event"]["rule"])
    lines.append("근거:" + ", ".join(ticket["event"]["evidence"]))
    lines.append("탐지 시각:" + ticket["event"]["detected_at"])
    lines.append("조치:" + ticket["request"]["action"])
    lines.append("대상:" + ticket["request"]["target"])
    lines.append("대응 등급:" + ticket["request"]["response_level"])

    for log in logs:
        if log["event_id"] == ticket["event"]["event_id"]:
                lines.append( "이력 시각:" + log["timestamp"])
                lines.append( "이력 결과:" + log["result"] )
                lines.append( "이력 사유:" + log["reason"] )

    if ticket["action_result"] is None:
        lines.append("조치 결과: 조치 없음")
    else:
        lines.append("조치 결과:" + ticket["action_result"])
    lines.append("현재 상태:" + ticket["status"])

    
        
         
         
    return(lines)




def save_report(lines, filename):
    with open(filename, "w", encoding="utf-8")as file:
       json.dump(lines, file, ensure_ascii=False, indent=4)





if __name__ == "__main__":
    # ============================================================
    # 이 테스트가 하는 일
    #   make_report가 내가 쓴 대로 줄을 만드는지 3가지 경우로 확인한다.
    #   경우 1 : 조치 결과가 오기 전 티켓 (action_result가 None)
    #   경우 2 : 조치 결과가 온 뒤 티켓 (update_ticket으로 바꾼 것)
    #   경우 3 : 조치 이력 파일에 이 이벤트가 없을 때 (logs가 빈 목록)
    # 왜 이렇게 하나
    #   make_report는 값이 없는 경우(None, 이력 없음)에서 에러가 나기 쉽다.
    #   그래서 정상 경우 하나만 보지 않고 3가지를 모두 돌려 본다.
    # 이 블록은 report.py를 직접 실행할 때만 돈다.
    #   (다른 파일이 import 하면 안 돈다. classifier.py와 같은 이유)
    # ============================================================

    # [뭐함] 4번 ticket.py의 함수 2개를 가져온다.
    # [왜]   make_report가 받는 티켓은 4번이 만든 모양이어야 한다.
    #        손으로 티켓을 쓰면 칸 이름이 틀리기 쉬워서 4번 함수로 만든다.
    from ticket import make_ticket, update_ticket

    # [뭐함] 테스트용 이벤트. 칸 11개는 공통로그 2번(detections.json)과 같은 이름이다.
    # [출처] 값은 내가 정한 테스트 값이다. 이름만 맞으면 값이 달라도 된다.
    test_event = {
        "event_id": "EVT-001",
        "detected_at": "2026-11-02T02:10:00",
        "rule": "failed_login_5_in_10min",
        "event_type": "ABNORMAL_LOGIN",
        "user": "emp3",
        "src_ip": "192.168.30.12",
        "risk_score": 90,          # 숫자다. make_report에서 str( )가 필요한 값이다.
        "priority": "High",
        "asset": "web-server-01",
        "impact_scope": "web service",
        "evidence": ["2026-11-02 02:10:11", "2026-11-02 02:14:05"],
    }

    # [뭐함] 테스트용 조치 요청. 공통로그 3번 칸 이름이다. make_ticket이 읽는다.
    test_request = {
        "event_id": "EVT-001",
        "action": "block_ip",
        "target": "192.168.30.12",
        "response_level": "즉시 자동조치",
        "reason": "failed_login_5_in_10min",
        "dry_run": False
    }

    # [뭐함] 조치 이력 파일을 읽는다. 같은 폴더의 containment_log.json이다.
    # [출처] read_log는 위에서 내가 쓴 함수다. 안에 EVT-001 줄이 1개 들어 있다.
    logs = read_log("containment_log.json")

    # ---------------- 경우 1 : 조치 결과가 오기 전 ----------------
    print("=== 경우 1 : 조치 결과 오기 전 ===")
    # [뭐함] 티켓을 만든다. 세 번째 "조치중"은 def의 status 자리로 들어간다.
    #        이때 ticket["action_result"]는 None이다.
    ticket = make_ticket(test_event, test_request, "조치중")
    lines = make_report(ticket, logs)
    # [뭐함] lines는 글자 목록이다. for로 한 줄씩 꺼내 찍는다.
    # [기대] 이벤트 ID ... 위험 점수:90, 탐지 규칙/근거/시각, (조치 요청 3줄), 이력 3줄,
    #        "조치 결과: 없음"이 차례로 나온다.
    for line in lines:
        print(line)
    # [뭐함] 모든 줄이 글자인지 확인한다. 글자가 아닌 것(숫자, None)이 섞이면 False가 나온다.
    # [기대] True
    print("모두 글자인가:", all(isinstance(line, str) for line in lines))
    # [뭐함] 줄 수를 센다.
    # [기대] 아래 두 값 중 내가 쓴 단계에 맞는 것.
    #   지금까지 쓴 것(사고 개요 8 + 탐지 근거 3 + 이력 3 + 결과 1) : 15
    #   조치 요청 3줄과 현재 상태 1줄까지 쓴 것 : 19
    #   후속 조치까지 쓴 것 : 20
    print("줄 수:", len(lines))

    # ---------------- 경우 2 : 조치 결과가 온 뒤 ----------------
    print("=== 경우 2 : 조치 결과 온 뒤 ===")
    # [뭐함] 1·3파트가 돌려준다고 가정한 조치 결과. 공통로그 5번 칸 이름이다.
    # [출처] 값은 내가 정한 테스트 값이다.
    test_result = {
        "event_id": "EVT-001",
        "action": "block_ip",
        "target": "192.168.30.12",
        "result": "success",
        "message": "차단 완료",
        "timestamp": "2026-11-02 02:15:05",
        "dry_run": False
    }
    # [뭐함] 4번 update_ticket이 티켓의 action_result를 "success"로, status를 "완료"로 바꾼다.
    ticket = update_ticket(ticket, test_result)
    lines = make_report(ticket, logs)
    # [기대] 경우 1과 줄 수가 같고, 마지막 쪽 줄이 "조치 결과:success"로 바뀐다.
    #        (현재 상태 줄까지 썼다면 "완료"도 나온다)
    for line in lines:
        print(line)
    print("줄 수:", len(lines))

    # ---------------- 경우 3 : 조치 이력이 없을 때 ----------------
    print("=== 경우 3 : logs가 빈 목록 ===")
    # [뭐함] 빈 목록 [ ]를 넣는다. for가 한 번도 돌지 않아 이력 3줄이 빠져야 한다.
    # [왜]   이력 파일에 이 이벤트가 없어도 에러 없이 리포트가 만들어지는지 본다.
    lines = make_report(ticket, [])
    # [기대] 경우 2보다 줄 수가 정확히 3 적다.
    print("줄 수:", len(lines))

        # [왜 쓰나] save_report가 파일을 제대로 저장했는지 확인한다.
    # [어떻게 도나] 1) make_report로 줄 목록을 만든다.
    #              2) save_report로 파일에 저장한다.
    #              3) 같은 파일을 다시 읽어서 처음 줄 목록과 비교한다.
    # 값의 출처: ticket, logs는 위 경우 3에서 쓴 값이다.
    lines = make_report(ticket, logs)
    save_report(lines, "report_test.json")

    # 저장한 파일을 읽는다. json.dump로 썼으니 json.load로 읽는다.
    # encoding="utf-8"은 save_report와 같아야 한글이 안 깨진다.
    with open("report_test.json", "r", encoding="utf-8") as file:
        saved = json.load(file)

    print("저장 전 줄 수:", len(lines))
    print("저장 후 줄 수:", len(saved))
    print("내용이 같은가:", saved == lines)   # True가 나와야 한다