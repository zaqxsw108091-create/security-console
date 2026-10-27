from playbook import run_playbook, apply_result
from ticket import make_ticket, update_ticket
from report import read_log, make_report, save_report
import json
from false_positive import handle_false_positive, read_false_positive_input

with open("detections.json", "r", encoding="utf-8") as file:
    detections = json.load(file)

with open("vip_accounts.json", "r", encoding="utf-8") as file:
    vip_data= json.load(file)

logs = read_log("containment_log.json")

statuses = {}
tickets = {}
requests = {}
events = {}

for event in detections:
    request = run_playbook( event, vip_data, statuses)
    if request is not None:
        
        tickets[event["event_id"]] = make_ticket(event, request, statuses[event["event_id"]])
    
        event_id = event["event_id"]
       
        requests[event_id] = request
        events[event_id] = event



result = {"event_id": "EVT-001", "action": "block_ip", "target": "192.168.30.12",
          "result": "success", "message": "차단 완료",
          "timestamp": "2026-11-02 02:15:05", "dry_run": False}


apply_result(statuses, result)


update_ticket(tickets["EVT-001"], result)

for event_id in tickets:
    lines = make_report(tickets[event_id], logs)

    save_report(lines, "report_" + event_id + ".json")

false_list = read_false_positive_input("false_positive_input.json")
for item in false_list:
    event_id = item["event_id"]
    restore = handle_false_positive(events[event_id],requests
                                     [event_id],result,item["reason"],
                                     item["confirmed_by"])

print("복구 요청:", restore)

#===========================
# 테스트 (main.py를 실행하면 맨 아래에서 돈다)
#
# 왜 쓰나
#   위 1~5단계가 맞게 돌았는지 숫자와 글자로 확인한다.
#
# 어떻게 도나
#   위에서 이미 만들어진 statuses, tickets, detections를 읽기만 한다.
#   (아무것도 바꾸지 않는다)
#
# 값의 출처
#   detections : 7번 줄에서 읽은 이벤트 목록 (7건)
#   statuses   : 15번 줄에서 만들고, 19번 줄의 run_playbook이 채운 서랍장
#   tickets    : 16번 줄에서 만들고, 21번 줄이 채운 서랍장
# =====================================================================
print("=== main.py 확인 ===")

# [뭐함] 이벤트 7건 중 몇 건이 티켓이 되었는지 센다.
# [기대] 이벤트 7건 중 EVT-004(점수 20)가 "모니터링만"이라 티켓이 없다. 그래서 6.
#        (classifier.py의 등급 규칙에 따라 다를 수 있다. 숫자가 다르면 알려 주세요)
print("이벤트 수:", len(detections))      # 기대: 7
print("티켓 수:", len(tickets))           # 기대: 6 (또는 classifier 규칙에 따른 숫자)
print("요청 수", len(requests))
print("events 칸 수", len(events))

# [뭐함] 이벤트마다 상태와 티켓 여부를 한 줄씩 출력한다.
# [기대] 티켓이 없는 이벤트는 상태가 "모니터링" 또는 "신규"이다.
for event in detections:
    event_id = event["event_id"]
    print(event_id, statuses[event_id], "티켓 있음" if event_id in tickets else "티켓 없음")

# [뭐함] 저장된 리포트 파일이 티켓 수만큼 있는지 확인한다.
# [어떻게] 티켓마다 report_이벤트번호.json을 다시 읽어 json.load로 목록을 꺼낸다.
#          make_report를 다시 불러서 만든 줄 목록과 같은지(True/False) 비교한다.
# [기대] 티켓마다 True
for event_id in tickets:
    with open("report_" + event_id + ".json", "r", encoding="utf-8") as file:
        saved = json.load(file)
    print(event_id, "저장 내용 같은가:", saved == make_report(tickets[event_id], logs))
print("=== 6단계 확인 ===")
print("상태 서랍장:", statuses["EVT-001"])                      # 기대: 완료
print("티켓 상태:", tickets["EVT-001"]["status"])               # 기대: 완료
print("티켓 조치 결과:", tickets["EVT-001"]["action_result"])    # 기대: success
print("티켓 갱신 시각:", tickets["EVT-001"]["updated_at"])       # 기대: 2026-11-02 02:15:05