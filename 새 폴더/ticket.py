def make_ticket(event, request, status):
    ticket_id = "TKT-"+ event["event_id"]
    
   

    ticket = {
        "event" : {
           "event_id": event["event_id"],
            "event_type": event["event_type"],
            "user": event["user"], 
            "src_ip": event["src_ip"], 
            "risk_score" : event["risk_score"],
            "priority" : event["priority"],
            "asset" : event["asset"],
            "impact_scope" : event["impact_scope"],
            "detected_at": event["detected_at"],
            "rule": event["rule"],
            "evidence": event["evidence"]
           },
        "request":  {
                "action": request["action"],
                "target": request["target"],
                "response_level":request["response_level"],
                "reason": request["reason"],
                "dry_run": request["dry_run"]
        },
        "ticket_id" : ticket_id, 
        "status" : status,
        "action_result" : None,
        "message" : None,
        "updated_at":event["detected_at"],
       
       
       }

    return(ticket)


# ---- 테스트용 (맨 아래에 붙여 넣기, main.py가 생기면 지워도 됨) ----
test_event = {
    "event_id": "EVT-001", "detected_at": "2026-10-26T09:00:00",
    "rule": "failed_login_5_in_10min", "event_type": "ABNORMAL_LOGIN",
    "user": "emp3", "src_ip": "192.168.30.12", "risk_score": 90,
    "priority": "high", "asset": "web01", "impact_scope": "single_user",
    "evidence": "x"
}

for level, status in [("즉시 자동조치", "조치중"), ("승인 후 조치", "승인대기"), ("모니터링만", "모니터링")]:
    test_request = {
        "event_id": "EVT-001", "action": "lock_account", "target": "emp3",
        "response_level": level, "reason": "test", "dry_run": True
    }
    
def update_ticket(ticket, result):

    ticket["action_result"] = result["result"]
    ticket["message"] =  result["message"]
    ticket["updated_at"] = result["timestamp"]


    if result["result"] == "success":
        ticket["status"] = "완료"
    elif result["result"] == "fail":
        ticket["status"] = "실패"

    elif result["result"] == "approval_required":
        ticket["status"] = "승인대기"

    else:
        None

    return(ticket)



def make_alert_request(event, level, message):
    if level == 1:
       to = "보안 담당자"
    else:
      to =   "보안 팀장"

    request = {
        "event_id" : event["event_id"],   
        "level"    : level,              
        "to"       : to  ,                
        "message"  : message
    }
    return(request)
























if __name__ == "__main__":
    test_event = {"event_id": "EVT-001", "detected_at": "2026-10-26T09:00:00", "rule": "failed_login_5_in_10min", 
                  "event_type": "ABNORMAL_LOGIN", "user": "emp3", 
                  "src_ip": "192.168.30.12", "risk_score": 90, 
                  "priority": "high", "asset": "web01", 
                  "impact_scope": "single_user", "evidence": "x"}                     
    for level, status in [("즉시 자동조치", "조치중"), ("승인 후 조치", "승인대기"), ("모니터링만", "모니터링")]:
        test_request = {"event_id": "EVT-001", "action": "lock_account", "target": "emp3", "response_level": level, "reason": "test", "dry_run": True}             
        ticket = make_ticket(test_event, test_request, status)
        print(level, "→", ticket["status"], ticket["event"]["user"], ticket["request"]["action"], ticket["updated_at"])

    alert = make_alert_request(test_event, 2, "테스트 알림")
    print(alert)

