import json
from classifier import event_check



def choose_action(event_type):
    if event_type in ["ABNORMAL_LOGIN", "TRAFFIC_SPIKE", "CORRELATED_ATTACK","MALICIOUS_IP"]:
        return("block_ip")
    elif event_type == "OFFHOUR_LOGIN":
        return("terminate_session")
    elif event_type == "UNAUTHORIZED_ACCESS":
        return("lock_account")
    else:
        return None

def choose_target(action, user, src_ip):
    if action == "block_ip":
        return(src_ip)
    elif action in ["lock_account", "terminate_session"]:
        return(user)

    else:
        return None




def make_request(event, level, dry_run):
    action = choose_action(event["event_type"])
    target = choose_target(action, event["user"], event["src_ip"])
    request = {
        "event_id"       : event["event_id"],
       "action"         : action,
       "target"         : target,
       "response_level" : level,
       "reason"         : event["rule"],
      "dry_run"        : dry_run 
    }
    return request




def first_status(level):
    if level == "즉시 자동조치":
        return("조치중")
    elif level == "승인 후 조치":
        return("승인대기")
    elif level == "모니터링만":
        return("모니터링")
    else:
        return("신규")

def apply_result(statuses, result):
    event_id = result["event_id"]

    outcome = result["result"]

    if outcome == "success":
        statuses[event_id]="완료"

    elif outcome == "fail":
        statuses[event_id]="실패"
    elif outcome == "skipped":
        statuses[event_id]="완료"
    elif outcome == "approval_required":
        statuses[event_id]="승인대기"

def run_playbook(event, vip_data, statuses):
    event_id = event["event_id"]
    level = event_check(event["user"], event["src_ip"], 
                        event["risk_score"], event["rule"], 
                        vip_data)
    statuses[event_id]=first_status(level)
    if level == "모니터링만":
        return None
    else:
        request = make_request(event, level, False)
        if request["action"] is None:
            statuses[event_id] = "신규"
            return None
        return request


if __name__ == "__main__":
    test_event = {"event_id": "EVT-001", "rule": "failed_login_5_in_10min", "event_type": "ABNORMAL_LOGIN", "user": "emp3", "src_ip": "192.168.30.12", "risk_score": 80}
    vip_data = {"vip_users": ["admin"], "vip_ips": []}
    statuses = {}
    print(run_playbook(test_event, vip_data, statuses))
    print(statuses)






