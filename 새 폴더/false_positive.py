from datetime import datetime
import os
import json
def choose_restore_action(action):
    if action == "block_ip":
        return("unblock_ip")
    elif action == "lock_account":
        return("unlock_account")
    else: 
        return None

def make_restore_request(request, result):
    restore_action = choose_restore_action(request["action"])

    if result["result"] != "success":
        return None
    if request["dry_run"] == True:
        return None
    if restore_action == None:
        return None


    data = {
        "event_id": request["event_id"],
        "action": restore_action,
        "target": request["target"],
        "response_level": "즉시 자동조치",
        "reason": "false_positive",
        "dry_run": request["dry_run"]
    } 

    return(data)

def make_feedback(event_id, username, event_type, risk_score, reason, confirmed_by):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    data_1 = {
        "event_id"               : event_id,
        "username"               :  username,
        "event_type"             :  event_type,
        "detected_as_anomaly"    : True,
        "risk_score"             :  risk_score,
        "is_actual_anomaly"      : False,
        "false_positive_reason"  :  reason,
        "confirmed_by"           :  confirmed_by,
        "recorded_at"           : current_time
    

    }

    return(data_1)

def save_feedback(feedback, filename):
    if os.path.exists(filename): 
        with open(filename, "r") as file:
            
                records = json.load(file)
        
    else:
        records = []


    records.append(feedback)
    
    with open(filename, "w") as file:
        json.dump(records, file, ensure_ascii=False, indent=4)

def handle_false_positive(event, request, result, reason, confirmed_by):
    restore = make_restore_request(request, result)

    feedback = make_feedback(event["event_id"], event["user"], event["event_type"], event["risk_score"], reason, confirmed_by)

    save_feedback(feedback, "false_positive_feedback.json")

    return restore    




def read_false_positive_input(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, "r", encoding="utf-8") as file:
        records = json.load(
            file
        )
    return(records)