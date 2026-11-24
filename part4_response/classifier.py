import json
import os



def check_vip(src_ip, user, vip_data):
    if user in vip_data["vip_users"]:
       return True

    elif src_ip in vip_data["vip_ips"]:
       return True
    else:
       return False
       
def event_check(user, src_ip, risk_score, rule, vip_data):
    
    if risk_score >= 80:
        level = "즉시 자동조치"

    elif risk_score >= 50:
        level = "승인 후 조치"
    else:
        level = "모니터링만"   

    if risk_score >= 80 and check_vip(src_ip, user, vip_data) == True:
        level = "승인 후 조치"

    return level



    
if __name__ == "__main__":
    with open ("detections.json", "r") as file:
        detections = json.load(file)

    with open ("vip_accounts.json", "r") as file:
        vip_data = json.load(file)
    
    for event in detections:
        result = event_check(event["user"], event["src_ip"], event["risk_score"], event["rule"], vip_data)
        print(event["event_id"], result)
    

        