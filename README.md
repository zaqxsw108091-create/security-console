# 보안 콘솔 프로토타입

SKT ALEPH 보안과정 4인 캡스톤(ASTRA)의 보안 콘솔 프로토타입입니다. Claude와 함께 만들었습니다.

**시험 모드(DRY_RUN)** 로 설정되어 있습니다. 승인해도 실제 차단은 하지 않고 기록만 남깁니다.

## 폴더 설명

| 위치 | 내용 |
|---|---|
| `security_console/` | 콘솔 프로그램 |
| `part4_response/` | 내 대응·기록 파트 코드 (`classifier.py`, `playbook.py`, `ticket.py`, `report.py`, `false_positive.py`, `main.py`) |
| 맨 위의 html 파일들, `작업기록.md` | 학습·작업 기록 |

## 직접 확인하는 방법

자세한 설명: [security_console/README.md](security_console/README.md)

파이썬 기본 기능만 써서 따로 설치할 것이 없습니다. Windows에서 `python3` 이 안 되면 `python` 으로 바꿔 입력합니다.

### 1. 관리자 계정 만들기 (처음 한 번)

```bash
cd security_console
python3 app.py --add-admin 이름
```

이름은 영문·숫자·`_ . -` 로 3~32자이고, 비밀번호는 10자 이상입니다. 계정은 자동으로 만들어지는 `data/` 폴더에 저장되며, 이 폴더는 저장소에 올라가지 않습니다.

### 2. 콘솔 실행하고 들어가기

```bash
python3 app.py
```

- 같은 PC의 브라우저: `http://127.0.0.1:8080`
- 콘솔 서버와 같은 VLAN 20의 PC: `http://192.168.20.104:8080`

끄려면 `Ctrl + C` 를 누릅니다.

### 3. 임시 데이터로 사건 보기

로그인하면 `sample_data/` 의 시험용 사건 9건이 자동으로 들어와 목록에 보입니다.

### 4. 자동 시험 실행하기

```bash
python3 test_console.py
```

임시 폴더에서 **56가지** 를 시험하며, 실제 `data/` 는 건드리지 않습니다. `security_console/작업기록.md` 에도 56건 통과로 적혀 있고, 2026-11-24에 `data/` 폴더 없이 다시 돌려 56건 통과 / 0건 실패를 확인했습니다.

Windows에서는 비밀번호 자동 입력이 되지 않아 그대로 실행하면 멈춥니다. 위 확인은 Windows에서 시험 파일은 고치지 않고 비밀번호 입력만 우회해서 했습니다.

## 공개하지 않는 것

최종 팀 콘솔과 팀 코드는 DB 비밀번호와 방화벽 접속 키가 들어 있어 공개하지 않습니다.
