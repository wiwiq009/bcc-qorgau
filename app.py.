
from flask import Flask, request, jsonify, render_template
import re

app = Flask(__name__)

RULES = [
    {
        "name": "Запрос конфиденциальных данных",
        "patterns": [
            r"\b(cv[vv]|pin|парол[ья]|код из смс|одноразов\w* код)\b",
            r"(sms|смс).{0,20}(код|парол)",
            r"(код|парол).{0,20}(sms|смс)"
        ],
        "points": 40
    },
    {
        "name": "Срочность и давление",
        "patterns": [
            r"срочно",
            r"немедленно",
            r"прямо сейчас",
            r"аккаунт будет заблокирован",
            r"последнее предупреждение",
            r"шұғыл",
            r"дереу"
        ],
        "points": 20
    },
    {
        "name": "Подозрительная ссылка",
        "patterns": [
            r"https?://",
            r"www\.",
            r"перейдите по ссылке",
            r"сілтемеге өтіңіз"
        ],
        "points": 25
    },
    {
        "name": "Требование перевести деньги",
        "patterns": [
            r"переведите деньги",
            r"срочный перевод",
            r"отправьте деньги",
            r"ақша аударыңыз"
        ],
        "points": 30
    },
    {
        "name": "Обещание лёгкой выгоды",
        "patterns": [
            r"вы выиграли",
            r"гарантированный доход",
            r"получите бесплатно",
            r"легкие деньги",
            r"ұтып алдыңыз"
        ],
        "points": 20
    },
    {
        "name": "Угроза или запугивание",
        "patterns": [
            r"ваш счет заблокируют",
            r"будет возбуждено дело",
            r"вас арестуют",
            r"штраф немедленно"
        ],
        "points": 25
    }
]


def analyze_message(message):
    if not message or not message.strip():
        return {
            "error": "Введите текст сообщения"
        }

    text = message.lower()
    findings = []
    score = 0

    for rule in RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append({
                    "name": rule["name"],
                    "points": rule["points"]
                })
                score += rule["points"]
                break

    score = min(score, 100)

    if score >= 60:
        level = "HIGH"
        advice = "Не переходите по ссылкам и не передавайте личные данные. Проверьте отправителя через официальный канал."
    elif score >= 30:
        level = "MEDIUM"
        advice = "Будьте осторожны. Проверьте отправителя и содержание сообщения."
    else:
        level = "LOW"
        advice = "Явных признаков из нашей базы правил не обнаружено. Это не гарантирует безопасность сообщения."

    return {
        "score": score,
        "level": level,
        "findings": findings,
        "advice": advice,
        "message": "Анализ выполнен по набору правил. Результат является предварительной оценкой."
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    result = analyze_message(message)
    status = 400 if "error" in result else 200

    return jsonify(result), status


if __name__ == "__main__":
    app.run(debug=True)
