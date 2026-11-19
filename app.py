
from flask import Flask, request, jsonify, render_template
import re

app = Flask(__name__)

RULES = [
    {
        "name": "Запрос конфиденциальных данных",
        "reason": "Мошенники могут пытаться получить пароли, PIN или SMS-коды.",
        "patterns": [
            r"\b(cvv|cvc|pin)\b",
            r"парол[ья]",
            r"код из смс",
            r"одноразов\w* код",
            r"(sms|смс).{0,20}(код|парол)",
            r"(код|парол).{0,20}(sms|смс)",
            r"құпия сөз",
            r"растау коды"
        ],
        "points": 40
    },
    {
        "name": "Срочность и давление",
        "reason": "Сообщение пытается заставить получателя действовать поспешно.",
        "patterns": [
            r"срочно",
            r"немедленно",
            r"прямо сейчас",
            r"аккаунт будет заблокирован",
            r"последнее предупреждение",
            r"шұғыл",
            r"дереу",
            r"тез арада"
        ],
        "points": 20
    },
    {
        "name": "Подозрительная ссылка",
        "reason": "Ссылка может вести на поддельный сайт для кражи данных.",
        "patterns": [
            r"https?://[^\s]+",
            r"www\.[^\s]+",
            r"перейдите по ссылке",
            r"сілтемеге өтіңіз"
        ],
        "points": 25
    },
    {
        "name": "Требование перевести деньги",
        "reason": "Неожиданный запрос перевода денег может быть признаком мошенничества.",
        "patterns": [
            r"переведите деньги",
            r"срочный перевод",
            r"отправьте деньги",
            r"ақша аударыңыз",
            r"ақша жіберіңіз"
        ],
        "points": 30
    },
    {
        "name": "Обещание лёгкой выгоды",
        "reason": "Обещания гарантированного дохода или неожиданного выигрыша могут быть обманом.",
        "patterns": [
            r"вы выиграли",
            r"гарантированный доход",
            r"получите бесплатно",
            r"легкие деньги",
            r"ұтып алдыңыз",
            r"кепілді табыс"
        ],
        "points": 20
    },
    {
        "name": "Угроза или запугивание",
        "reason": "Угрозы блокировки или наказания могут использоваться для давления.",
        "patterns": [
            r"ваш счет заблокируют",
            r"будет возбуждено дело",
            r"вас арестуют",
            r"штраф немедленно",
            r"шотыңыз бұғатталады"
        ],
        "points": 25
    }
]


def analyze_message(message):
    if not isinstance(message, str) or not message.strip():
        return {"error": "Введите текст сообщения"}

    text = message.lower()
    findings = []
    score = 0

    for rule in RULES:
        matched_phrases = []

        for pattern in rule["patterns"]:
            matches = re.findall(pattern, text, re.IGNORECASE)

            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        match = next(
                            (part for part in match if part),
                            ""
                        )

                    if match and match not in matched_phrases:
                        matched_phrases.append(match)

        if matched_phrases:
            score += rule["points"]

            findings.append({
                "name": rule["name"],
                "reason": rule["reason"],
                "points": rule["points"],
                "matched_phrases": matched_phrases
            })

    score = min(score, 100)

    if score >= 60:
        level = "HIGH"
        advice = (
            "Не переходите по ссылкам и не передавайте личные данные. "
            "Проверьте отправителя через официальный канал."
        )
    elif score >= 30:
        level = "MEDIUM"
        advice = (
            "Будьте осторожны. Проверьте отправителя и содержание "
            "сообщения через официальный источник."
        )
    else:
        level = "LOW"
        advice = (
            "Явных признаков из нашей базы правил не обнаружено. "
            "Это не гарантирует безопасность сообщения."
        )

    return {
        "score": score,
        "level": level,
        "findings": findings,
        "advice": advice,
        "message": (
            "Анализ выполнен по набору правил. "
            "Результат является предварительной оценкой."
        )
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
