"""Standalone HTML with no external assets, script, or raw response bodies."""
from datetime import datetime, timezone
from html import escape

STATUS = {"confirmed": "Подтверждено для указанной версии", "corroborated": "Есть независимый повтор",
          "observed": "Есть прямое наблюдение", "hypothesis": "Гипотеза сканера",
          "conflicting": "Противоречивые данные", "not_reproduced": "В записях не воспроизводится",
          "insufficient": "Недостаточно данных", "invalid_evidence": "Ошибка проверки артефакта"}
GATES = {"direct_observation": "Прямое наблюдение", "independent_repeat": "Независимый повтор",
         "negative_control": "Контрольный образец чист", "all_inputs_comparable": "Все входы сопоставимы",
         "contradiction": "Обнаружено противоречие", "integrity_error": "Ошибка проверки данных"}
RULES = {"http.private_json": "Второй тестовый аккаунт получил закрытый контрольный объект владельца",
         "http.nosniff": "Отсутствует ожидаемое значение X-Content-Type-Options: nosniff",
         "tcp.exposure": "Согласованный с оператором TCP-порт открыт",
         "postgres.superuser": "У указанной роли PostgreSQL установлен rolsuper",
         "testssl": "Предупреждение testssl.sh", "forge": "Сбой указанного теста Forge",
         "echidna": "Контрпример свойства Echidna", "semgrep": "Совпадение правила Semgrep", "trivy": "Совпадение идентификатора Trivy",
         "zap": "Предупреждение ZAP", "slither": "Совпадение детектора Slither"}
STATE = {"present": "эффект есть", "absent": "эффект отсутствует", "unknown": "неопределённо",
         "signal": "сигнал инструмента"}


def esc(value):
    return escape(str(value), quote=True)


def date(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def case_html(c):
    rule = c["rule"]
    qualifier = rule.get("port") or rule.get("role") or rule.get("detector") or rule.get("media_type") or rule.get("marker_field")
    checks = "".join(f"<li>{label} — <b>{'да' if c['gates'][key] else 'нет'}</b></li>"
                     for key, label in GATES.items())
    evidence = []
    for run in c["runs"]:
        data = "; ".join(STATE[i["outcome"]] for i in run["items"]) or "нет сопоставимой записи"
        refs = " ".join(i["ref"] for i in run["items"])
        details = run.get("error", "")
        evidence.append(f"<tr><td>{esc(run['id'])}<br>{esc(run['collector'])}</td>"
                        f"<td>{'Цель' if run['side'] == 'target' else 'Контроль'}</td>"
                        f"<td>{esc(data)} {esc(details)}</td><td><code>{esc(run['sha256'])}</code>"
                        f"<details><summary>Записи</summary><code>{esc(refs)}</code></details></td></tr>")
    advice = c.get("advisory", {})
    reviews = " · ".join(esc(k) + " — " + esc(v.get("reason")) + ", " + esc(v.get("next"))
                         for k, v in advice.items() if isinstance(v, dict))
    return (f"<article><h2>{esc(c['id'])} · {STATUS[c['status']]}</h2><p>{RULES[rule['kind']]} "
            f"(<b>{esc(qualifier)}</b>).</p><p>Цель <code>{esc(c['target'])}</code> · "
            f"контроль <code>{esc(c['control'])}</code> · версия <code>{esc(c['revision'])}</code></p>"
            f"<p>{date(c['window'][0])} — {date(c['window'][1])}</p><ul>{checks}</ul>"
            "<table><tr><th>Сбор</th><th>Образец</th><th>Результат</th><th>SHA-256</th></tr>"
            + "".join(evidence) + "</table>" + (f"<p>Разбор моделей: {reviews}</p>" if reviews else "") + "</article>")


def benchmark_html(report):
    if "benchmark" not in report:
        return ""
    m = report["benchmark"]["overall"]
    interval = m["precision_95_interval"]
    def percent(value):
        return "нет знаменателя" if value is None else f"{value:.1%}"
    ci = "" if interval is None else f" (95% Wilson: {percent(interval[0])}–{percent(interval[1])})"
    return (f"<h2>Проверка по внешней разметке</h2><p>Всего {m['cases']}, верных подтверждений "
            f"{m['confirmed_true']}, ошибочных {m['confirmed_false']}, воздержаний {m['abstained']}.</p>"
            f"<p>Точность подтверждений {percent(m['precision'])}{ci}. "
            f"Полнота {percent(m['recall_including_abstentions'])}. "
            f"Доля случаев с решением {percent(m['decision_coverage'])}.</p>")


def to_html(report):
    summary = " · ".join(f"{esc(STATUS[k])}: {n}" for k, n in report["counts"].items() if n)
    review = report.get("model_review")
    models = (f"<p>Разбор моделей: {esc(review['status'])}, вызовов {review['calls']} из "
              f"{review['budget']}, полностью разобрано {review['processed']}.</p>") if review else ""
    return ("""<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport"
content="width=device-width, initial-scale=1"><title>ARTEX · Проверка находок</title>
<style>body{font:16px/1.55 system-ui,sans-serif;color:#142e38;margin:2rem auto;padding:0 1rem;max-width:68rem}
article{border-top:2px solid #137969;margin-top:2rem}li{margin:.2rem}table{border-collapse:collapse;width:100%}
td,th{text-align:left;padding:.5rem;border-bottom:1px solid #ccd9db;vertical-align:top}code{overflow-wrap:anywhere}
td:last-child{max-width:16rem}p{overflow-wrap:anywhere}@media print{article{break-inside:avoid}}</style>
<h1>Проверка достоверности находок</h1><p>Вывод относится к указанной версии, наблюдению и периоду.
Независимость сборщиков и соответствие версии удостоверяет оператор. Хеши проверяют целостность.
Серьёзность, эксплуатируемость и вероятность компрометации по ним не вычисляются.</p>"""
            + "<p>" + summary + "</p>" + models + benchmark_html(report) + "".join(case_html(c) for c in report["cases"]) + "</html>")
