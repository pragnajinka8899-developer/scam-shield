"""Measure the rule engine on tests.csv. Run with: python evaluate.py"""
import csv
from rules import SUSPICIOUS, analyze

tp = fn = fp = tn = 0
missed, false_alarms = [], []

with open("tests.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        score = analyze(row["text"])["score"]
        flagged = score >= SUSPICIOUS
        is_scam = row["label"].strip().lower() == "scam"
        if is_scam and flagged:
            tp += 1
        elif is_scam:
            fn += 1
            missed.append((score, row["text"]))
        elif flagged:
            fp += 1
            false_alarms.append((score, row["text"]))
        else:
            tn += 1

scams, safes = tp + fn, tn + fp
print("=" * 45)
print("       SCAM SHIELD EVALUATION REPORT       ")
print("=" * 45)
print(f"Scams caught: {tp}/{scams} ({100 * tp / scams:.0f}%)")
print(f"False alarms: {fp}/{safes} ({100 * fp / safes:.0f}%)")

for title, items in (("MISSED SCAMS", missed), ("FALSE ALARMS", false_alarms)):
    if items:
        print(f"\n{title}:")
        for score, text in items:
            print(f" [{score:>3}] {text[:90]}")
print("=" * 45)

