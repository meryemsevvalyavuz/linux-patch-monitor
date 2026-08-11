#!/bin/bash
# Linux Patch Monitor - Tum zinciri sirayla calistiran otomasyon scripti
# Sirayla: paket toplama -> CVE eslestirme -> Telegram bildirimi

echo "=== $(date) - Patch Monitor calistiriliyor ==="

echo ""
echo "--- 1. Agent: paket toplama ---"
cd ~/patchmon-project/agent
source venv/bin/activate
python3 collector.py
deactivate

echo ""
echo "--- 2. CVE eslestirme ---"
cd ~/patchmon-project/cve_matcher
source venv/bin/activate
python3 cve_matcher.py
deactivate

echo ""
echo "--- 3. Telegram bildirimi ---"
cd ~/patchmon-project/notifier
source venv/bin/activate
python3 notifier.py
deactivate

echo ""
echo "=== $(date) - Tamamlandi ==="
