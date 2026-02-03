# kameRadar 🛰️

A playful, OSCP-friendly recon helper that wraps **nmap** with a practical workflow:

- **TCP discovery** (quick = top ports, balanced/beast = all ports)
- **UDP discovery** (top N ports to catch SNMP/DNS/NTP/etc.)
- **Targeted detail scans** only on discovered ports
- Generates:
  - `SUMMARY.md` (clean overview)
  - `RECON.txt` (copy/paste recon commands — **no auto-exec**)

> Designed for repeated lab practice and clean note-taking / reporting.

---

## Install

```bash
git clone <your-repo-url>
cd kameRadar
chmod +x kameRadar.sh
