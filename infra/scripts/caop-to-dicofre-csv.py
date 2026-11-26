#!/usr/bin/env python3
"""Converte os CSV oficiais da CAOP (DGT, "Areas_Freg_Mun_Dist_Pais_CAOP<ano>_csv.zip", extraído) no CSV intermédio code,name do seed-dicofre.sh.
Uso: python3 -I infra/scripts/caop-to-dicofre-csv.py <pasta-dos-csv> <saida.csv>
Valida: sem duplicados, regex do CHECK da 0027, nomes não vazios (<=160) e pai presente. Fonte CAOP 2025: https://www.dgterritorio.gov.pt/cartografia/cartografia-tematica/caop
"""
import csv, re, sys
src, out = sys.argv[1], sys.argv[2]
def rows(name, code_col, name_col):
    with open(f"{src}/{name}", encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f, delimiter=";"):
            yield r[code_col].strip().strip('"'), r[name_col].strip()
d = list(rows("Areas_Distrito_CAOP2025.csv", "dt", "distrito_ilha_dsg"))
m = list(rows("Areas_Municipio_CAOP2025.csv", "dtmn", "município_dsg"))
p = list(rows("Areas_Freguesia_CAOP2025.csv", "dtmnfr", "freguesia_dsg"))
allr = d + m + p
codes = [c for c, _ in allr]
assert len(codes) == len(set(codes)), "duplicados"
cs = set(codes)
for c, n in allr:
    assert re.fullmatch(r"[0-9]{2}([0-9]{2}([0-9A-Z]{2})?)?", c), c
    assert n and len(n) <= 160 and "\n" not in n, (c, n)
    if len(c) > 2: assert c[:-2] in cs, ("sem pai", c)
with open(out, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f, lineterminator="\n"); w.writerow(["code", "name"]); w.writerows(allr)
print(f"distritos/ilhas={len(d)} concelhos={len(m)} freguesias={len(p)} total={len(allr)}")
