# SRC — interno orodje za preverjanje razkritij

Interna spletna aplikacija za pooblaščene preiskave (IR / threat intel). Poizveduje proti bazam razkritij prek **LeakOsint API** in prikaže najdene zapise po virih.

> ⚠️ **Samo za interno, pooblaščeno uporabo.** Ni namenjeno javnemu dostopu. Deploy izključno na interni mreži / za VPN. Vsaka poizvedba je avtenticirana in zabeležena.

## Lastnosti

- Prijava (uporabniški računi z zgoščenimi gesli)
- Beleženje vseh prijav, odjav in poizvedb (`audit.log`)
- Poizvedba prek LeakOsint (e-naslov, uporabniško ime, telefon, ime …)
- Statični frontend (HTML/CSS/JS); strežnik je tanek JSON proxy, ki hrani token
- Dva načina v enem vmesniku:
  - **Živa poizvedba** — klic prek proxyja (token skrit, poizvedba se beleži)
  - **Uvoz rezultatov** — lokalni pregled JSON odgovora (naloži/prilepi), brez klica in brez beleženja
- Prikaz zadetkov po bazah z vsemi polji
- Izvoz rezultatov v CSV in JSON
- Omejevanje hitrosti (rate limiting), podpora za reverse proxy

## Namestitev

```bash
pip install -r requirements.txt

# 1. Ustvari uporabnika (izpiše hash gesla)
python app.py hash "mocno-geslo"

# 2. Vpiši ga v users.json:
#    { "wolfy": "<izpisani-hash>" }

# 3. Zagon
gunicorn app:app
```

## Okoljske spremenljivke

| Spremenljivka | Obvezno | Pomen |
| --- | --- | --- |
| `SECRET_KEY` | da | ključ za podpisovanje sej (naključen niz) |
| `LEAKOSINT_TOKEN` | da | API ključ storitve LeakOsint |
| `USERS_FILE` | ne | pot do datoteke z uporabniki (privzeto `users.json`) |
| `AUDIT_LOG` | ne | pot do dnevnika (privzeto `audit.log`) |
| `SEARCH_LIMIT` | ne | privzeti limit poizvedbe (privzeto 100) |
| `SEARCH_LANG` | ne | jezik rezultatov (privzeto `en`) |
| `SESSION_COOKIE_SECURE` | ne | `1`, če je pred aplikacijo HTTPS |
| `RATELIMIT_STORAGE_URI` | ne | npr. `redis://…` za trajno omejevanje hitrosti |

## Varnost in skladnost

- `users.json` in `audit.log` sta v `.gitignore` — **ne commitaj ju**.
- `audit.log` vsebuje iskalne pojme (osebni podatki) — datoteko zaščiti in hrani skladno z internimi pravili in GDPR (obdelava mora biti sledljiva in časovno omejena).
- Orodje ne sme biti dosegljivo z interneta — omeji dostop na interno mrežo / VPN oz. z IP allowlist.
- Poizvedbe naj bodo vezane na pooblaščene preiskave; izvoženi podatki (CSV/JSON) so občutljivi.

## Struktura

```
.
├── app.py                  # Flask app: prijava, beleženje, LeakOsint, izvoz
├── requirements.txt
├── users.example.json      # primer (kopiraj v users.json)
├── .gitignore
└── static/
    ├── index.html          # frontend (HTML + CSS + JS, kliče /api/*)
    └── logo.png
```

---

Razvito v [SRC d.o.o.](https://src.si)
