# ScamShield

Telegram anti-scam assistant built with Python, aiogram 3 and SQLite.

## Features
- URL risk heuristics and optional Google Safe Browsing lookup.
- Message pattern analysis with explanations.
- Phone-number lookup against moderator-approved reports.
- User-submitted reports with admin moderation.
- User check history stored in SQLite.
- Admin statistics and basic access blocking field in database.

## Run locally
1. Install Python 3.10+.
2. `python -m venv .venv`
3. Activate the virtual environment.
4. `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and fill `BOT_TOKEN`, `ADMIN_IDS`.
6. Optional: set `GOOGLE_SAFE_BROWSING_KEY`.
7. `python main.py`

## Deploy
Set the same environment variables in your hosting provider and run `python main.py`.
Persist `scamshield.db` on a persistent disk. Do not commit `.env` or your bot token.

## Important limitations
- Local heuristics are signals, not proof. False positives and false negatives are possible.
- A clean result does not prove that a URL, phone number, or account is safe.
- Google Safe Browsing is optional and requires an API key.
- Phone-number reports are only shown after moderator approval. This is not an identity-verification service.
- The bot does not open submitted URLs or download their contents.
- Do not submit passwords, one-time codes, payment card data, identity documents, or private conversations without removing personal details.


## Размещение на Bothost

- Главный файл: `main.py`
- Зависимости: `requirements.txt`
- Переменные окружения:
  - `BOT_TOKEN` — токен от BotFather
  - `ADMIN_IDS` — Telegram ID администраторов через запятую
  - `DB_PATH` — `/app/data/scamshield.db` (папка Bothost для сохранения SQLite между обновлениями)
  - `GOOGLE_SAFE_BROWSING_KEY` — необязательно
- Не загружайте `.env`, токены, базу данных, `venv` или `__pycache__` в GitHub.
