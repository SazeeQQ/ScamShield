import asyncio, html, logging, os, re, ipaddress, json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit, unquote
import aiohttp
import aiosqlite
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv('BOT_TOKEN', '').strip()
DB_PATH = os.getenv('DB_PATH', '/app/data/scamshield.db')
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
ADMIN_IDS = {int(x) for x in os.getenv('ADMIN_IDS', '').split(',') if x.strip().isdigit()}
GOOGLE_SAFE_BROWSING_KEY = os.getenv('GOOGLE_SAFE_BROWSING_KEY', '').strip()
MAX_TEXT = 5000
router = Router()
log = logging.getLogger('scamshield')

class ReportForm(StatesGroup):
    kind = State(); value = State(); details = State()

class SearchForm(StatesGroup):
    query = State()


def esc(s): return html.escape(str(s or ''))

def menu():
    kb = InlineKeyboardBuilder()
    for label, data in [
        ('🔗 Проверить ссылку','check_url'), ('🧠 Проверить сообщение','check_text'),
        ('📞 Проверить номер','check_phone'), ('🚨 Сообщить об угрозе','report'),
        ('📚 База предупреждений','database'), ('ℹ️ Как это работает','about'),
    ]: kb.button(text=label, callback_data=data)
    kb.adjust(2,2,2)
    return kb.as_markup()

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, joined_at TEXT DEFAULT CURRENT_TIMESTAMP, checks INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, kind TEXT, target TEXT, verdict TEXT, score INTEGER, explanation TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, kind TEXT, target TEXT, details TEXT, status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP, reviewed_by INTEGER, review_note TEXT);
        CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(kind,target);
        CREATE INDEX IF NOT EXISTS idx_checks_user ON checks(user_id,created_at);
        ''')
        await db.commit()

async def touch_user(user):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('INSERT INTO users(id,username,first_name) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET username=excluded.username, first_name=excluded.first_name', (user.id,user.username,user.first_name))
        await db.commit()

async def log_check(uid, kind, target, verdict, score, explanation):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('INSERT INTO checks(user_id,kind,target,verdict,score,explanation) VALUES(?,?,?,?,?,?)',(uid,kind,target[:1000],verdict,score,explanation[:2000]))
        await db.execute('UPDATE users SET checks=checks+1 WHERE id=?',(uid,))
        await db.commit()

async def is_blocked(uid):
    async with aiosqlite.connect(DB_PATH) as db:
        cur=await db.execute('SELECT blocked FROM users WHERE id=?',(uid,)); row=await cur.fetchone()
        return bool(row and row[0])

async def google_check(url):
    if not GOOGLE_SAFE_BROWSING_KEY: return None
    endpoint=f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}'
    payload={'client':{'clientId':'scamshield','clientVersion':'1.0'},'threatInfo':{'threatTypes':['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],'platformTypes':['ANY_PLATFORM'],'threatEntryTypes':['URL'],'threatEntries':[{'url':url}]}}
    timeout=aiohttp.ClientTimeout(total=8)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.post(endpoint,json=payload) as r:
                if r.status != 200: return None
                data=await r.json()
                return bool(data.get('matches'))
    except (aiohttp.ClientError, asyncio.TimeoutError): return None

def analyze_url(raw):
    raw=raw.strip()
    candidate=raw if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://',raw) else 'https://'+raw
    try:
        p=urlsplit(candidate); host=(p.hostname or '').lower().rstrip('.')
        if p.scheme not in ('http','https') or not host: return None, 0, ['Не удалось распознать корректную веб-ссылку.']
    except ValueError: return None,0,['Некорректный формат ссылки.']
    reasons=[]; score=0
    if p.scheme=='http': score+=10; reasons.append('Используется HTTP без шифрования.')
    try:
        ipaddress.ip_address(host); score+=35; reasons.append('Вместо домена используется IP-адрес.')
    except ValueError: pass
    if host.startswith('xn--') or '.xn--' in host: score+=25; reasons.append('Обнаружен IDN-домен (возможна визуальная подмена символов).')
    if len(host)>35: score+=10; reasons.append('Необычно длинное доменное имя.')
    if host.count('-')>=3: score+=10; reasons.append('В домене много дефисов.')
    if host.count('.')>=4: score+=10; reasons.append('Необычно много уровней домена.')
    if '@' in p.netloc: score+=30; reasons.append('В адресе есть символ @, который может скрывать настоящий домен.')
    if re.search(r'(login|verify|secure|account|wallet|bonus|gift|claim|support|payment)',host): score+=8; reasons.append('Домен содержит слова, часто встречающиеся в приманках.')
    if len(p.query)>180: score+=5; reasons.append('Очень длинные параметры ссылки.')
    if not reasons: reasons.append('Явных подозрительных признаков в самом адресе не найдено.')
    return candidate,min(score,100),reasons

async def check_url(url):
    normalized,score,reasons=analyze_url(url)
    if not normalized: return 'unknown',0,'\n'.join(reasons)
    external=await google_check(normalized)
    if external is True: score=100; reasons.append('Google Safe Browsing сообщил об угрозе для этой ссылки.')
    elif external is False: reasons.append('Google Safe Browsing не обнаружил совпадений в своей базе на момент проверки.')
    if score>=50: verdict='high'
    elif score>=20: verdict='suspicious'
    else: verdict='low'
    return verdict,score,'\n'.join('• '+x for x in reasons)

SCAM_PATTERNS=[
 ('Требование срочно перевести деньги',r'срочн|прямо сейчас|немедленно|последн(ий|яя) шанс|в течение 10 минут'),
 ('Запрос кодов подтверждения или паролей',r'код из смс|код подтверждения|назовите код|сообщите код|парол[ья]'),
 ('Обещание лёгкого или гарантированного дохода',r'гарантированн(ый|о) доход|без риска|удвоим|пассивный доход|100% прибыли'),
 ('Подозрительная предоплата или комиссия',r'предоплат|комисси[яю].{0,30}получ|оплатите доставку|для получения выплаты'),
 ('Попытка увести общение по ссылке',r'перейдите по ссылке|оформите получение|получить выплату|подтвердите аккаунт'),
 ('Давление или запугивание',r'аккаунт будет заблокирован|штраф|возбуждено дело|ваш сч[её]т заблок'),
]
def analyze_text(text):
    found=[]
    for title,pattern in SCAM_PATTERNS:
        if re.search(pattern,text,re.I|re.S): found.append(title)
    urls=re.findall(r'(?:https?://|www\.)\S+',text,re.I)
    score=min(15*len(found)+10*len(urls),90)
    if len(found)>=3: verdict='high'
    elif found or urls: verdict='suspicious'
    else: verdict='low'
    lines=['• '+x for x in found] or ['• Встроенные правила не нашли типичных признаков обмана.']
    if urls: lines.append(f'• Найдено ссылок: {len(urls)}. Проверяйте каждую отдельно.')
    lines.append('• Автоматический анализ не понимает весь контекст и может ошибаться.')
    return verdict,score,'\n'.join(lines)

async def report_count(kind,target):
    async with aiosqlite.connect(DB_PATH) as db:
        cur=await db.execute("SELECT COUNT(*) FROM reports WHERE kind=? AND lower(target)=lower(?) AND status='approved'",(kind,target))
        return (await cur.fetchone())[0]

async def check_phone(phone):
    normalized=re.sub(r'[\s()\-]','',phone)
    if not re.fullmatch(r'\+?\d{7,15}',normalized): return None
    count=await report_count('phone',normalized)
    if count: return 'suspicious',min(30+count*15,90),f'В базе есть {count} подтверждённых пользовательских жалоб на этот номер.'
    return 'unknown',0,'В нашей базе пока нет подтверждённых жалоб на этот номер. Это не доказывает его безопасность.'

async def send_result(message, kind, target, verdict, score, explanation):
    labels={'high':'🔴 Высокий риск','suspicious':'🟠 Есть подозрительные признаки','low':'🟢 Явных признаков не найдено','unknown':'⚪ Недостаточно данных'}
    await log_check(message.from_user.id,kind,target,verdict,score,explanation)
    await message.answer(f'<b>Результат проверки</b>\n\n{labels[verdict]}\nОценка риска: <b>{score}/100</b>\n\n{esc(explanation)}\n\n<i>Оценка автоматическая и не является гарантией безопасности.</i>',reply_markup=menu())

@router.message(CommandStart())
async def start(m:Message):
    await touch_user(m.from_user)
    if await is_blocked(m.from_user.id): return await m.answer('Доступ к сервису ограничен.')
    await m.answer('🛡️ <b>ScamShield</b>\n\nПомогаю выявлять признаки интернет-мошенничества. Отправь ссылку, подозрительное сообщение или номер телефона.\n\n<b>Важно:</b> бот не гарантирует безопасность и не заменяет проверку через официальные источники.',reply_markup=menu())

@router.callback_query(F.data=='about')
async def about(c:CallbackQuery):
    await c.answer(); await c.message.answer('ScamShield анализирует технические признаки ссылок, текстовые шаблоны мошенничества и пользовательские жалобы. Результат — ориентир, а не окончательный вердикт. Не отправляйте пароли, SMS-коды, банковские данные и документы.')

@router.callback_query(F.data=='check_url')
async def ask_url(c:CallbackQuery,state:FSMContext):
    await state.set_state(SearchForm.query); await state.update_data(mode='url'); await c.answer(); await c.message.answer('Пришли ссылку целиком. Не открывай её самостоятельно.')

@router.callback_query(F.data=='check_text')
async def ask_text(c:CallbackQuery,state:FSMContext):
    await state.set_state(SearchForm.query); await state.update_data(mode='text'); await c.answer(); await c.message.answer('Перешли подозрительное сообщение или вставь его текст. Не присылай пароли, коды и личные данные.')

@router.callback_query(F.data=='check_phone')
async def ask_phone(c:CallbackQuery,state:FSMContext):
    await state.set_state(SearchForm.query); await state.update_data(mode='phone'); await c.answer(); await c.message.answer('Введи номер телефона в международном формате, например +996700123456.')

@router.message(SearchForm.query)
async def process_query(m:Message,state:FSMContext):
    data=await state.get_data(); await state.clear(); value=(m.text or '').strip()
    if not value or len(value)>MAX_TEXT: return await m.answer('Отправь текст до 5000 символов.')
    mode=data.get('mode')
    if mode=='url':
        if len(value.split())!=1: return await m.answer('Пришли одну ссылку без дополнительного текста.')
        verdict,score,ex=await check_url(value)
        return await send_result(m,'url',value,verdict,score,ex)
    if mode=='text':
        verdict,score,ex=analyze_text(value)
        return await send_result(m,'text',value,verdict,score,ex)
    if mode=='phone':
        result=await check_phone(value)
        if result is None: return await m.answer('Не удалось распознать номер. Используй международный формат, например +996700123456.')
        verdict,score,ex=result
        return await send_result(m,'phone',value,verdict,score,ex)

@router.callback_query(F.data=='report')
async def report_start(c:CallbackQuery,state:FSMContext):
    kb=InlineKeyboardBuilder()
    for label,val in [('Ссылка','url'),('Телефон','phone'),('Telegram-аккаунт','account'),('Другое','other')]: kb.button(text=label,callback_data='rtype:'+val)
    kb.adjust(2,2); await state.set_state(ReportForm.kind); await c.answer(); await c.message.answer('На что хотите пожаловаться?',reply_markup=kb.as_markup())

@router.callback_query(ReportForm.kind,F.data.startswith('rtype:'))
async def report_kind(c:CallbackQuery,state:FSMContext):
    kind=c.data.split(':',1)[1]; await state.update_data(kind=kind); await state.set_state(ReportForm.value); await c.answer(); await c.message.answer('Укажи ссылку, номер или @username. Не отправляй личные данные третьих лиц, кроме самого идентификатора для проверки.')

@router.message(ReportForm.value)
async def report_value(m:Message,state:FSMContext):
    value=(m.text or '').strip()
    if not value or len(value)>500: return await m.answer('Укажи корректный идентификатор длиной до 500 символов.')
    await state.update_data(value=value); await state.set_state(ReportForm.details); await m.answer('Кратко опиши, что произошло. Не прикладывай пароли, коды, данные карт или документы.')

@router.message(ReportForm.details)
async def report_details(m:Message,state:FSMContext,bot:Bot):
    data=await state.get_data(); await state.clear(); details=(m.text or '').strip()[:1500]
    if len(details)<10: return await m.answer('Добавь немного подробностей (не менее 10 символов).')
    async with aiosqlite.connect(DB_PATH) as db:
        cur=await db.execute('INSERT INTO reports(user_id,kind,target,details) VALUES(?,?,?,?)',(m.from_user.id,data['kind'],data['value'],details)); rid=cur.lastrowid; await db.commit()
    await m.answer(f'✅ Жалоба #{rid} отправлена на модерацию. До проверки она не влияет на публичные результаты.',reply_markup=menu())
    kb=InlineKeyboardBuilder(); kb.button(text='✅ Подтвердить',callback_data=f'mod:approve:{rid}'); kb.button(text='❌ Отклонить',callback_data=f'mod:reject:{rid}'); kb.adjust(2)
    for aid in ADMIN_IDS:
        try: await bot.send_message(aid,f'🚨 <b>Жалоба #{rid}</b>\nТип: {esc(data["kind"])}\nОбъект: {esc(data["value"])}\nОписание: {esc(details)}',reply_markup=kb.as_markup())
        except Exception: log.exception('Admin notification failed')

@router.callback_query(F.data=='database')
async def database(c:CallbackQuery):
    await c.answer(); await c.message.answer('📚 <b>База предупреждений</b>\n\nВ публичную базу попадают только жалобы, проверенные модератором. Сейчас доступен поиск по номеру через кнопку «Проверить номер».')

@router.callback_query(F.data.startswith('mod:'))
async def moderate(c:CallbackQuery):
    if c.from_user.id not in ADMIN_IDS: return await c.answer('Нет доступа',show_alert=True)
    _,action,rid=c.data.split(':'); status='approved' if action=='approve' else 'rejected'
    async with aiosqlite.connect(DB_PATH) as db:
        cur=await db.execute("UPDATE reports SET status=?,reviewed_by=? WHERE id=? AND status='pending'",(status,c.from_user.id,int(rid))); await db.commit()
        if cur.rowcount==0: return await c.answer('Жалоба уже обработана',show_alert=True)
    await c.message.edit_reply_markup(reply_markup=None); await c.answer('Жалоба подтверждена' if status=='approved' else 'Жалоба отклонена')

@router.message(Command('stats'))
async def stats(m:Message):
    async with aiosqlite.connect(DB_PATH) as db:
        u=await (await db.execute('SELECT COUNT(*) FROM users')).fetchone(); checks=await (await db.execute('SELECT COUNT(*) FROM checks')).fetchone(); reports=await (await db.execute("SELECT COUNT(*) FROM reports WHERE status='pending'")).fetchone()
    if m.from_user.id not in ADMIN_IDS: return await m.answer('Эта команда доступна администраторам.')
    await m.answer(f'📊 <b>Статистика ScamShield</b>\nПользователей: {u[0]}\nПроверок: {checks[0]}\nЖалоб ожидают модерации: {reports[0]}')

@router.message(Command('cancel'))
async def cancel(m:Message,state:FSMContext):
    await state.clear(); await m.answer('Действие отменено.',reply_markup=menu())

@router.message()
async def fallback(m:Message):
    await touch_user(m.from_user)
    if await is_blocked(m.from_user.id): return
    await m.answer('Выбери действие в меню или используй /start.',reply_markup=menu())

async def main():
    if not TOKEN: raise SystemExit('Укажи BOT_TOKEN в .env')
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    await init_db()
    bot=Bot(TOKEN,default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp=Dispatcher(storage=MemoryStorage()); dp.include_router(router)
    await bot.delete_webhook(drop_pending_updates=True)
    log.info('ScamShield started')
    await dp.start_polling(bot)

if __name__=='__main__': asyncio.run(main())
