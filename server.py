import os,io,csv,re,secrets,hashlib,calendar,unicodedata
from datetime import datetime,date,timedelta,timezone
from pathlib import Path
from fastapi import FastAPI,HTTPException,Depends,Request,Response
from contextlib import asynccontextmanager
from fastapi.responses import FileResponse,StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine,Column,String,Integer,Boolean,DateTime,ForeignKey,UniqueConstraint,select,text
from sqlalchemy.orm import declarative_base,sessionmaker
from sqlalchemy.types import JSON
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

P=Path(__file__).parent
if not os.getenv('DATABASE_URL'):raise RuntimeError('DATABASE_URL PostgreSQL 未設定')
engine=create_engine(os.environ['DATABASE_URL'].replace('postgres://','postgresql://',1),pool_pre_ping=True);Session=sessionmaker(engine);Base=declarative_base();ph=PasswordHasher()

NO_EXPIRY_LABEL='不限期（未購新方案）'
ALL_CAMPUSES=['仁德學院','南英學院']

def clean_text(raw)->str:
 if raw is None:return ''
 if isinstance(raw,float) and raw.is_integer():raw=int(raw)
 s=unicodedata.normalize('NFKC',str(raw)).strip()
 if re.fullmatch(r'\d+\.0',s):s=s[:-2]
 return s

def normalize_phone(raw)->str:
 s=clean_text(raw)
 if not s:return ''
 digits=re.sub(r'\D','',s)
 if digits.startswith('8860') and len(digits)==13:digits=digits[3:]
 elif digits.startswith('886') and len(digits)==12:digits='0'+digits[3:]
 elif len(digits)==9 and digits.startswith('9'):digits='0'+digits
 return digits

def parse_iso_date(raw)->str:
 if isinstance(raw,(date,datetime)):
  return raw.date().isoformat() if isinstance(raw,datetime) else raw.isoformat()
 if isinstance(raw,(int,float)):
  return (date(1899,12,30)+timedelta(days=int(raw))).isoformat()
 s=clean_text(raw).replace('/','-')
 parts=s.split('-')
 if len(parts)==3:
  s=f'{int(parts[0]):04d}-{int(parts[1]):02d}-{int(parts[2]):02d}'
 date.fromisoformat(s)
 return s

def is_valid_iso_date(s:str)->bool:
 if not s:return False
 try:
  date.fromisoformat(s)
  return True
 except ValueError:
  return False

def tw_today()->str:
 return datetime.now(timezone(timedelta(hours=8))).date().isoformat()

def now():return datetime.now(timezone.utc)
def uid():return secrets.token_hex(12)
def digest(t):return hashlib.sha256(t.encode()).hexdigest()
def month(s,n):
 d=date.fromisoformat(s);y=d.year+(d.month-1+n)//12;m=(d.month-1+n)%12+1;return date(y,m,min(d.day,calendar.monthrange(y,m)[1])).isoformat()
def strong(p):return len(p)>=10 and all(re.search(x,p) for x in ['[A-Z]','[a-z]','[0-9]','[^A-Za-z0-9]'])
def pwcheck(p):
 if not strong(p):raise HTTPException(400,'密碼至少10碼，需含大小寫、數字及特殊符號')

def normalize_campuses(raw)->list[str]:
 if not raw:return list(ALL_CAMPUSES)
 valid=[c for c in ALL_CAMPUSES if c in raw]
 return valid if valid else list(ALL_CAMPUSES)

def user_campuses(u)->list[str]:
 if u.role=='superadmin':return list(ALL_CAMPUSES)
 return normalize_campuses(u.campuses)

def check_campus_access(u,campus:str):
 if u.role=='superadmin':return
 if campus not in user_campuses(u):
  raise HTTPException(403,f'您沒有「{campus}」的管理權限')

class User(Base):
 __tablename__='users';id=Column(String,primary_key=True,default=uid);username=Column(String,unique=True);name=Column(String);password_hash=Column(String);password_plain=Column('password_plain',String,default='');role=Column(String);active=Column(Boolean,default=True);student_id=Column(String);campuses=Column('campuses',JSON,default=lambda:list(ALL_CAMPUSES))
class Student(Base):
 __tablename__='students';id=Column(String,primary_key=True,default=uid);name=Column(String);number=Column(String);campus=Column(String);parentName=Column(String);parentPhone=Column(String);studentType=Column(String);planType=Column(String);purchaseDate=Column(String);expiryDate=Column(String);totalClasses=Column(Integer);remainingClasses=Column(Integer);legacyClasses=Column('legacy_classes',Integer,default=0);totalLeaves=Column(Integer);remainingLeaves=Column(Integer);equipment=Column(JSON)
class Attendance(Base):
 __tablename__='attendance';id=Column(String,primary_key=True,default=uid);student_id=Column(String,ForeignKey('students.id'));date=Column(String);campus=Column(String);status=Column(String);note=Column(String);deductedFrom=Column('deducted_from',String,default='plan');__table_args__=(UniqueConstraint('student_id','date'),)
class Renewal(Base):
 __tablename__='renewals';id=Column(String,primary_key=True,default=uid);student_id=Column(String,ForeignKey('students.id'));planType=Column(String);bankLast5=Column(String);requestTime=Column(String);status=Column(String);confirmTime=Column(String);prevExpiryDate=Column(String);newExpiryDate=Column(String)
class Announcement(Base):
 __tablename__='announcements';id=Column(String,primary_key=True,default=uid);title=Column(String);content=Column(String);campus=Column(String,default='ALL');pinned=Column(Boolean,default=False);author=Column(String);createdAt=Column('created_at',String)
class Audit(Base):
 __tablename__='audit';id=Column(String,primary_key=True,default=uid);actor=Column(String);action=Column(String);student_id=Column(String);detail=Column(String);time=Column(DateTime(timezone=True),default=now)
class SessionToken(Base):
 __tablename__='sessions';token_hash=Column(String,primary_key=True);user_id=Column(String,ForeignKey('users.id'));expires=Column(DateTime(timezone=True))

def ensure_schema():
 Base.metadata.create_all(engine)
 with engine.begin() as conn:
  conn.execute(text("ALTER TABLE students ADD COLUMN IF NOT EXISTS legacy_classes INTEGER DEFAULT 0"))
  conn.execute(text("UPDATE students SET legacy_classes = 0 WHERE legacy_classes IS NULL"))
  conn.execute(text("ALTER TABLE attendance ADD COLUMN IF NOT EXISTS deducted_from VARCHAR DEFAULT 'plan'"))
  conn.execute(text("UPDATE attendance SET deducted_from = 'plan' WHERE deducted_from IS NULL"))
  conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_plain VARCHAR DEFAULT ''"))
  conn.execute(text("UPDATE users SET password_plain = '' WHERE password_plain IS NULL"))
  conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS campuses JSON"))

def dbdep():
 with Session() as db:yield db

def auth(request:Request,db=Depends(dbdep)):
 t=request.cookies.get('magic_session');s=db.get(SessionToken,digest(t)) if t else None
 if not s or s.expires<now():raise HTTPException(401,'請重新登入')
 u=db.get(User,s.user_id)
 if not u or not u.active:raise HTTPException(401,'帳號已停用')
 return u

def roles(u,*allowed):
 if u.role not in allowed:raise HTTPException(403,'權限不足')
def own(u,sid):
 if u.role=='parent' and u.student_id!=sid:raise HTTPException(403,'無權讀取')
def log(db,u,action,sid='',detail=''):db.add(Audit(actor=u.username,action=action,student_id=sid,detail=detail))
def eqdefault():return {k:{'size':'','issued':False,'date':''} for k in ['jersey','pants','practiceShirt','hat','belt','towel']}

def student(db,sid,lock=False,u=None):
 q=select(Student).where(Student.id==sid)
 if lock:q=q.with_for_update()
 s=db.scalar(q)
 if not s:raise HTTPException(404,'學員不存在')
 if u and u.role=='admin':
  check_campus_access(u,s.campus)
 return s

def public(db,s):
 eq={**eqdefault(),**(s.equipment or {})};n=sum(bool(eq[k].get('issued')) for k in eqdefault());eq['status']='已領取' if n==6 else '部分領取' if n else '未領取'
 a=db.scalars(select(Attendance).where(Attendance.student_id==s.id).order_by(Attendance.date.desc())).all();r=db.scalars(select(Renewal).where(Renewal.student_id==s.id).order_by(Renewal.requestTime.desc())).all()
 leg=int(s.legacyClasses or 0)
 rem=int(s.remainingClasses or 0)
 plan_rem=max(0,rem-leg)
 data={k:getattr(s,k) for k in ['id','name','number','campus','parentName','parentPhone','studentType','planType','purchaseDate','expiryDate','totalClasses','remainingClasses','totalLeaves','remainingLeaves']}
 data['legacyClasses']=leg
 data['planRemainingClasses']=plan_rem
 return {**data,'equipment':eq,'attendanceHistory':[{k:getattr(x,k) for k in ['id','date','campus','status','note','deductedFrom']} for x in a],'renewalRequests':[{k:getattr(x,k) for k in ['id','planType','bankLast5','requestTime','status','confirmTime','prevExpiryDate','newExpiryDate']} for x in r]}

@asynccontextmanager
async def lifespan(app):
 ensure_schema()
 initial=os.getenv('BOOTSTRAP_ADMIN_PASSWORD','')
 if initial:
  if not strong(initial):raise RuntimeError('BOOTSTRAP_ADMIN_PASSWORD 密碼強度不足')
  with Session() as db:
   u=db.scalar(select(User).where(User.role=='superadmin'))
   if not u:
    db.add(User(username=os.getenv('BOOTSTRAP_ADMIN_USERNAME','superadmin'),name='超級管理員',password_hash=ph.hash(initial),password_plain='',role='superadmin',active=True,campuses=list(ALL_CAMPUSES)));db.commit()
   elif os.getenv('FORCE_RESET_SUPERADMIN')=='1':
    u.password_hash=ph.hash(initial)
    u.active=True
    for sess in db.scalars(select(SessionToken).where(SessionToken.user_id==u.id)).all():db.delete(sess)
    db.add(Audit(actor='system',action='force_reset_superadmin',student_id='',detail=u.username))
    db.commit()
 yield

app=FastAPI(docs_url=None,redoc_url=None,lifespan=lifespan)

@app.middleware('http')
async def protect_mutations(request:Request,call_next):
 if request.method in ('POST','PUT','PATCH','DELETE') and request.url.path.startswith('/api/'):
  origin=request.headers.get('origin')
  if origin:
   from urllib.parse import urlparse
   host=urlparse(origin).netloc.lower()
   allowed={request.headers.get('host','').lower(),os.getenv('RENDER_EXTERNAL_HOSTNAME','').lower()}
   if host not in allowed or urlparse(origin).scheme!='https' and os.getenv('RENDER')=='true':
    return Response('Origin not allowed',status_code=403)
 return await call_next(request)

app.mount('/static',StaticFiles(directory=P/'static'),name='static')

@app.get('/healthz')
def healthz():
 with engine.connect() as conn:conn.execute(select(1))
 return {'status':'ok'}

@app.get('/')
def index():return FileResponse(P/'static'/'index.html')

class Login(BaseModel):username:str;password:str
@app.post('/api/login')
def login(p:Login,response:Response,db=Depends(dbdep)):
 raw_u=clean_text(p.username)
 phone_u=normalize_phone(raw_u)
 u=db.scalar(select(User).where(User.username==raw_u,User.active==True))
 if not u and phone_u and phone_u!=raw_u:
  u=db.scalar(select(User).where(User.username==phone_u,User.active==True))
 try:
  if not u or not ph.verify(u.password_hash,p.password):raise ValueError()
 except (ValueError,VerificationError):raise HTTPException(401,'帳號或密碼錯誤')
 t=secrets.token_urlsafe(40);db.add(SessionToken(token_hash=digest(t),user_id=u.id,expires=now()+timedelta(hours=12)));db.commit();response.set_cookie('magic_session',t,httponly=True,secure=os.getenv('COOKIE_SECURE','1')=='1',samesite='lax',max_age=43200);return {'role':u.role,'name':u.name,'username':u.username,'campuses':user_campuses(u)}

@app.post('/api/logout')
def logout(request:Request,response:Response,db=Depends(dbdep)):
 t=request.cookies.get('magic_session');s=db.get(SessionToken,digest(t)) if t else None
 if s:db.delete(s);db.commit()
 response.delete_cookie('magic_session');return {'ok':True}

@app.get('/api/me')
def me(u=Depends(auth)):return {'role':u.role,'name':u.name,'username':u.username,'campuses':user_campuses(u)}

@app.get('/api/announcements')
def list_announcements(db=Depends(dbdep),u=Depends(auth)):
 rows=db.scalars(select(Announcement).order_by(Announcement.pinned.desc(),Announcement.createdAt.desc())).all()
 if u.role=='parent':
  st=db.get(Student,u.student_id)
  sc=st.campus if st else ''
  rows=[r for r in rows if r.campus in ('ALL',sc)]
 elif u.role=='admin':
  ac=user_campuses(u)
  rows=[r for r in rows if r.campus in ('ALL',*ac)]
 return [{'id':r.id,'title':r.title,'content':r.content,'campus':r.campus,'pinned':bool(r.pinned),'author':r.author,'createdAt':r.createdAt} for r in rows]

class AnnouncementIn(BaseModel):
 title:str
 content:str
 campus:str='ALL'
 pinned:bool=False

@app.post('/api/announcements')
def create_announcement(p:AnnouncementIn,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin')
 title=clean_text(p.title)
 content=(p.content or '').strip()
 if not title or not content:
  raise HTTPException(400,'請填寫公告標題與內容')
 ac=user_campuses(u)
 target=p.campus or 'ALL'
 if target=='ALL':
  if u.role=='admin' and len(ac)<len(ALL_CAMPUSES):
   target=ac[0]
 elif target not in ALL_CAMPUSES:
  raise HTTPException(400,'學院選擇錯誤')
 elif u.role=='admin' and target not in ac:
  raise HTTPException(403,f'您沒有「{target}」的公告發佈權限')
 tw_now=datetime.now(timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M')
 ann=Announcement(title=title,content=content,campus=target,pinned=bool(p.pinned),author=u.name or u.username,createdAt=tw_now)
 db.add(ann)
 log(db,u,'add_announcement',detail=f'{target}: {title}')
 db.commit()
 return {'id':ann.id}

@app.delete('/api/announcements/{aid}')
def delete_announcement(aid:str,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin')
 ann=db.get(Announcement,aid)
 if not ann:raise HTTPException(404,'公告不存在')
 if u.role=='admin':
  ac=user_campuses(u)
  if ann.campus not in ac and ann.author not in (u.name,u.username):
   raise HTTPException(403,'無權刪除此公告')
 log(db,u,'delete_announcement',detail=ann.title)
 db.delete(ann);db.commit();return {'ok':True}

@app.get('/api/students')
def students(db=Depends(dbdep),u=Depends(auth)):
 q=select(Student).order_by(Student.campus,Student.number)
 if u.role=='parent':q=q.where(Student.id==u.student_id)
 elif u.role=='admin':q=q.where(Student.campus.in_(user_campuses(u)))
 return [public(db,s) for s in db.scalars(q)]

class StudentIn(BaseModel):
 name:str
 number:str=''
 campus:str='仁德學院'
 parentName:str=''
 parentPhone:str
 password:str
 studentType:str='新生'
 planType:str='A'
 purchaseDate:str
 legacyClasses:int|None=None
 remainingLeaves:int|None=None
 equipment:dict|None=None

@app.post('/api/students')
def addstudent(p:StudentIn,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin');pwcheck(p.password)
 check_campus_access(u,p.campus)
 phone=normalize_phone(p.parentPhone)
 if not clean_text(p.name) or not re.fullmatch(r'09\d{8}',phone):raise HTTPException(400,'請填寫學員姓名與正確家長手機（09 開頭 10 碼）')
 if p.planType not in ('A','B'):raise HTTPException(400,'方案錯誤')
 if db.scalar(select(User).where(User.username==phone)):raise HTTPException(409,'家長帳號已存在，暫不支援共用手機多位學員')
 try:
  purchase_dt=parse_iso_date(p.purchaseDate)
 except (ValueError,TypeError):
  raise HTTPException(400,'日期格式錯誤，請使用 YYYY-MM-DD')
 c,l,m=(11,4,4) if p.planType=='A' else (12,8,6)
 if p.studentType=='舊生':
  if p.legacyClasses is None or p.legacyClasses<0:
   raise HTTPException(400,'舊生請填寫原本剩餘堂數（0 以上的整數）')
  leg=int(p.legacyClasses)
  tot_c=leg
  rem_c=leg
  exp_dt=NO_EXPIRY_LABEL
  rem_l=l if p.remainingLeaves is None else int(p.remainingLeaves)
  if rem_l<0:raise HTTPException(400,'剩餘請假不可為負數')
  tot_l=max(l,rem_l)
 else:
  leg=0
  tot_c=c
  rem_c=c
  exp_dt=month(purchase_dt,m)
  tot_l=l
  rem_l=l
 s=Student(name=clean_text(p.name),number=clean_text(p.number),campus=p.campus,parentName=clean_text(p.parentName),parentPhone=phone,studentType=p.studentType,planType=p.planType,purchaseDate=purchase_dt,expiryDate=exp_dt,totalClasses=tot_c,remainingClasses=rem_c,legacyClasses=leg,totalLeaves=tot_l,remainingLeaves=rem_l,equipment={k:{'size':clean_text((p.equipment or {}).get(k,{}).get('size',''))[:30],'issued':False,'date':''} for k in eqdefault()})
 db.add(s);db.flush();db.add(User(username=phone,name=clean_text(p.parentName) or clean_text(p.name),role='parent',password_hash=ph.hash(p.password),password_plain='',student_id=s.id));log(db,u,'add_student',s.id);db.commit();return {'id':s.id}

@app.get('/api/students/{sid}/account')
def student_account(sid:str,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin')
 st=student(db,sid,u=u)
 account=db.scalar(select(User).where(User.student_id==st.id,User.role=='parent'))
 return {'username':account.username if account else st.parentPhone,'active':bool(account and account.active),'hasAccount':bool(account)}

class ResetStudentPassword(BaseModel):newPassword:str
@app.post('/api/students/{sid}/reset-password')
def reset_student_password(sid:str,p:ResetStudentPassword,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin');pwcheck(p.newPassword)
 st=student(db,sid,True)
 account=db.scalar(select(User).where(User.student_id==st.id,User.role=='parent'))
 if not account:raise HTTPException(404,'此學員尚無家長登入帳號')
 account.password_hash=ph.hash(p.newPassword)
 for sess in db.scalars(select(SessionToken).where(SessionToken.user_id==account.id)).all():db.delete(sess)
 log(db,u,'reset_parent_password',sid)
 db.commit();return {'ok':True}

@app.delete('/api/students/{sid}')
def delete_student(sid:str,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin')
 st=student(db,sid,True)
 accounts=db.scalars(select(User).where(User.student_id==sid)).all()
 for account in accounts:
  for sess in db.scalars(select(SessionToken).where(SessionToken.user_id==account.id)).all():db.delete(sess)
  db.delete(account)
 for model in (Attendance,Renewal):
  for record in db.scalars(select(model).where(model.student_id==sid)).all():db.delete(record)
 log(db,u,'delete_student',sid,st.name)
 db.delete(st);db.commit();return {'ok':True}

class AttendanceIn(BaseModel):date:str;status:str;note:str=''
@app.post('/api/students/{sid}/attendance')
def attendance(sid:str,p:AttendanceIn,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin')
 if p.status not in ('present','leave','absent'):raise HTTPException(400,'狀態錯誤')
 s=student(db,sid,True,u=u)
 if db.scalar(select(Attendance).where(Attendance.student_id==sid,Attendance.date==p.date)):raise HTTPException(409,'當日已點名')
 deducted_from='plan'
 if p.status=='leave':
  if int(s.remainingLeaves or 0)<1:raise HTTPException(409,'剩餘請假額度不足')
  s.remainingLeaves=int(s.remainingLeaves)-1
  deducted_from='leave'
 else:
  if int(s.remainingClasses or 0)<1:raise HTTPException(409,'剩餘堂數不足')
  leg=int(s.legacyClasses or 0)
  if leg>0:
   s.legacyClasses=leg-1
   deducted_from='legacy'
  else:
   deducted_from='plan'
  s.remainingClasses=int(s.remainingClasses)-1
 db.add(Attendance(student_id=sid,date=p.date,campus=s.campus,status=p.status,note=p.note,deductedFrom=deducted_from))
 log(db,u,'attendance',sid,f'{p.status}:{deducted_from}')
 db.commit();return {'ok':True}

@app.delete('/api/students/{sid}/attendance/{day}')
def cancel(sid:str,day:str,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin');s=student(db,sid,True,u=u);a=db.scalar(select(Attendance).where(Attendance.student_id==sid,Attendance.date==day))
 if not a:raise HTTPException(404,'找不到紀錄')
 if a.status=='leave':
  s.remainingLeaves=int(s.remainingLeaves or 0)+1
 else:
  s.remainingClasses=int(s.remainingClasses or 0)+1
  if (a.deductedFrom or 'plan')=='legacy':
   s.legacyClasses=int(s.legacyClasses or 0)+1
 db.delete(a);log(db,u,'cancel_attendance',sid,day);db.commit();return {'ok':True}

class NoteIn(BaseModel):note:str
@app.patch('/api/students/{sid}/attendance/{day}')
def note(sid:str,day:str,p:NoteIn,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin');student(db,sid,u=u);a=db.scalar(select(Attendance).where(Attendance.student_id==sid,Attendance.date==day))
 if not a:raise HTTPException(404,'請先點名')
 a.note=p.note;log(db,u,'note',sid);db.commit();return {'ok':True}

class EquipmentIn(BaseModel):equipment:dict
@app.put('/api/students/{sid}/equipment')
def equipment(sid:str,p:EquipmentIn,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin');s=student(db,sid,True,u=u);s.equipment={k:{'size':clean_text(p.equipment.get(k,{}).get('size','')),'issued':bool(p.equipment.get(k,{}).get('issued',False)),'date':clean_text(p.equipment.get(k,{}).get('date',''))} for k in eqdefault()};log(db,u,'equipment',sid);db.commit();return {'ok':True}

class Balance(BaseModel):remainingClasses:int;legacyClasses:int|None=None;remainingLeaves:int;reason:str=''
@app.patch('/api/students/{sid}/balance')
def balance(sid:str,p:Balance,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin')
 if min(p.remainingClasses,p.remainingLeaves)<0:raise HTTPException(400,'不可為負數')
 s=student(db,sid,True)
 leg=int(s.legacyClasses or 0) if p.legacyClasses is None else int(p.legacyClasses)
 if leg<0:raise HTTPException(400,'原本剩餘堂數不可為負數')
 if leg>p.remainingClasses:raise HTTPException(400,'原本剩餘堂數不可大於總剩餘堂數')
 s.remainingClasses=p.remainingClasses
 s.legacyClasses=leg
 s.remainingLeaves=p.remainingLeaves
 log(db,u,'adjust_balance',sid,p.reason);db.commit();return {'ok':True}

class RenewalIn(BaseModel):planType:str;bankLast5:str
@app.post('/api/students/{sid}/renewals')
def renewal(sid:str,p:RenewalIn,db=Depends(dbdep),u=Depends(auth)):
 own(u,sid)
 if p.planType not in ('A','B') or not re.fullmatch('[0-9]{5}',p.bankLast5):raise HTTPException(400,'輸入不正確')
 s=student(db,sid,True)
 if db.scalar(select(Renewal).where(Renewal.student_id==sid,Renewal.status=='pending')):raise HTTPException(409,'已有待審核續約')
 months=4 if p.planType=='A' else 6
 base_dt=s.expiryDate if is_valid_iso_date(s.expiryDate) else tw_today()
 db.add(Renewal(student_id=sid,planType=p.planType,bankLast5=p.bankLast5,requestTime=now().isoformat(),status='pending',confirmTime='',prevExpiryDate=s.expiryDate,newExpiryDate=month(base_dt,months)))
 log(db,u,'renewal_request',sid);db.commit();return {'ok':True}

@app.post('/api/renewals/{rid}/approve')
def approve(rid:str,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin');r=db.scalar(select(Renewal).where(Renewal.id==rid).with_for_update())
 if not r or r.status!='pending':raise HTTPException(409,'無待審核資料')
 s=student(db,r.student_id,True);c,l,m=(11,4,4) if r.planType=='A' else (12,8,6)
 r.prevExpiryDate=s.expiryDate
 base_dt=s.expiryDate if is_valid_iso_date(s.expiryDate) else tw_today()
 r.newExpiryDate=month(base_dt,m)
 s.expiryDate=r.newExpiryDate
 s.planType=r.planType
 s.totalClasses=int(s.totalClasses or 0)+c
 s.remainingClasses=int(s.remainingClasses or 0)+c
 s.totalLeaves=int(s.totalLeaves or 0)+l
 s.remainingLeaves=int(s.remainingLeaves or 0)+l
 r.status='approved';r.confirmTime=now().isoformat()
 log(db,u,'approve_renewal',s.id);db.commit();return {'ok':True}

class PasswordIn(BaseModel):oldPassword:str;newPassword:str
@app.post('/api/password')
def password(p:PasswordIn,db=Depends(dbdep),u=Depends(auth)):
 pwcheck(p.newPassword)
 try:ph.verify(u.password_hash,p.oldPassword)
 except VerificationError:raise HTTPException(400,'舊密碼錯誤')
 u.password_hash=ph.hash(p.newPassword)
 if u.role=='admin':u.password_plain=p.newPassword
 log(db,u,'change_password');db.commit();return {'ok':True}

class AdminIn(BaseModel):username:str;name:str;password:str;campuses:list[str]=list(ALL_CAMPUSES)
@app.get('/api/admins')
def admins(db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin')
 return [{'id':x.id,'username':x.username,'name':x.name,'password':x.password_plain or '','campuses':normalize_campuses(x.campuses),'active':x.active} for x in db.scalars(select(User).where(User.role=='admin'))]

@app.post('/api/admins')
def addadmin(p:AdminIn,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin');pwcheck(p.password)
 uname=clean_text(p.username)
 if not uname or not clean_text(p.name):raise HTTPException(400,'請填寫管理員帳號與姓名')
 valid_campuses=[c for c in ALL_CAMPUSES if c in (p.campuses or [])]
 if not valid_campuses:raise HTTPException(400,'請至少勾選一個可管理的學院')
 if db.scalar(select(User).where(User.username==uname)):raise HTTPException(409,'帳號已存在')
 db.add(User(username=uname,name=clean_text(p.name),role='admin',password_hash=ph.hash(p.password),password_plain=p.password,campuses=valid_campuses,active=True))
 log(db,u,'add_admin',detail=f'{uname} ({",".join(valid_campuses)})');db.commit();return {'ok':True}

class AdminUpdate(BaseModel):campuses:list[str]|None=None;newPassword:str|None=None
@app.patch('/api/admins/{aid}')
def update_admin(aid:str,p:AdminUpdate,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin');a=db.get(User,aid)
 if not a or a.role!='admin':raise HTTPException(404,'帳號不存在')
 details=[]
 if p.campuses is not None:
  valid_campuses=[c for c in ALL_CAMPUSES if c in p.campuses]
  if not valid_campuses:raise HTTPException(400,'請至少勾選一個可管理的學院')
  a.campuses=valid_campuses
  details.append('campuses='+','.join(valid_campuses))
 if p.newPassword is not None and p.newPassword!='':
  pwcheck(p.newPassword)
  a.password_hash=ph.hash(p.newPassword)
  a.password_plain=p.newPassword
  for sess in db.scalars(select(SessionToken).where(SessionToken.user_id==a.id)).all():db.delete(sess)
  details.append('reset_password')
 log(db,u,'update_admin',detail=f'{a.username}: {";".join(details)}');db.commit();return {'ok':True}

@app.patch('/api/admins/{aid}/toggle')
def toggle(aid:str,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin');a=db.get(User,aid)
 if not a or a.role!='admin':raise HTTPException(404,'帳號不存在')
 a.active=not a.active;log(db,u,'toggle_admin',detail=a.username);db.commit();return {'ok':True}

@app.delete('/api/admins/{aid}')
def delete_admin(aid:str,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin');a=db.get(User,aid)
 if not a or a.role!='admin':raise HTTPException(404,'帳號不存在')
 for sess in db.scalars(select(SessionToken).where(SessionToken.user_id==a.id)).all():db.delete(sess)
 log(db,u,'delete_admin',detail=f'{a.username} ({a.name})')
 db.delete(a);db.commit();return {'ok':True}

@app.get('/api/export.xlsx')
def export(db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin')
 allowed_campuses=user_campuses(u)
 from openpyxl import Workbook
 w=Workbook();w.remove(w.active)
 allowed_sids={s.id for s in db.scalars(select(Student).where(Student.campus.in_(allowed_campuses)))}
 for name,model,fields in [('學員名冊',Student,['id','name','number','campus','parentName','parentPhone','studentType','planType','purchaseDate','expiryDate','totalClasses','remainingClasses','legacyClasses','totalLeaves','remainingLeaves']),('點名紀錄',Attendance,['student_id','date','campus','status','deductedFrom','note']),('續約紀錄',Renewal,['student_id','planType','bankLast5','requestTime','status','confirmTime','prevExpiryDate','newExpiryDate'])]:
  sh=w.create_sheet(name);sh.append(fields)
  if name=='學員名冊':
   sh.column_dimensions['F'].number_format='@'
   sh.column_dimensions['F'].width=16
  rows_iter=db.scalars(select(model))
  idx=2
  for x in rows_iter:
   if name=='學員名冊' and x.campus not in allowed_campuses:continue
   if name!='學員名冊' and x.student_id not in allowed_sids:continue
   row_vals=[getattr(x,k) for k in fields]
   if name=='學員名冊':
    phone_val=normalize_phone(x.parentPhone) or clean_text(x.parentPhone)
    row_vals[5]=str(phone_val)
   sh.append(row_vals)
   if name=='學員名冊':
    cell=sh.cell(row=idx,column=6)
    cell.value=str(row_vals[5])
    cell.number_format='@'
   idx+=1
 sh=w.create_sheet('裝備領用');sh.append(['學員ID','項目','尺寸','已領取','日期'])
 for s in db.scalars(select(Student).where(Student.campus.in_(allowed_campuses))):
  for k,v in (s.equipment or {}).items():sh.append([s.id,k,v.get('size',''),v.get('issued',False),v.get('date','')])
 b=io.BytesIO();w.save(b);b.seek(0);return StreamingResponse(b,media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',headers={'Content-Disposition':'attachment; filename="magic_baseball.xlsx"'})


# Bulk Excel import: single transaction; no plaintext passwords in spreadsheets.
REQUIRED_IMPORT_HEADERS = ['學員姓名','背號','場域','家長姓名','家長電話','新舊生','方案','購買生效日','制服尺寸','球褲尺寸','練習衣尺寸']
TEMPLATE_IMPORT_HEADERS = ['學員姓名','背號','場域','家長姓名','家長電話','新舊生','方案','購買生效日','原本剩餘堂數','制服尺寸','球褲尺寸','練習衣尺寸']

@app.get('/api/students/import-template.xlsx')
def import_template(u=Depends(auth)):
 roles(u,'admin','superadmin')
 from openpyxl import Workbook
 w=Workbook();sh=w.active;sh.title='學員匯入';sh.append(TEMPLATE_IMPORT_HEADERS)
 sh.append(['測試新生',15,'仁德學院','測試家長A','0900000001','新生','A','2026-11-02','',140,140,'M'])
 sh.append(['測試舊生',28,'南英學院','測試家長B','0900000002','舊生','B','2026-11-02',7,150,150,'L'])
 sh.column_dimensions['E'].number_format='@'
 for r in range(1,1001):
  cell=sh.cell(row=r,column=5)
  cell.number_format='@'
  if r>=2 and cell.value is not None:
   cell.value=str(cell.value)
 sh.freeze_panes='A2'
 for col in sh.columns:
  sh.column_dimensions[col[0].column_letter].width=18
 sh2=w.create_sheet('使用說明')
 sh2.append(['僅上傳 .xlsx；第一列欄名請勿修改。範例第 2、3 列請刪除後再匯入。'])
 sh2.append(['新舊生為「新生」時：原本剩餘堂數請留空，系統自動依購買生效日與方案計算堂數與到期日。'])
 sh2.append(['新舊生為「舊生」時：請填入「原本剩餘堂數」（數字），舊生原本堂數不計算到期日；後續新購方案時才開始計算到期日，且上課優先扣除原本剩餘堂數。'])
 sh2.append(['家長電話：整欄已設定為純文字格式（@），直接輸入 0912345678 即可保留開頭的 0。'])
 sh2.append(['不含密碼：匯入的家長帳號預設停用，需由超級管理員重設密碼並啟用。'])
 sh2.append(['同一檔案內或資料庫中家長電話重複，整批拒絕，不會寫入部分資料。'])
 sh2.append(['方案 A：11 堂/4 個月/4 次請假；方案 B：12 堂/6 個月/8 次請假。'])
 b=io.BytesIO();w.save(b);b.seek(0)
 return StreamingResponse(b,media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',headers={'Content-Disposition':'attachment; filename="magic_students_import_template.xlsx"'})

@app.post('/api/students/import.xlsx')
async def import_students_excel(request:Request,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'admin','superadmin')
 allowed_campuses=user_campuses(u)
 from openpyxl import load_workbook
 raw=await request.body()
 if len(raw)>3_000_000:raise HTTPException(413,'檔案超過 3 MB 限制')
 if not raw.startswith(b'PK') :raise HTTPException(400,'請上傳 .xlsx Excel 檔案')
 try:
  w=load_workbook(io.BytesIO(raw),read_only=True,data_only=True)
  sh=w['學員匯入'] if '學員匯入' in w.sheetnames else w.active
  rows=sh.iter_rows(values_only=True)
  header=[clean_text(v) for v in next(rows)]
  missing=[h for h in REQUIRED_IMPORT_HEADERS if h not in header]
  if missing:raise HTTPException(400,'缺少欄位：'+', '.join(missing))
  idx={h:header.index(h) for h in header if h}
  prepared=[];errors=[];seen=set()
  for excel_row,values in enumerate(rows,2):
   if excel_row>502:raise HTTPException(400,'單次最多匯入 500 位學員')
   if not any(v is not None and clean_text(v) for v in values):continue
   def val(k):
    if k not in idx:return ''
    i=idx[k];v=values[i] if i<len(values) else None
    return clean_text(v)
   name=val('學員姓名')
   phone=normalize_phone(values[idx['家長電話']] if idx['家長電話']<len(values) else None)
   campus=val('場域')
   stype=val('新舊生') or '新生'
   plan=val('方案').upper().replace('方案','').strip()
   start_raw=values[idx['購買生效日']] if idx['購買生效日']<len(values) else None
   try:
    start=parse_iso_date(start_raw)
   except (ValueError,TypeError):
    errors.append(f'第 {excel_row} 列：購買生效日格式應為 YYYY-MM-DD');continue
   if not name or not re.fullmatch(r'09\d{8}',phone):errors.append(f'第 {excel_row} 列：姓名或家長手機格式錯誤（須為 09 開頭 10 碼）');continue
   if campus not in ALL_CAMPUSES or plan not in ('A','B'):errors.append(f'第 {excel_row} 列：場域或方案錯誤');continue
   if campus not in allowed_campuses:errors.append(f'第 {excel_row} 列：您無權匯入「{campus}」學員');continue
   if stype not in ('新生','舊生'):errors.append(f'第 {excel_row} 列：新舊生請填「新生」或「舊生」');continue
   if phone in seen:errors.append(f'第 {excel_row} 列：檔案內家長手機重複');continue

   c,l,m=(11,4,4) if plan=='A' else (12,8,6)
   raw_leg=val('原本剩餘堂數') or val('原本堂數')
   if stype=='舊生':
    if not raw_leg:
     errors.append(f'第 {excel_row} 列：舊生請填寫「原本剩餘堂數」');continue
    try:
     leg=int(float(raw_leg))
     if leg<0:raise ValueError()
    except ValueError:
     errors.append(f'第 {excel_row} 列：原本剩餘堂數須為 0 以上的整數');continue
    tot_c=leg
    rem_c=leg
    exp_dt=NO_EXPIRY_LABEL
   else:
    leg=0
    tot_c=c
    rem_c=c
    exp_dt=month(start,m)

   seen.add(phone)
   prepared.append(dict(name=name,number=val('背號'),campus=campus,parentName=val('家長姓名'),parentPhone=phone,studentType=stype,planType=plan,purchaseDate=start,expiryDate=exp_dt,totalClasses=tot_c,remainingClasses=rem_c,legacyClasses=leg,totalLeaves=l,remainingLeaves=l,jersey=val('制服尺寸'),pants=val('球褲尺寸'),practiceShirt=val('練習衣尺寸')))
  w.close()
 except HTTPException:raise
 except Exception:raise HTTPException(400,'無法讀取 Excel，請使用下載的範本並另存為 .xlsx')
 if not prepared and not errors:raise HTTPException(400,'Excel 沒有學員資料')
 if errors:raise HTTPException(400,'；'.join(errors[:12]))
 for item in prepared:
  if db.scalar(select(User.id).where(User.username==item['parentPhone'])) or db.scalar(select(Student.id).where(Student.parentPhone==item['parentPhone'])):
   errors.append(item['name']+'：家長手機已存在 '+item['parentPhone'][-4:])
 if errors:raise HTTPException(409,'；'.join(errors[:12])+'。本次未匯入任何資料')
 for item in prepared:
  eq=eqdefault()
  for k in ('jersey','pants','practiceShirt'):eq[k]['size']=item[k]
  st=Student(name=item['name'],number=item['number'],campus=item['campus'],parentName=item['parentName'],parentPhone=item['parentPhone'],studentType=item['studentType'],planType=item['planType'],purchaseDate=item['purchaseDate'],expiryDate=item['expiryDate'],totalClasses=item['totalClasses'],remainingClasses=item['remainingClasses'],legacyClasses=item['legacyClasses'],totalLeaves=item['totalLeaves'],remainingLeaves=item['remainingLeaves'],equipment=eq)
  db.add(st);db.flush()
  db.add(User(username=item['parentPhone'],name=item['parentName'] or item['name'],password_hash=ph.hash(secrets.token_urlsafe(32)),password_plain='',role='parent',active=False,student_id=st.id))
  log(db,u,'excel_import_student',st.id)
 db.commit()
 return {'ok':True,'imported':len(prepared),'message':f'成功匯入 {len(prepared)} 位學員；家長帳號預設停用，請由超級管理員設定密碼並啟用'}

@app.post('/api/students/{sid}/activate-parent')
def activate_parent(sid:str,db=Depends(dbdep),u=Depends(auth)):
 roles(u,'superadmin')
 st=student(db,sid,True)
 account=db.scalar(select(User).where(User.student_id==st.id,User.role=='parent'))
 if not account:raise HTTPException(404,'找不到家長帳號')
 account.active=True;log(db,u,'activate_parent',sid);db.commit();return {'ok':True}