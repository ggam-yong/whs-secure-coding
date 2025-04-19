from flask import Flask, render_template, request, redirect, url_for, session, flash, abort,g
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, SelectField, Form
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange
from markupsafe import escape
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from datetime import datetime, timedelta

import sqlite3
import uuid
import bcrypt
import time

# Flask 기본 설정
app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secure-key!'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # 운영 환경에서만 활성화 권장
csrf = CSRFProtect(app)

socketio = SocketIO(app, manage_session=False)
user_last_sent = {}  # 스팸 방지용 사용자 타임스탬프
DATABASE = 'market.db'

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 회원가입 폼
class RegisterForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6)])

# 로그인 폼
class LoginForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])

# 소개글 폼
class BioForm(FlaskForm):
    bio = TextAreaField('소개글', validators=[Length(max=200)])

# 비밀번호 수정 폼
class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('기존 비밀번호')
    new_password = PasswordField('새 비밀번호', validators=[Length(min=6)])
    confirm_password = PasswordField('새 비밀번호 확인', validators=[
        EqualTo('new_password', message='비밀번호가 일치하지 않습니다')
    ])

# 상품 편집 폼
class ProductEditForm(FlaskForm):
    title = StringField('제목', validators=[DataRequired(), Length(max=50)])
    description = TextAreaField('설명', validators=[DataRequired(), Length(max=300)])
    price = IntegerField('가격', validators=[DataRequired(), NumberRange(min=100, max=1000000)])

# 상품 등록 폼
class ProductForm(FlaskForm):
    title = StringField('제목', validators=[DataRequired(), Length(max=50)])
    description = TextAreaField('설명', validators=[DataRequired(), Length(max=300)])
    price = IntegerField('가격', validators=[DataRequired(), NumberRange(min=100, max=1000000)])

# 송금 폼
class TransferForm(FlaskForm):
    amount = IntegerField('송금 금액', validators=[
        DataRequired(), NumberRange(min=100, max=1000000)
    ])

# 신고 폼
class ReportForm(FlaskForm):
    target_type = SelectField('신고 대상 유형', choices=[('user', '유저'), ('product', '상품')], validators=[DataRequired()])
    target_id = StringField('신고 대상 ID', validators=[DataRequired(), Length(min=1, max=50)])
    reason = TextAreaField('신고 사유', validators=[DataRequired(), Length(min=5, max=200)])

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                status TEXT DEFAULT 'active',
                balance INTEGER DEFAULT 10000,
                is_admin INTEGER DEFAULT 0
            )
        """)

        # 상품 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                is_deleted INTEGER DEFAULT 0
            )
        """)

        # 신고 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        # 전체 채팅 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS global_message (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 1:1 채팅 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 포인트 송금 내역
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer_history (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 로그인 실패 횟수 관리
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempt (
                username TEXT PRIMARY KEY,
                fail_count INTEGER DEFAULT 0,
                last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 감사 로그
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_id TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.commit()


# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

#===================로그인, 회원가입 ==============================

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = escape(form.username.data.strip())
        password = form.password.data.strip()

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password, bio, status, balance, is_admin) VALUES (?, ?, ?, '', 'active', 10000, 0)",
                       (user_id, username, hashed_pw))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = escape(form.username.data.strip())
        password = form.password.data.strip()

        db = get_db()
        cursor = db.cursor()

        # 로그인 실패 기록 조회
        cursor.execute("SELECT fail_count, last_attempt FROM login_attempt WHERE username = ?", (username,))
        row = cursor.fetchone()

        now = datetime.utcnow()
        lockout_time = timedelta(minutes=5)

        if row:
            fail_count, last_attempt_str = row['fail_count'], row['last_attempt']
            last_attempt = datetime.fromisoformat(last_attempt_str)
            if fail_count >= 5 and now - last_attempt < lockout_time:
                flash("로그인 시도 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.")
                return redirect(url_for('login'))

        # 사용자 인증
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            if user['status'] != 'active':
                flash('정지된 계정입니다.')
                return redirect(url_for('login'))

            # 로그인 성공 
            cursor.execute("DELETE FROM login_attempt WHERE username = ?", (username,))
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin'] 
            session['username'] = user['username'] 
            session['last_active'] = datetime.utcnow().isoformat()
            db.commit()
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            # 로그인 실패 기록 증가 또는 삽입
            if row:
                cursor.execute("UPDATE login_attempt SET fail_count = fail_count + 1, last_attempt = ? WHERE username = ?",
                               (now.isoformat(), username))
            else:
                cursor.execute("INSERT INTO login_attempt (username, fail_count, last_attempt) VALUES (?, ?, ?)",
                               (username, 1, now.isoformat()))
            db.commit()
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

#=======================대시보드, 이동 ======================================

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 삭제되지 않은 상품만 조회
    cursor.execute("SELECT * FROM product WHERE is_deleted = 0")
    all_products = cursor.fetchall()
    # 저장된 채팅 불러오기
    cursor.execute("SELECT * FROM global_message ORDER BY timestamp ASC")
    messages = cursor.fetchall()


    return render_template('dashboard.html', products=all_products, user=current_user, messages=messages)



@app.route('/users')
def user_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, bio FROM user")
    users = cursor.fetchall()

    return render_template('user_list.html', users=users)


#=================프로필 ===============================

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 사용자 정보 불러오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 포인트 사용 내역
    cursor.execute("""
        SELECT th.*, 
               sender.username AS sender_name, 
               receiver.username AS receiver_name
        FROM transfer_history th
        LEFT JOIN user AS sender ON th.sender_id = sender.id
        LEFT JOIN user AS receiver ON th.receiver_id = receiver.id
        WHERE th.sender_id = ? OR th.receiver_id = ?
        ORDER BY timestamp DESC
    """, (session['user_id'], session['user_id']))
    history = cursor.fetchall()

    # 폼들 생성
    bio_form = BioForm()
    pw_form = PasswordChangeForm()

    action = request.form.get("action")

    if request.method == "POST":
        if action == "update_bio" and bio_form.validate_on_submit():
            new_bio = escape(bio_form.bio.data.strip())
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (new_bio, session['user_id']))
            db.commit()
            flash("소개글이 업데이트되었습니다.")
            return redirect(url_for("profile"))

        elif action == "update_password" and pw_form.validate_on_submit():
            current_pw = pw_form.current_password.data
            new_pw = pw_form.new_password.data

            if not bcrypt.checkpw(current_pw.encode(), current_user["password"].encode()):
                flash("기존 비밀번호가 일치하지 않습니다.")
                return redirect(url_for("profile"))

            hashed_pw = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_pw, session['user_id']))
            db.commit()
            flash("비밀번호가 성공적으로 변경되었습니다.")
            return redirect(url_for("profile"))

    # 기존 bio를 bio_form에 기본값으로 채워넣음
    bio_form.bio.data = current_user["bio"]

    return render_template("profile.html",
                           user=current_user,
                           bio_form=bio_form,
                           pw_form=pw_form,
                           history=history)


# ====================== 상품 ===========================
# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = ProductForm()

    if form.validate_on_submit():
        title = escape(form.title.data.strip())
        description = escape(form.description.data.strip())
        price = form.price.data

        product_id = str(uuid.uuid4())
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html', form=form)  # ✅ form 넘기기


# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 상품 조회
@app.route('/products')
def product_list():
    db = get_db()
    cursor = db.cursor()
    q = request.args.get('q', '').strip()

    if q:
        cursor.execute("SELECT * FROM product WHERE is_deleted = 0 AND title LIKE ?", ('%' + q + '%',))
    else:
        cursor.execute("SELECT * FROM product WHERE is_deleted = 0")
    
    products = cursor.fetchall()
    return render_template('product_list.html', products=products)

# 상품 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product or product['seller_id'] != session['user_id']:
        flash("접근 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    form = ProductEditForm()

    if form.validate_on_submit():
        title = escape(form.title.data.strip())
        description = escape(form.description.data.strip())
        price = form.price.data

        cursor.execute("""
            UPDATE product SET title = ?, description = ?, price = ?
            WHERE id = ?
        """, (title, description, price, product_id))
        db.commit()
        flash("상품이 수정되었습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    # 초기값 세팅
    form.title.data = product['title']
    form.description.data = product['description']
    form.price.data = product['price']

    return render_template('edit_product.html', form=form, product=product)

# 상품 삭제 
@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product or product['seller_id'] != session['user_id']:
        flash("삭제 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('dashboard'))

# =========================송금 ==============================
@app.route('/transfer/<receiver_id>', methods=['GET', 'POST'])
def transfer(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 본인 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 받는 사람 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (receiver_id,))
    receiver = cursor.fetchone()

    if not receiver or receiver['id'] == current_user['id']:
        flash("송금할 수 없는 대상입니다.")
        return redirect(url_for('dashboard'))

    form = TransferForm()

    if form.validate_on_submit():
        amount = form.amount.data
        if current_user['balance'] < amount:
            flash("보유 포인트가 부족합니다.")
            return redirect(request.url)

        # 포인트 이동
        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, current_user['id']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))

        # 내역 저장
        history_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO transfer_history (id, sender_id, receiver_id, amount)
            VALUES (?, ?, ?, ?)
        """, (history_id, current_user['id'], receiver['id'], amount))

        db.commit()
        flash("포인트가 성공적으로 송금되었습니다!")
        return redirect(url_for('dashboard'))

    return render_template('transfer.html', form=form, receiver=receiver, current_user=current_user)




# =============================신고 ====================
# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 사용자 및 상품 목록 가져오기 (선택 리스트용)
    cursor.execute("SELECT id, username FROM user WHERE id != ?", (session['user_id'],))
    users = [dict(u) for u in cursor.fetchall()]

    cursor.execute("SELECT id, title FROM product")
    products = [dict(p) for p in cursor.fetchall()]

    form = ReportForm()

    if form.validate_on_submit():
        reporter_id = session['user_id']
        target_id = escape(form.target_id.data.strip())
        reason = escape(form.reason.data.strip())

        # 입력 검증: 유효한 사용자 or 상품인지 확인
        cursor.execute("SELECT id FROM user WHERE id = ?", (target_id,))
        is_user = cursor.fetchone()

        cursor.execute("SELECT id FROM product WHERE id = ? AND is_deleted = 0", (target_id,))
        is_product = cursor.fetchone()


        if not (is_user or is_product):
            flash("신고 대상이 존재하지 않습니다.")
            return redirect(url_for('report'))

        # 중복 신고 방지
        cursor.execute("SELECT * FROM report WHERE reporter_id = ? AND target_id = ?", (reporter_id, target_id))
        if cursor.fetchone():
            flash("이미 해당 대상을 신고했습니다.")
            return redirect(url_for('report'))

        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, reporter_id, target_id, reason)
        )

        # 🔍 해당 대상의 신고 누적 횟수 확인
        cursor.execute("SELECT COUNT(*) FROM report WHERE target_id = ?", (target_id,))
        report_count = cursor.fetchone()[0]

        # 🧨 상품 신고 횟수 3회 이상 ➜ 삭제 처리
        cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
        product_target = cursor.fetchone()
        if product_target and report_count >= 3:
            cursor.execute("UPDATE product SET is_deleted = 1 WHERE id = ?", (target_id,))
            flash("해당 상품은 다수의 신고로 자동 삭제되었습니다.")

        # 😶 유저 신고 횟수 5회 이상 ➜ 휴면 처리
        cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
        user_target = cursor.fetchone()
        if user_target and report_count >= 5:
            cursor.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (target_id,))
            flash("해당 유저는 다수의 신고로 정지되었습니다.")

        # ✅ 감사 로그 DB 기록 (누락된 필드 추가!)
        log_id = str(uuid.uuid4())
        action = "신고"
        details = reason
        cursor.execute(
            "INSERT INTO audit_log (id, user_id, action, target_id, details) VALUES (?, ?, ?, ?, ?)",
            (log_id, reporter_id, action, target_id, details)
        )

        db.commit()

        flash("신고가 접수되었습니다.")
        return redirect(url_for('dashboard'))

    return render_template("report.html", form=form, users=users, products=products)


# ====================================1:1채팅 =============================

# 1:1 채팅
# 🔒 1:1 채팅 페이지 라우트
@app.route('/chat/<receiver_id>')
def private_chat(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 📌 상대방 유저 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (receiver_id,))
    receiver = cursor.fetchone()
    if not receiver:
        flash('대상을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 💬 기존 채팅 내역 불러오기
    cursor.execute("""
        SELECT * FROM message
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], receiver_id, receiver_id, session['user_id']))
    chat_history = cursor.fetchall()

    return render_template('private_chat.html', receiver=receiver, chat_history=chat_history)
def make_private_room(user1, user2):
    return '_'.join(sorted([user1, user2]))

@socketio.on('join_private', namespace='/')
def join_private(data):
    if 'user_id' not in session:
        return
    room = make_private_room(session['user_id'], data['room'])
    join_room(room)

@socketio.on('send_private_message', namespace='/')
def send_private_message(data):
    if 'user_id' not in session:
        return

    sender_id = session['user_id']
    receiver_id = data.get('to')
    message = escape(data.get('message', '').strip())

    if not message or len(message) > 200:
        return
        

    

    db = get_db()
    cursor = db.cursor()
    msg_id = str(uuid.uuid4())
    cursor.execute("INSERT INTO message (id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)",
                   (msg_id, sender_id, receiver_id, message))
    db.commit()

    room = make_private_room(sender_id, receiver_id)
    socketio.emit('private_message', {
        'from': sender_id,
        'message': message
    }, room=room, namespace='/')



#======================전체 채팅 ===================================

# 실시간 전체 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message', namespace='/')
def handle_send_message_event(data):
    
    if 'user_id' not in session:
        return

    user_id = session['user_id']
    now = time.time()

    # 스팸 방지: 1초 이내 연속 전송 차단
    last = user_last_sent.get(user_id, 0)
    if now - last < 1:
        return
    user_last_sent[user_id] = now

    username = data.get('username', '익명')
    message = data.get('message', '').strip()
    if not message or len(message) > 200:
        return

    clean_message = escape(message)

    # DB 저장
    db = get_db()
    cursor = db.cursor()
    msg_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO global_message (id, username, content) VALUES (?, ?, ?)",
        (msg_id, username, clean_message)
    )
    db.commit()

    # 실시간 브로드캐스트
    socketio.emit(
        'message',
        {'username': escape(username), 'message': clean_message},
        namespace='/'
    )

#====================================관리자 기능 ================================
from flask import abort

# 관리자 대시보드
@app.route("/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        abort(403)

    db = get_db()
    cursor = db.cursor()

    # 사용자 목록
    cursor.execute("SELECT id, username, bio, status FROM user WHERE is_admin = 0")
    users = cursor.fetchall()

    # 상품 목록 (판매자 이름도 함께)
    cursor.execute("""
        SELECT p.id, p.title, p.description, p.price, p.is_deleted, u.username AS seller_username
        FROM product p
        JOIN user u ON p.seller_id = u.id
    """)
    products = cursor.fetchall()

    # 신고 내역
    cursor.execute("""
        SELECT r.id, r.reporter_id, r.target_id, r.reason,
               u1.username AS reporter_name,
               COALESCE(u2.username, p.title) AS target_name,
               CASE
                   WHEN u2.id IS NOT NULL THEN 'user'
                   WHEN p.id IS NOT NULL THEN 'product'
                   ELSE 'unknown'
               END AS target_type,
               u2.status AS target_status,
               p.is_deleted AS product_deleted
        FROM report r
        LEFT JOIN user u1 ON r.reporter_id = u1.id
        LEFT JOIN user u2 ON r.target_id = u2.id
        LEFT JOIN product p ON r.target_id = p.id
        ORDER BY r.id DESC
    """)
    reports = cursor.fetchall()

    return render_template("admin_dashboard.html", users=users, products=products, reports=reports)

# 관리자 : 유저 정지
@app.route('/admin/suspend/<user_id>', methods=['POST'])
def admin_suspend_user(user_id):
    if not session.get("is_admin"):
        abort(403)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (user_id,))
    
    log_id = str(uuid.uuid4())
    action = "관리자에 의한 계정 정지"
    cursor.execute("INSERT INTO audit_log (id, user_id, action, target_id) VALUES (?, ?, ?, ?)",
                   (log_id, session['user_id'], action, user_id))
    db.commit()
    flash("계정이 정지되었습니다.")
    return redirect(url_for("admin_dashboard"))

# 관리자 : 유저 복구
@app.route('/admin/restore/<user_id>', methods=['POST'])
def admin_restore_user(user_id):
    if not session.get("is_admin"):
        abort(403)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET status = 'active' WHERE id = ?", (user_id,))
    
    log_id = str(uuid.uuid4())
    action = "관리자에 의한 계정 복구"
    cursor.execute("INSERT INTO audit_log (id, user_id, action, target_id) VALUES (?, ?, ?, ?)",
                   (log_id, session['user_id'], action, user_id))
    db.commit()
    flash("계정이 복구되었습니다.")
    return redirect(url_for("admin_dashboard"))

# 관리자 : 소개글 삭제
@app.route('/admin/clear_bio/<user_id>', methods=['POST'])
def admin_clear_bio(user_id):
    if not session.get("is_admin"):
        abort(403)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET bio = '' WHERE id = ?", (user_id,))
    
    log_id = str(uuid.uuid4())
    action = "관리자에 의한 소개글 삭제"
    cursor.execute("INSERT INTO audit_log (id, user_id, action, target_id) VALUES (?, ?, ?, ?)",
                   (log_id, session['user_id'], action, user_id))
    db.commit()
    flash("소개글이 삭제되었습니다.")
    return redirect(url_for("admin_dashboard"))

# 관리자: 상품 삭제
@app.route('/admin/delete_product/<product_id>', methods=['POST'])
def delete_product_admin(product_id):
    if not session.get("is_admin"):
        abort(403)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE product SET is_deleted = 1 WHERE id = ?", (product_id,))
    
    log_id = str(uuid.uuid4())
    action = "관리자에 의한 상품 삭제"
    cursor.execute("INSERT INTO audit_log (id, user_id, action, target_id) VALUES (?, ?, ?, ?)",
                   (log_id, session['user_id'], action, product_id))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for("admin_dashboard"))


    
# ========================에러 =================================
@app.errorhandler(404)
def not_found_error(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500  # 디버깅 정보 노출 X

#==========================세션 ==============================

@app.before_request
def check_session_expiration():
    if 'user_id' in session:
        last_active = session.get('last_active')
        if last_active:
            last_active = datetime.fromisoformat(last_active)
            if datetime.utcnow() - last_active > timedelta(minutes=30):
                session.clear()
                flash('세션이 만료되었습니다. 다시 로그인 해주세요.')
                return redirect(url_for('login'))
        session['last_active'] = datetime.utcnow().isoformat()
        
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://cdnjs.cloudflare.com; "
        "connect-src 'self' ws://localhost:5000; "
        "style-src 'self' 'unsafe-inline'; "
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response



if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True) # 배포시 WSS 적용 (암호화 전송) 
