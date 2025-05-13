import os
import datetime
import json
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g, session, send_file, current_app
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash  # For password hashing
import re  # For validation
from sqlalchemy import or_, text, func, String  # Import or_ function, text for raw SQL, func for distinct, String for casting
import copy # 객체 복사를 위해 추가

# 데이터베이스 관련 임포트
from db import get_db, close_db, init_db
from models import Order, User, AccessLog

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'furniture_order_management_secret_key'

# 업로드 경로 설정
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'xlsx', 'xls'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 데이터베이스 연결 설정
app.teardown_appcontext(close_db)

# Function to check if file has allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Order status constants
STATUS = {
    'RECEIVED': '접수',
    'MEASURED': '실측',
    'SCHEDULED': '설치 예정',
    'COMPLETED': '완료',
    'AS_RECEIVED': 'AS 접수',
    'AS_COMPLETED': 'AS 완료',
    'DELETED': '삭제됨'
}

# User roles 
ROLES = {
    'ADMIN': '관리자',         # Full access
    'MANAGER': '매니저',       # Can manage orders but not users
    'STAFF': '직원',           # Can view and add orders, limited edit
    'VIEWER': '뷰어'           # Read-only access
}

# Authentication Helper Functions
def log_access(action, user_id=None, additional_data=None):
    """Log user actions for security monitoring"""
    try:
        db = get_db()
        
        ip_address = request.remote_addr
        user_agent = request.user_agent.string
        
        # 기본 로그 데이터
        log_data = {
            'user_id': user_id,
            'action': action,
            'ip_address': ip_address,
            'user_agent': user_agent
        }
        
        # 추가 데이터가 있으면 처리
        if additional_data:
            # additional_data를 문자열로 변환
            if not isinstance(additional_data, str):
                additional_data_str = json.dumps(additional_data)
            else:
                additional_data_str = additional_data
                
            # 컬럼이 존재하는지 확인하기 위한 시도
            try:
                new_log = AccessLog(
                    **log_data,
                    additional_data=additional_data_str
                )
                db.add(new_log)
                db.commit()
            except Exception as e:
                db.rollback()
                # additional_data 컬럼 오류시 해당 필드 제외하고 로깅
                if 'additional_data' in str(e):
                    new_log = AccessLog(**log_data)
                    db.add(new_log)
                    db.commit()
                    print(f"Warning: additional_data column not available: {str(e)}")
                else:
                    raise e
        else:
            # 추가 데이터가 없는 경우 기본 로깅
            new_log = AccessLog(**log_data)
            db.add(new_log)
            db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error logging access: {str(e)}")

def is_password_strong(password):
    """Check if password meets security requirements"""
    if len(password) < 8:
        return False
    
    # Check for at least one uppercase, one lowercase, and one digit
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    
    return has_upper and has_lower and has_digit

def get_user_by_username(username):
    """Retrieve user by username"""
    db = get_db()
    return db.query(User).filter(User.username == username).first()

def get_user_by_id(user_id):
    """Retrieve user by ID"""
    db = get_db()
    return db.query(User).filter(User.id == user_id).first()

def update_last_login(user_id):
    """Update the last login timestamp for a user"""
    try:
        db = get_db()
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.last_login = datetime.datetime.now()
            db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error updating last login: {str(e)}")

def login_required(f):
    """Decorator to require login for routes"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def role_required(roles):
    """Decorator to require specific roles for routes"""
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('로그인이 필요합니다.', 'error')
                return redirect(url_for('login', next=request.url))
            
            user = get_user_by_id(session['user_id'])
            if not user:
                session.clear()
                flash('사용자를 찾을 수 없습니다. 다시 로그인해주세요.', 'error')
                return redirect(url_for('login'))
            
            if user.role not in roles:
                flash('이 페이지에 접근할 권한이 없습니다.', 'error')
                log_access(f"Unauthorized access attempt to {request.path}", user.id)
                return redirect(url_for('index'))
                
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# Auth Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    next_url = request.args.get('next', url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('아이디와 비밀번호를 모두 입력해주세요.', 'error')
            return render_template('login.html')
        
        # Get user by username
        user = get_user_by_username(username)
        
        if not user:
            log_access(f"Failed login attempt for username: {username}")
            flash('아이디 또는 비밀번호가 일치하지 않습니다.', 'error')
            return render_template('login.html')
        
        # Check if user is active
        if not user.is_active:
            log_access(f"Inactive account login attempt: {username}", user.id)
            flash('비활성화된 계정입니다. 관리자에게 문의하세요.', 'error')
            return render_template('login.html')
        
        # Verify password
        if not check_password_hash(user.password, password):
            log_access(f"Failed login attempt for username: {username} (wrong password)", user.id)
            flash('아이디 또는 비밀번호가 일치하지 않습니다.', 'error')
            return render_template('login.html')
        
        # Login successful
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        
        # Update last login
        update_last_login(user.id)
        
        # Log successful login
        log_access(f"Successful login: {username}", user.id)
        
        flash(f'{user.name}님, 환영합니다!', 'success')
        return redirect(next_url)
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']
        username = session.get('username', 'Unknown')
        
        session.clear()
        log_access(f"Logout: {username}", user_id)
        
        flash('로그아웃되었습니다.', 'success')
    
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    # Check if there are any users in the system
    db = get_db()
    user_count = db.query(User).count()
    
    # If there are already users, redirect to login
    if user_count > 0:
        flash('사용자 등록은 관리자를 통해서만 가능합니다.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name', '관리자')
        
        if not username or not password or not confirm_password:
            flash('모든 필드를 입력해주세요.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.', 'error')
            return render_template('register.html')
        
        if not is_password_strong(password):
            flash('비밀번호는 최소 8자 이상이며, 대문자, 소문자, 숫자를 포함해야 합니다.', 'error')
            return render_template('register.html')
        
        # Check if username already exists
        existing_user = get_user_by_username(username)
        if existing_user:
            flash('이미 사용 중인 아이디입니다.', 'error')
            return render_template('register.html')
        
        # Create new admin user
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            name=name,
            role='ADMIN'  # First user is always admin
        )
        
        db.add(new_user)
        db.commit()
        
        log_access(f"Initial admin account created: {username}")
        
        flash('계정이 생성되었습니다. 로그인해주세요.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Removed email verification and password reset routes

# Context Processors
@app.context_processor
def inject_status_list():
    """상태 목록과 현재 사용자 정보를 템플릿에 주입"""
    # 삭제됨(DELETED) 상태를 제외한 상태 목록
    display_status = {k: v for k, v in STATUS.items() if k != 'DELETED'}
    
    # 일괄 작업용 상태 목록 (삭제됨 제외)
    bulk_action_status = {k: v for k, v in STATUS.items() if k != 'DELETED'}
    
    # 현재 로그인한 사용자 추가
    current_user = None
    if 'user_id' in session:
        current_user = get_user_by_id(session['user_id'])
    
    return dict(
        STATUS=display_status, 
        BULK_ACTION_STATUS=bulk_action_status,
        ALL_STATUS=STATUS, 
        ROLES=ROLES,
        current_user=current_user
    )

def parse_json_string(json_string):
    if not json_string:
        return None
    try:
        return json.loads(json_string)
    except json.JSONDecodeError:
        return None

@app.context_processor
def utility_processor():
    return dict(parse_json_string=parse_json_string)

# Routes
@app.route('/')
@login_required
def index():
    db = get_db()
    status_filter = request.args.get('status')
    search_query = request.args.get('search', '').strip()
    sort_column = request.args.get('sort', 'id')
    sort_direction = request.args.get('direction', 'desc')
    page = request.args.get('page', 1, type=int)
    per_page = 100 # 페이지당 표시할 항목 수

    # 기본 쿼리 생성 (삭제되지 않은 주문만)
    query = db.query(Order).filter(Order.deleted_at.is_(None))
    
    # 상태 필터 적용
    if status_filter:
        query = query.filter(Order.status == status_filter)
    
    # 검색어 필터 적용
    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter( # Corrected indentation for line 1139
            or_(
                Order.id.like(search_term),
                Order.received_date.like(search_term),
                Order.received_time.like(search_term),
                Order.customer_name.like(search_term),
                Order.phone.like(search_term),
                Order.address.like(search_term),
                Order.product.like(search_term),
                Order.options.like(search_term),
                Order.notes.like(search_term),
                Order.status.like(search_term),
                Order.measurement_date.like(search_term),
                Order.measurement_time.like(search_term),
                Order.completion_date.like(search_term),
                Order.manager_name.like(search_term)
            )
        )

    # 컬럼별 입력 필터 적용
    column_filters = {}
    filterable_columns = [
        'id', 'received_date', 'received_time', 'customer_name', 'phone',
        'address', 'product', 'options', 'notes', 'status',
        'measurement_date', 'measurement_time', 'completion_date', 'manager_name', 'payment_amount'
    ]
    for column_name in filterable_columns:
        filter_value = request.args.get(f'filter_{column_name}', '').strip()
        if filter_value:
            if hasattr(Order, column_name):
                # payment_amount 같은 숫자 필터는 정확한 일치 또는 범위 검색이 더 적합할 수 있음
                # 여기서는 일단 모든 필드에 대해 LIKE 검색 적용
                # PostgreSQL에서는 숫자 타입에 LIKE 사용 시 에러 발생 가능 -> 문자열로 변환 필요
                try:
                    column_attr = getattr(Order, column_name)
                    # 숫자 타입 컬럼일 경우 문자열로 캐스팅 후 LIKE 적용
                    if isinstance(column_attr.type.python_type(), (int, float)):
                         query = query.filter(column_attr.cast(String).like(f"%{filter_value}%"))
                    else:
                         query = query.filter(column_attr.like(f"%{filter_value}%"))
                    column_filters[column_name] = filter_value # 활성 필터 값 저장
                except AttributeError:
                    print(f"Warning: Column {column_name} not found or cannot be filtered with LIKE.")
            else:
                 print(f"Warning: Column {column_name} not found in Order model.")

    # 정렬 적용 (index 함수와 동일한 로직)
    if hasattr(Order, sort_column):
        column_to_sort = getattr(Order, sort_column)
        if sort_direction == 'asc':
            query = query.order_by(column_to_sort.asc())
        else:
            query = query.order_by(column_to_sort.desc())
    else: # Corrected indentation for line 1175
        query = query.order_by(Order.id.desc()) # Corrected indentation for line 1176 (기본 정렬)

    # 페이지네이션 적용
    total_orders = query.count()
    orders = query.offset((page - 1) * per_page).limit(per_page).all()

    # 사용자 정보 가져오기 (예: 역할 기반 UI 표시용)
    user = None
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
    
    return render_template(
        'index.html',
                          orders=orders, 
        status_list=STATUS, # 상태 목록은 여전히 필요
                          current_status=status_filter,
        search_query=search_query,
        sort_column=sort_column,
        sort_direction=sort_direction,
        page=page,
        per_page=per_page,
        total_orders=total_orders,
        active_column_filters=column_filters, # 입력 필터 값 전달 (변경 후)
        user=user # 사용자 정보 전달
    )

@app.route('/add', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN', 'MANAGER', 'STAFF'])
def add_order():
    if request.method == 'POST':
        try:
            db = get_db()
            
            # 필수 필드 검증
            required_fields = ['customer_name', 'phone', 'address', 'product']
            for field in required_fields:
                if not request.form.get(field):
                    flash(f'{field} 필드는 필수입니다.', 'error')
                    return redirect(url_for('add_order'))
            
            # 새 주문 생성
            options_data = None
            option_type = request.form.get('option_type')

            if option_type == 'direct':
                direct_options = {
                    'product_name': request.form.get('direct_product_name'),
                    'standard': request.form.get('direct_standard'),
                    'internal': request.form.get('direct_internal'),
                    'color': request.form.get('direct_color'),
                    'option_detail': request.form.get('direct_option_detail'),
                    'handle': request.form.get('direct_handle'),
                    'misc': request.form.get('direct_misc'),
                    'quote': request.form.get('direct_quote')
                }
                # 비어있지 않은 값들만 필터링하거나, 모든 값을 저장할 수 있습니다.
                # 여기서는 모든 값을 저장합니다.
                options_data = json.dumps(direct_options, ensure_ascii=False)
            else: # 'online' or an undefined type
                options_data = request.form.get('options_online')

            # payment_amount 추가
            payment_amount_str = request.form.get('payment_amount', '').replace(',', '') # 콤마 제거
            payment_amount = None
            if payment_amount_str:
                try:
                    payment_amount = int(payment_amount_str) # 정수로 변환
                except ValueError:
                    flash('결제금액은 숫자만 입력해주세요.', 'error')
                    return render_template('add_order.html')
            else:
                payment_amount = 0 # 값이 없으면 0으로 처리

            new_order = Order(
                received_date=request.form.get('received_date'),
                received_time=request.form.get('received_time'),
                customer_name=request.form.get('customer_name'),
                phone=request.form.get('phone'),
                address=request.form.get('address'),
                product=request.form.get('product'),
                options=options_data,
                notes=request.form.get('notes'),
                status=request.form.get('status', 'RECEIVED'), # Use submitted status or default to RECEIVED
                # Add new fields from the form
                measurement_date=request.form.get('measurement_date'),
                measurement_time=request.form.get('measurement_time'),
                completion_date=request.form.get('completion_date'),
                manager_name=request.form.get('manager_name'),
                payment_amount=payment_amount # 저장
            )
            
            db.add(new_order)
            db.commit()
            
            log_access(f"주문 추가: {new_order.customer_name}", session.get('user_id'))
            
            flash('주문이 성공적으로 추가되었습니다.', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            db.rollback()
            flash(f'오류가 발생했습니다: {str(e)}', 'error')
            return redirect(url_for('add_order'))
    
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.datetime.now().strftime('%H:%M')
    
    return render_template('add_order.html', today=today, current_time=current_time)

@app.route('/edit/<int:order_id>', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN', 'MANAGER', 'STAFF'])
def edit_order(order_id):
    db = get_db()
    
    order = db.query(Order).filter(Order.id == order_id, Order.status != 'DELETED').first()
    
    if not order:
        flash('주문을 찾을 수 없거나 이미 삭제되었습니다.', 'error')
        return redirect(url_for('index'))
    
    # 옵션 데이터 처리를 위한 변수 초기화
    option_type = 'online'  # 기본 옵션 타입
    online_options = ""     # 온라인 옵션 텍스트
    direct_options = {      # 직접 입력 옵션 필드
        'product_name': '', 
        'standard': '', 
        'internal': '',
        'color': '',
        'option_detail': '',
        'handle': '',
        'misc': '',
        'quote': ''
    }
    
    # 주문 옵션 데이터 처리
    if order.options:
        try:
            # 옵션 데이터 파싱 시도
            options_data = json.loads(order.options)
            
            # 옵션 데이터가 객체고 option_type 필드가 있는 경우
            if isinstance(options_data, dict):
                # 1. option_type 필드가 있는 경우 
                if 'option_type' in options_data:
                    option_type = options_data['option_type']
                    
                    if option_type == 'direct' and 'details' in options_data:
                        # 새로운 형식: "details" 객체에서 직접 값 추출
                        details = options_data['details']
                        for key in direct_options.keys():
                            if key in details:
                                direct_options[key] = details[key]
                    elif option_type == 'online' and 'online_options_summary' in options_data:
                        online_options = options_data['online_options_summary']
                
                # 2. 구형식 - option_type 없이 직접 키가 있는 경우
                elif any(key in options_data for key in direct_options.keys()):
                    option_type = 'direct'
                    for key in direct_options.keys():
                        if key in options_data:
                            direct_options[key] = options_data[key]
                
                # 3. 한글 키 대응
                elif any(key in options_data for key in ['제품명', '규격', '내부', '색상', '상세옵션', '손잡이', '기타', '견적내용']):
                    option_type = 'direct'
                    key_mapping = {
                        '제품명': 'product_name',
                        '규격': 'standard', 
                        '내부': 'internal',
                        '색상': 'color',
                        '상세옵션': 'option_detail',
                        '손잡이': 'handle',
                        '기타': 'misc',
                        '견적내용': 'quote'
                    }
                    for k_kor, k_eng in key_mapping.items():
                        if k_kor in options_data:
                            direct_options[k_eng] = options_data[k_kor]
                
                # 4. 이외의 경우 online으로 처리하고 문자열로 표시
                else:
                    option_type = 'online'
                    online_options = order.options  # 원래 문자열 그대로 표시
            
            # 객체가 아닌 경우 온라인 옵션으로 처리
            else:
                option_type = 'online'
                online_options = order.options
                
        except json.JSONDecodeError:
            # JSON 파싱 실패 시 온라인 옵션으로 처리
            option_type = 'online'
            online_options = order.options if order.options else ""
    
    if request.method == 'POST':
        try:
            # ... (기존 POST 로직의 시작 부분) ...
            received_date = request.form.get('received_date')
            received_time = request.form.get('received_time')
            customer_name = request.form.get('customer_name')
            phone = request.form.get('phone')
            address = request.form.get('address')
            product = request.form.get('product')
            notes = request.form.get('notes')
            status = request.form.get('status')
            
            measurement_date = request.form.get('measurement_date')
            measurement_time = request.form.get('measurement_time')
            completion_date = request.form.get('completion_date')
            manager_name = request.form.get('manager_name')

            # 옵션 데이터 처리 (단순화)
            options_data_json_to_save = None
            option_type = request.form.get('option_type')
            
            if option_type == 'direct':
                # 직접입력 필드 값 수집
                direct_details = {
                    'product_name': request.form.get('direct_product_name', ''),
                    'standard': request.form.get('direct_standard', ''),
                    'internal': request.form.get('direct_internal', ''),
                    'color': request.form.get('direct_color', ''),
                    'option_detail': request.form.get('direct_option_detail', ''),
                    'handle': request.form.get('direct_handle', ''),
                    'misc': request.form.get('direct_misc', ''),
                    'quote': request.form.get('direct_quote', '')
                }
                
                # 새로운 JSON 형식으로 저장 - 간단하고 직관적인 구조
                options_to_save_dict = {
                    "option_type": "direct",
                    "details": direct_details
                }
                options_data_json_to_save = json.dumps(options_to_save_dict, ensure_ascii=False)
            else:  # 'online'
                online_summary = request.form.get('options_online', '')
                options_to_save_dict = {
                    "option_type": "online",
                    "online_options_summary": online_summary
                }
                options_data_json_to_save = json.dumps(options_to_save_dict, ensure_ascii=False)
            
            # ... (기존 POST 로직의 변경 감지 및 DB 업데이트 부분) ...
            changes = {}
            if order.received_date != received_date: changes['received_date'] = {'old': order.received_date, 'new': received_date}
            if order.received_time != received_time: changes['received_time'] = {'old': order.received_time, 'new': received_time}
            if order.customer_name != customer_name: changes['customer_name'] = {'old': order.customer_name, 'new': customer_name}
            if order.phone != phone: changes['phone'] = {'old': order.phone, 'new': phone}
            if order.address != address: changes['address'] = {'old': order.address, 'new': address}
            if order.product != product: changes['product'] = {'old': order.product, 'new': product}
            if order.options != options_data_json_to_save: changes['options'] = {'old': order.options, 'new': options_data_json_to_save}
            if order.notes != notes: changes['notes'] = {'old': order.notes, 'new': notes}
            if order.status != status: changes['status'] = {'old': order.status, 'new': status}
            if order.measurement_date != measurement_date: changes['measurement_date'] = {'old': order.measurement_date, 'new': measurement_date}
            if order.measurement_time != measurement_time: changes['measurement_time'] = {'old': order.measurement_time, 'new': measurement_time}
            if order.completion_date != completion_date: changes['completion_date'] = {'old': order.completion_date, 'new': completion_date}
            if order.manager_name != manager_name: changes['manager_name'] = {'old': order.manager_name, 'new': manager_name}
            
            # payment_amount 업데이트 및 변경 감지
            new_payment_amount = 0
            payment_amount_str = request.form.get('payment_amount', '').replace(',', '') # 콤마 제거
            if payment_amount_str:
                try:
                    new_payment_amount = int(payment_amount_str) # 정수로 변환
                except ValueError:
                    flash('결제금액은 숫자만 입력해주세요.', 'error')
                    # 에러 발생 시 기존 값 유지하며 템플릿 다시 렌더링 (아래에서 처리)
                    raise ValueError("Invalid payment amount") # 예외를 발생시켜 아래 except 블록으로 이동
            
            if order.payment_amount != new_payment_amount:
                changes['payment_amount'] = {'old': order.payment_amount, 'new': new_payment_amount}
                order.payment_amount = new_payment_amount

            order.received_date = received_date
            order.received_time = received_time
            order.customer_name = customer_name
            order.phone = phone
            order.address = address
            order.product = product
            order.options = options_data_json_to_save
            order.notes = notes
            order.status = status
            order.measurement_date = measurement_date
            order.measurement_time = measurement_time
            order.completion_date = completion_date
            order.manager_name = manager_name
            # order.payment_amount 는 위에서 이미 처리됨
            
            # # payment_amount 업데이트 (기존 로직 - 위에서 통합 처리됨)
            # payment_amount_str = request.form.get('payment_amount', '').replace(',', '') # 콤마 제거
            # if payment_amount_str:
            #     try:
            #         order.payment_amount = int(payment_amount_str) # 정수로 변환
            #     except ValueError:
            #         flash('결제금액은 숫자만 입력해주세요.', 'error')
            #         return render_template('edit_order.html', order=order, status_list=STATUS)
            # else:
            #     order.payment_amount = 0 # 값이 없으면 0으로 처리
            
            db.commit()
            
            additional_data = {"order_id": order_id, "customer_name": customer_name, "changes": changes}
            log_action = f"Updated order #{order_id}"
            log_access(log_action, session.get('user_id'), additional_data)
            
            flash('주문이 성공적으로 수정되었습니다.', 'success')
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'success'})
            
            return redirect(url_for('index'))
        except Exception as e:
            db.rollback()
            flash(f'주문 수정 중 오류가 발생했습니다: {str(e)}', 'error')
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': str(e)})
            
            # 오류 발생 시 현재 데이터로 페이지 다시 로드
            return render_template(
                'edit_order.html', 
                order=order,
                option_type=option_type,
                online_options=online_options,
                direct_options=direct_options
            )
    
    # GET 요청에 대한 최종 반환 - 미리 처리된 옵션 데이터를 직접 템플릿에 전달
    return render_template(
        'edit_order.html', 
        order=order,
        option_type=option_type,
        online_options=online_options,
        direct_options=direct_options
    )

@app.route('/delete/<int:order_id>')
@login_required
@role_required(['ADMIN', 'MANAGER'])
def delete_order(order_id):
    try:
        db = get_db()
        
        # Get order from database
        order = db.query(Order).filter(Order.id == order_id, Order.status != 'DELETED').first()
        
        if not order:
            flash('주문을 찾을 수 없거나 이미 삭제되었습니다.', 'error')
            return redirect(url_for('index'))
        
        # Save original status before deletion
        original_status = order.status
        deleted_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Soft delete by updating status and recording original status
        order.status = 'DELETED'
        order.original_status = original_status
        order.deleted_at = deleted_at
        
        db.commit()
        
        # Log the action
        log_access(f"Deleted order #{order_id}", session.get('user_id'))
        
        flash('주문이 휴지통으로 이동되었습니다.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'주문 삭제 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/trash')
@login_required
@role_required(['ADMIN', 'MANAGER'])
def trash():
    search_term = request.args.get('search', '')
    
    db = get_db()
    
    # Base query for deleted orders
    query = db.query(Order).filter(Order.status == 'DELETED')
    
    # Add search filter if provided
    if search_term:
        search_pattern = f"%{search_term}%"
        query = query.filter(
            (Order.customer_name.like(search_pattern)) |
            (Order.phone.like(search_pattern)) |
            (Order.address.like(search_pattern)) |
            (Order.product.like(search_pattern)) |
            (Order.options.like(search_pattern)) |
            (Order.notes.like(search_pattern))
        )
    
    # Order by deleted_at timestamp
    orders = query.order_by(Order.deleted_at.desc()).all()
    
    return render_template('trash.html', orders=orders, search_term=search_term)

@app.route('/restore_orders', methods=['POST'])
@login_required
@role_required(['ADMIN', 'MANAGER'])
def restore_orders():
    selected_ids = request.form.getlist('selected_order')
    
    if not selected_ids:
        flash('복원할 주문을 선택해주세요.', 'warning')
        return redirect(url_for('trash'))
    
    try:
        db = get_db()
        
        for order_id in selected_ids:
            # Get order by id
            order = db.query(Order).filter(Order.id == order_id, Order.status == 'DELETED').first()
            
            if order:
                # Get original status or default to RECEIVED
                original_status = order.original_status if order.original_status else 'RECEIVED'
                
                # Restore order by updating status
                order.status = original_status
                order.original_status = None
                order.deleted_at = None
        
        db.commit()
        
        # Log the action
        log_access(f"Restored {len(selected_ids)} orders", session.get('user_id'))
        
        flash(f'{len(selected_ids)}개의 주문이 성공적으로 복원되었습니다.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'주문 복원 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('trash'))

@app.route('/permanent_delete_orders', methods=['POST'])
@login_required
@role_required(['ADMIN'])
def permanent_delete_orders():
    selected_ids = request.form.getlist('selected_order')
    
    if not selected_ids:
        flash('영구 삭제할 주문을 선택해주세요.', 'warning')
        return redirect(url_for('trash'))
    
    try:
        db = get_db()
        
        for order_id in selected_ids:
            # Get order by id
            order = db.query(Order).filter(Order.id == order_id).first()
            
            if order:
                # Permanently delete order from database
                db.delete(order)
        
        db.commit()
        
        # Log the action
        log_access(f"Permanently deleted {len(selected_ids)} orders", session.get('user_id'))
        
        flash(f'{len(selected_ids)}개의 주문이 영구적으로 삭제되었습니다.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'주문 영구 삭제 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('trash'))

@app.route('/bulk_action', methods=['POST'])
@login_required
@role_required(['ADMIN', 'MANAGER'])
def bulk_action():
    action = request.form.get('action')
    selected_ids = request.form.getlist('selected_order')
    
    if not selected_ids:
        flash('작업할 주문을 선택해주세요.', 'warning')
        return redirect(url_for('index'))
    
    if not action:
        flash('수행할 작업을 선택해주세요.', 'warning')
        return redirect(url_for('index'))

    # db 변수 미리 선언
    db = None
    current_user_id = session.get('user_id')
    processed_count = 0
    failed_count = 0
        
    try:
        db = get_db()
        if action == 'delete':
            for order_id in selected_ids:
                order = db.query(Order).filter(Order.id == order_id, Order.status != 'DELETED').first()
                if order:
                    original_status = order.status
                    deleted_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    order.status = 'DELETED'
                    order.original_status = original_status
                    order.deleted_at = deleted_at
                    log_access(f"Deleted order #{order_id} via bulk action", current_user_id, {"order_id": order_id})
                    processed_count += 1
                else:
                    failed_count += 1
        
        # --- 주문 복사 로직 추가 --- 
        elif action == 'copy':
            now = datetime.datetime.now()
            today_str = now.strftime('%Y-%m-%d')
            time_str = now.strftime('%H:%M')
            
            for order_id in selected_ids:
                original_order = db.query(Order).get(order_id)
                if original_order:
                    # Order 객체 복사 (ID 등 자동 생성 필드는 제외)
                    copied_order = Order()
                    
                    # 필드 복사 (수정 필요한 필드 제외)
                    for column in Order.__table__.columns:
                        col_name = column.name
                        if col_name not in ['id', 'status', 'received_date', 'received_time',
                                             'customer_name', 'notes', 'measurement_date', 'measurement_time', 
                                             'completion_date', 'original_status', 'deleted_at']:
                            setattr(copied_order, col_name, getattr(original_order, col_name))
                    
                    # 필드 수정
                    copied_order.status = 'RECEIVED' # 상태는 '접수'로
                    copied_order.received_date = today_str # 접수일은 오늘 날짜
                    copied_order.received_time = time_str # 접수시간은 현재 시간
                    copied_order.customer_name = f"[복사: 원본 #{original_order.id}] {original_order.customer_name}"
                    
                    original_notes = original_order.notes or ""
                    copied_order.notes = f"원본 주문 #{original_order.id} 에서 복사됨.\n---\n" + original_notes
                    
                    # 날짜/시간 정보 초기화
                    copied_order.measurement_date = None
                    copied_order.measurement_time = None
                    copied_order.completion_date = None
                    
                    db.add(copied_order)
                    db.flush() # 새 ID를 가져오기 위해 flush
                    
                    # log_access(f"Copied order #{original_order.id} to new order #{copied_order.id} via bulk action", 
                    #            current_user_id, {"original_order_id": original_order.id, "new_order_id": copied_order.id})
                    processed_count += 1
                else:
                    failed_count += 1
        # --- 주문 복사 로직 끝 --- 
            
        elif action.startswith('status_'):
            new_status = action.split('_', 1)[1]
            if new_status in STATUS:
                for order_id in selected_ids:
                    order = db.query(Order).filter(Order.id == order_id, Order.status != 'DELETED').first()
                    if order and order.status != new_status:
                        old_status = order.status
                        order.status = new_status
                        log_access(f"Changed status of order #{order_id} from {old_status} to {new_status} via bulk action", 
                                   current_user_id, {"order_id": order_id, "old_status": old_status, "new_status": new_status})
                        processed_count += 1
                    elif not order:
                         failed_count += 1 # 존재하지 않거나 삭제된 주문
                    # 상태가 이미 동일하면 처리하지 않음 (processed_count 증가 안함)
            else:
                 # flash(f''{new_status}'는 유효하지 않은 상태입니다.', 'error') # 이전 코드
                 flash("'" + new_status + "'" + '는 유효하지 않은 상태입니다.', 'error') # f-string 제거
                 return redirect(url_for('index'))

        # db.commit() # 각 액션 블록 안에서 commit 하거나, 여기서 한번에 commit
        db.commit() # 모든 변경 사항을 한번에 커밋

        # 성공/실패 메시지 생성
        if action.startswith('status_'):
            # action_display_name = f"상태를 '{STATUS.get(action.split('_', 1)[1], action)}'(으)로 변경"
            status_code = action.split('_', 1)[1]
            status_name = STATUS.get(status_code, status_code) # 괄호 수정
            action_display_name = f"상태를 '{status_name}'(으)로 변경"
        elif action == 'copy':
            action_display_name = "'복사'"
        elif action == 'delete':
            action_display_name = "'삭제'"
        else:
            action_display_name = f"\'{action}\'" # 알 수 없는 액션 처리
        
        success_msg = f"{processed_count}개의 주문에 대해 {action_display_name} 작업을 완료했습니다."
        if failed_count > 0:
            warning_msg = f"{failed_count}개의 주문은 처리할 수 없었습니다 (이미 삭제되었거나 존재하지 않음)."
            flash(warning_msg, 'warning')
        
        if processed_count > 0:
             flash(success_msg, 'success')
        elif failed_count == len(selected_ids):
             flash('선택한 주문을 처리할 수 없습니다.', 'error')
        else: # 처리된 건 없고, 실패도 없으면 (예: 상태 변경 시 이미 해당 상태였음)
             flash('변경된 사항이 없습니다.', 'info')

    except Exception as e:
        if db:  # db 변수가 정의된 경우에만 롤백 수행
            db.rollback()
        flash(f'일괄 작업 중 오류 발생: {str(e)}', 'error')
        current_app.logger.error(f"Bulk action failed: {e}", exc_info=True)
    
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN', 'MANAGER'])
def upload_excel():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'excel_file' not in request.files:
            flash('파일이 선택되지 않았습니다.', 'error')
            return redirect(request.url)
        
        file = request.files['excel_file']
        
        if file.filename == '':
            flash('파일이 선택되지 않았습니다.', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            try:
                # Process the Excel file with pandas
                df = pd.read_excel(file_path)
                
                # Check for required columns (한글 컬럼명으로 변경)
                required_columns = ['접수일', '고객명', '전화번호', '주소', '제품']
                missing_columns = [col for col in required_columns if col not in df.columns]
                
                if missing_columns:
                    flash(f'엑셀 파일에 필수 컬럼이 누락되었습니다: {", ".join(missing_columns)}', 'error')
                    return redirect(request.url)
                
                # Connect to database
                db = get_db()
                
                # Process each row
                order_count = 0
                for index, row in df.iterrows():
                    # Convert fields to the right format and provide defaults (한글 컬럼명 사용)
                    received_date = row['접수일'].strftime('%Y-%m-%d') if pd.notna(row['접수일']) else datetime.datetime.now().strftime('%Y-%m-%d')
                    
                    # Handle received_time column if it exists (한글 컬럼명 '접수시간')
                    received_time = None
                    if '접수시간' in df.columns and pd.notna(row['접수시간']):
                        if isinstance(row['접수시간'], datetime.time):
                            received_time = row['접수시간'].strftime('%H:%M')
                        elif isinstance(row['접수시간'], str):
                            received_time = row['접수시간']
                    
                    # Handle options column if it exists (한글 컬럼명 '옵션')
                    options = row['옵션'] if '옵션' in df.columns and pd.notna(row['옵션']) else None
                    
                    # Handle notes column if it exists (한글 컬럼명 '비고')
                    notes = row['비고'] if '비고' in df.columns and pd.notna(row['비고']) else None
                    
                    # 새 필드에 대한 처리 추가 (엑셀 업로드 시)
                    measurement_date = row['실측일'].strftime('%Y-%m-%d') if '실측일' in df.columns and pd.notna(row['실측일']) else None
                    measurement_time = row['실측시간'].strftime('%H:%M') if '실측시간' in df.columns and pd.notna(row['실측시간']) else None
                    completion_date = row['설치완료일'].strftime('%Y-%m-%d') if '설치완료일' in df.columns and pd.notna(row['설치완료일']) else None
                    manager_name = row['담당자'] if '담당자' in df.columns and pd.notna(row['담당자']) else None
                    
                    # Create new order
                    new_order = Order(
                        customer_name=row['고객명'] if pd.notna(row['고객명']) else '',
                        phone=row['전화번호'] if pd.notna(row['전화번호']) else '',
                        address=row['주소'] if pd.notna(row['주소']) else '',
                        product=row['제품'] if pd.notna(row['제품']) else '',
                        options=options,
                        notes=notes,
                        received_date=received_date,
                        received_time=received_time,
                        status='RECEIVED',  # Default status
                        measurement_date=measurement_date,
                        measurement_time=measurement_time,
                        completion_date=completion_date,
                        manager_name=manager_name
                    )
                    
                    db.add(new_order)
                    order_count += 1
                
                db.commit()
                flash(f'{order_count}개의 주문이 성공적으로 등록되었습니다.', 'success')
                
            except Exception as e:
                db.rollback()
                flash(f'엑셀 파일 처리 중 오류가 발생했습니다: {str(e)}', 'error')
            
            # Delete the file after processing
            try:
                os.remove(file_path)
            except:
                pass
            
            return redirect(url_for('index'))
        else:
            flash('허용되지 않은 파일 형식입니다. .xlsx 또는 .xls 파일만 업로드 가능합니다.', 'error')
            return redirect(request.url)
    
    return render_template('upload.html')

@app.route('/download_excel')
@login_required
def download_excel():
    db = get_db()
    status_filter = request.args.get('status')
    search_query = request.args.get('search', '').strip()
    sort_column = request.args.get('sort', 'id') # 정렬 기준
    sort_direction = request.args.get('direction', 'desc') # 정렬 방향
    
    # 기본 쿼리 생성 (삭제되지 않은 주문만)
    query = db.query(Order).filter(Order.deleted_at.is_(None))
    
    # 상태 필터 적용
    if status_filter:
        query = query.filter(Order.status == status_filter)
    
    # 검색어 필터 적용
    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter(
            or_(
                Order.id.like(search_term),
                Order.received_date.like(search_term),
                Order.received_time.like(search_term),
                Order.customer_name.like(search_term),
                Order.phone.like(search_term),
                Order.address.like(search_term),
                Order.product.like(search_term),
                Order.options.like(search_term),
                Order.notes.like(search_term),
                Order.status.like(search_term),
                Order.measurement_date.like(search_term),
                Order.measurement_time.like(search_term),
                Order.completion_date.like(search_term),
                Order.manager_name.like(search_term),
                Order.payment_amount.like(search_term) # 결제금액 검색 추가
            )
        )

    # 컬럼별 드롭다운 필터 적용 (index 함수와 동일한 로직)
    filterable_columns = [
        'id', 'received_date', 'received_time', 'customer_name', 'phone', 
        'address', 'product', 'options', 'notes', 'status', 
        'measurement_date', 'measurement_time', 'completion_date', 'manager_name', 'payment_amount'
    ]
    for column_name in filterable_columns:
        filter_values = request.args.getlist(f'filter_{column_name}') # getlist 사용
        if filter_values:
            if "__EMPTY__" in filter_values:
                filter_values.remove("__EMPTY__")
                empty_filter = or_(getattr(Order, column_name).is_(None), getattr(Order, column_name) == '')
                if filter_values:
                    query = query.filter(or_(getattr(Order, column_name).in_(filter_values), empty_filter))
        else:
            query = query.filter(getattr(Order, column_name).in_(filter_values))
        column_to_sort = getattr(Order, sort_column)
        if sort_direction == 'asc':
            query = query.order_by(column_to_sort.asc())
        else:
            query = query.order_by(column_to_sort.desc())
    else:
        query = query.order_by(Order.id.desc()) # 기본 정렬

    orders = query.all()

    if not orders:
        flash('다운로드할 데이터가 없습니다.', 'warning')
        return redirect(request.referrer or url_for('index'))
    
    # 데이터를 Pandas DataFrame으로 변환
    orders_data = [order.to_dict() for order in orders]
    df = pd.DataFrame(orders_data)
    
    # 필요한 컬럼 선택 및 순서 지정
    excel_columns = [
        'id', 'received_date', 'received_time', 'customer_name', 'phone', 'address', 
        'product', 'options', 'notes', 'payment_amount', # 결제금액 추가
        'measurement_date', 'measurement_time', 'completion_date', 
        'manager_name', 'status'
    ]
    df_excel = df[excel_columns]
    
    # 컬럼명 한글로 변경
    df_excel.columns = [
        'ID', '접수일', '접수시간', '고객명', '연락처', '주소', 
        '제품', '옵션', '비고', '결제금액', # 결제금액 헤더 추가
        '실측일', '실측시간', '설치완료일', 
        '담당자', '상태'
    ]
    
    # 엑셀 파일 생성
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    excel_filename = f"furniture_orders_{timestamp}.xlsx"
    excel_path = os.path.join(app.config['UPLOAD_FOLDER'], excel_filename)
    
    df_excel.to_excel(excel_path, index=False, engine='openpyxl')
    
    # 로그 기록
    log_access(f"Excel downloaded: {excel_filename}", session.get('user_id'))
    
    # 파일을 사용자에게 전송 (다운로드 후 서버에서 파일 삭제 옵션 추가 가능)
    return send_file(excel_path, as_attachment=True)

@app.route('/calendar')
@login_required
def calendar():
    return render_template('calendar.html')

@app.route('/api/orders')
@login_required
def api_orders():
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    status_filter = request.args.get('status', None)
    
    db = get_db()
    
    # Base query for orders
    query = db.query(Order).filter(Order.status != 'DELETED')
    
    # Add status filter if provided
    if status_filter and status_filter in STATUS:
        query = query.filter(Order.status == status_filter)
    
    # Add date range filter if provided
    if start_date and end_date:
        # Handle date and datetime format properly
        if 'T' in start_date:  # ISO format with time (YYYY-MM-DDTHH:MM:SS)
            start_date_only = start_date.split('T')[0]
            end_date_only = end_date.split('T')[0]
            query = query.filter(Order.received_date.between(start_date_only, end_date_only))
        else:  # Date only format (YYYY-MM-DD)
            query = query.filter(Order.received_date.between(start_date, end_date))
    
    orders = query.all()
    
    # Map status to colors
    status_colors = {
        'RECEIVED': '#3788d8',   # Blue
        'MEASURED': '#f39c12',   # Orange
        'SCHEDULED': '#e74c3c',  # Red
        'COMPLETED': '#2ecc71',  # Green
        'AS_RECEIVED': '#9b59b6', # Purple
        'AS_COMPLETED': '#1abc9c'  # Teal
    }
    
    events = []
    for order in orders:
        start_date = order.received_date
        if order.received_time:
            start_datetime = f"{start_date}T{order.received_time}:00"
            all_day = False
        else:
            start_datetime = start_date
            all_day = True
        
        color = status_colors.get(order.status, '#3788d8')
        time_str = order.received_time if order.received_time else ''
        title = f"{order.customer_name} | {order.phone} | {order.product}"
        
        events.append({
            'id': order.id,
            'title': title,
            'start': start_datetime,
            'allDay': all_day,
            'backgroundColor': color,
            'borderColor': color,
            'extendedProps': {
                'customer_name': order.customer_name,
                'phone': order.phone,
                'address': order.address,
                'product': order.product,
                'options': order.options,
                'notes': order.notes,
                'status': order.status,
                'received_date': order.received_date,
                'received_time': order.received_time
            }
        })
    
    return jsonify(events)

# Admin routes for menu management
@app.route('/admin')
@login_required
@role_required(['ADMIN'])
def admin():
    return render_template('admin.html')

@app.route('/admin/update_menu', methods=['POST'])
@login_required
@role_required(['ADMIN'])
def update_menu():
    try:
        menu_config = request.form.get('menu_config')
        if menu_config:
            # Save menu configuration to a file
            with open('menu_config.json', 'w', encoding='utf-8') as f:
                f.write(menu_config)
            
            # Log the action
            log_access(f"Updated menu configuration", session.get('user_id'))
            
            flash('메뉴 구성이 업데이트되었습니다.', 'success')
        else:
            flash('메뉴 구성을 입력해주세요.', 'error')
    except Exception as e:
        flash(f'메뉴 업데이트 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('admin'))

# User Management Routes
@app.route('/admin/users')
@login_required
@role_required(['ADMIN'])
def user_list():
    db = get_db()
    
    # Get all users
    users = db.query(User).order_by(User.username).all()
    
    # Count admin users for template
    count_admin = db.query(User).filter(User.role == 'ADMIN').count()
    
    return render_template('user_list.html', users=users, count_admin=count_admin)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name', '사용자')
        role = request.form.get('role')
        
        # Validate required fields
        if not all([username, password, role]):
            flash('모든 필수 입력 필드를 입력해주세요.', 'error')
            return render_template('add_user.html')
        
        # Check password strength
        if not is_password_strong(password):
            flash('비밀번호는 8자 이상이며, 대문자, 소문자, 숫자를 각각 1개 이상 포함해야 합니다.', 'error')
            return render_template('add_user.html')
        
        # Check if username already exists
        if get_user_by_username(username):
            flash('이미 사용 중인 아이디입니다.', 'error')
            return render_template('add_user.html')
        
        # Validate role
        if role not in ROLES:
            flash('유효하지 않은 역할입니다.', 'error')
            return render_template('add_user.html')
        
        try:
            db = get_db()
            
            # Hash password
            hashed_password = generate_password_hash(password)
            
            # Create new user
            new_user = User(
                username=username,
                password=hashed_password,
                name=name,
                role=role,
                is_active=True
            )
            
            # Add and commit
            db.add(new_user)
            db.commit()
            
            # Log action
            log_access(f"Added new user: {username}", session.get('user_id'))
            
            flash('사용자가 성공적으로 추가되었습니다.', 'success')
            return redirect(url_for('user_list'))
                
        except Exception as e:
            db.rollback()
            flash(f'사용자 추가 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('add_user.html')
    
    return render_template('add_user.html', roles=ROLES)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
def edit_user(user_id):
    db = get_db()
    
    # Get the user from database
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        flash('사용자를 찾을 수 없습니다.', 'error')
        return redirect(url_for('user_list'))
    
    # Prevent editing admin user if it's the only admin
    if user.role == 'ADMIN':
        admin_count = db.query(User).filter(User.role == 'ADMIN').count()
        
        if admin_count == 1 and request.method == 'POST' and request.form.get('role') != 'ADMIN':
            flash('마지막 관리자의 역할은 변경할 수 없습니다.', 'error')
            return redirect(url_for('edit_user', user_id=user_id))
    
    if request.method == 'POST':
        name = request.form.get('name', '사용자')
        role = request.form.get('role')
        is_active = request.form.get('is_active') == 'on'
        
        # Validate required fields
        if not role:
            flash('역할은 필수 입력 필드입니다.', 'error')
            return render_template('edit_user.html', user=user)
        
        # Validate role
        if role not in ROLES:
            flash('유효하지 않은 역할입니다.', 'error')
            return render_template('edit_user.html', user=user)
        
        try:
            # Update user
            user.name = name
            user.role = role
            user.is_active = is_active
            db.commit()
            
            # Handle password change if provided
            new_password = request.form.get('new_password')
            if new_password:
                if is_password_strong(new_password):
                    user.password = generate_password_hash(new_password)
                    db.commit()
                    flash('비밀번호가 변경되었습니다.', 'success')
                else:
                    flash('비밀번호는 8자 이상이며, 대문자, 소문자, 숫자를 각각 1개 이상 포함해야 합니다.', 'error')
            
            # Log action
            log_access(f"Updated user #{user_id}", session.get('user_id'))
            
            flash('사용자 정보가 성공적으로 업데이트되었습니다.', 'success')
            return redirect(url_for('user_list'))
                
        except Exception as e:
            db.rollback()
            flash(f'사용자 정보 업데이트 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('edit_user.html', user=user)
    
    return render_template('edit_user.html', user=user, roles=ROLES)

@app.route('/admin/users/delete/<int:user_id>')
@login_required
@role_required(['ADMIN'])
def delete_user(user_id):
    # Prevent deleting self
    if user_id == session.get('user_id'):
        flash('자신의 계정은 삭제할 수 없습니다.', 'error')
        return redirect(url_for('user_list'))
    
    db = get_db()
    
    # Get the user from database
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        flash('사용자를 찾을 수 없습니다.', 'error')
        return redirect(url_for('user_list'))
    
    # Prevent deleting last admin
    if user.role == 'ADMIN':
        admin_count = db.query(User).filter(User.role == 'ADMIN').count()
        
        if admin_count == 1:
            flash('마지막 관리자는 삭제할 수 없습니다.', 'error')
            return redirect(url_for('user_list'))
    
    try:
        # Delete user
        db.delete(user)
        db.commit()
        
        # Log action
        log_access(f"Deleted user #{user_id}", session.get('user_id'))
        
        flash('사용자가 성공적으로 삭제되었습니다.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'사용자 삭제 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('user_list'))

def parse_action_log(action, additional_data=None):
    """
    작업 로그를 작업 유형과 세부 정보로 분리합니다.
    예: "Updated order #123" -> ("업데이트", "주문 #123")
    """
    action_type = "기타"
    action_details = action
    
    # Additional data parsing (from JSON if needed)
    if additional_data and isinstance(additional_data, str):
        try:
            additional_data = json.loads(additional_data)
        except:
            additional_data = {}
    elif additional_data is None:
            additional_data = {}
    
    # 로그인 관련
    if action.startswith("Successful login:"):
        action_type = "로그인"
        action_details = action.replace("Successful login:", "").strip()
    elif action.startswith("Failed login attempt"):
        action_type = "로그인 실패"
        if "(wrong password)" in action:
            action_details = action.replace("Failed login attempt for username:", "").replace("(wrong password)", "- 잘못된 비밀번호").strip()
        else:
            action_details = action.replace("Failed login attempt for username:", "").strip()
    elif action.startswith("Logout:"):
        action_type = "로그아웃"
        action_details = action.replace("Logout:", "").strip()
    
    # 주문 관련
    elif action.startswith("Updated order #"):
        action_type = "주문 수정"
        order_id = action.replace("Updated order #", "").strip()
        
        # 주문 번호에 링크 추가
        order_link = f'<a href="{url_for("edit_order", order_id=order_id)}" class="order-link">주문 #{order_id}</a>'
        
        # 변경 세부 정보 표시
        if additional_data and 'changes' in additional_data:
            changes = additional_data['changes']
            customer_name = additional_data.get('customer_name', '')
            
            # 상태 변경 정보
            if 'status' in changes:
                old_status = STATUS.get(changes['status']['old'], changes['status']['old'])
                new_status = STATUS.get(changes['status']['new'], changes['status']['new'])
                status_change = f"상태 변경: {old_status} → {new_status}"
            else:
                status_change = None
            
            # 기타 변경 항목들
            other_changes = []
            for field, values in changes.items():
                if field == 'status':
                    continue  # 이미 처리함
                    
                field_name = {
                    'received_date': '접수일',
                    'received_time': '접수시간',
                    'customer_name': '고객명',
                    'phone': '전화번호',
                    'address': '주소',
                    'product': '제품',
                    'options': '옵션',
                    'notes': '비고',
                    'measurement_date': '실측일',
                    'measurement_time': '실측시간',
                    'completion_date': '설치완료일',
                    'manager_name': '담당자'
                }.get(field, field)
                
                # None 값 안전하게 처리
                old_val = values.get('old', '') or '-'
                new_val = values.get('new', '') or '-'
                other_changes.append(f"{field_name}: {old_val} → {new_val}")
            
            # 모든 세부 정보 결합
            details = []
            if customer_name:
                details.append(f"고객: {customer_name}")
            
            if status_change:
                details.append(status_change)
                
            if other_changes:
                details.append(" | ".join(other_changes))
                
            if details:
                action_details = f"{order_link} 정보 수정 - " + " | ".join(details)
            else:
                action_details = f"{order_link} 정보 수정"
        else:
            # 이전 방식의 로그를 위한 호환성 유지
            if additional_data and 'old_status' in additional_data and 'new_status' in additional_data:
                old_status = STATUS.get(additional_data['old_status'], additional_data['old_status'])
                new_status = STATUS.get(additional_data['new_status'], additional_data['new_status'])
                customer_name = additional_data.get('customer_name', '')
                
                if customer_name:
                    action_details = f"{order_link} 정보 수정 - 고객: {customer_name}, 상태 변경: {old_status} → {new_status}"
                else:
                    action_details = f"{order_link} 정보 수정 - 상태 변경: {old_status} → {new_status}"
            else:
                action_details = f"{order_link} 정보 수정"
    elif action.startswith("Deleted order #"):
        action_type = "주문 삭제"
        order_id = action.replace("Deleted order #", "").strip()
        # 링크 추가 (휴지통으로 이동한 주문이므로 리스트로 안내)
        action_details = f'<a href="{url_for("trash")}" class="order-link">주문 #{order_id} 휴지통으로 이동</a>'
    elif action.startswith("주문 추가:"):
        action_type = "주문 추가"
        customer_name = action.replace("주문 추가:", "").strip()
        # 추가된 주문은 ID를 찾을 수 없어 링크를 추가하기 어려움
        action_details = f"고객명: {customer_name}"
    elif action.startswith("Restored"):
        action_type = "주문 복원"
        match = re.search(r"Restored (\d+) orders", action)
        if match:
            count = match.group(1)
            action_details = f'<a href="{url_for("index")}" class="order-link">{count}개 주문 복원됨</a>'
        else:
            action_details = action
    elif action.startswith("Permanently deleted"):
        action_type = "주문 영구삭제"
        match = re.search(r"Permanently deleted (\d+) orders", action)
        if match:
            count = match.group(1)
            action_details = f"{count}개 주문 영구삭제됨"
        else:
            action_details = action
    elif action.startswith("일괄 작업:"):
        action_type = "일괄 작업"
        # 일괄 작업 정보에서 주문 ID와 설명 추출
        match = re.search(r"일괄 작업: 주문 (.*?)에 대해 '(.*?)' 실행", action)
        if match:
            order_ids_str = match.group(1)
            desc = match.group(2)
            # 여러 주문 ID를 쉼표로 분리
            order_ids = [oid.strip() for oid in order_ids_str.split(',')]
                
            # 링크로 변환
            linked_orders = []
            for order_id in order_ids[:3]:  # 처음 3개만 표시
                linked_orders.append(f'<a href="{url_for("edit_order", order_id=order_id)}" class="order-link">#{order_id}</a>')
            
            if len(order_ids) > 3:
                action_details = f"주문 {', '.join(linked_orders)} 외 {len(order_ids) - 3}개에 대해 '{desc}' 실행"
            else: # Correct indentation for this else block's content
                action_details = f"주문 {', '.join(linked_orders)}에 대해 '{desc}' 실행"
        else:
            action_details = action
    # 사용자 관리 관련
    elif action.startswith("Added new user:"):
        action_type = "사용자 추가"
        username = action.replace("Added new user:", "").strip()
        action_details = f"사용자명: {username}"
    elif action.startswith("Updated user #"):
        action_type = "사용자 수정"
        user_id = action.replace("Updated user #", "").strip()
        action_details = f"사용자 ID #{user_id} 정보 수정"
    elif action.startswith("Deleted user #"):
        action_type = "사용자 삭제"
        user_id = action.replace("Deleted user #", "").strip()
        action_details = f"사용자 ID #{user_id} 삭제됨"
    elif action.startswith("Changed password"):
        action_type = "비밀번호 변경"
        action_details = "사용자 비밀번호 변경됨"
    
    # 기타 작업
    elif action.startswith("Downloaded Excel file"):
        action_type = "엑셀 다운로드"
        action_details = "주문 내역 엑셀 파일 다운로드"
    elif action.startswith("Updated menu configuration"):
        action_type = "메뉴 설정"
        action_details = "메뉴 구성 업데이트됨"
    elif action.startswith("Unauthorized access attempt"):
        action_type = "접근 제한"
        path = action.replace("Unauthorized access attempt to", "").strip()
        action_details = f"권한이 없는 페이지 접근 시도: {path}"
    
    return action_type, action_details

@app.route('/admin/security-logs')
@login_required
@role_required(['ADMIN'])
def security_logs():
    limit = request.args.get('limit', 100, type=int)
    user_id = request.args.get('user_id', type=int)
    
    db = get_db()
    
    try:
        # Get logs with user information - with additional_data column
        logs_query = db.query(AccessLog, User.username, User.name)\
                      .outerjoin(User, AccessLog.user_id == User.id)\
                      .order_by(AccessLog.timestamp.desc())
        
        if user_id:
            logs_query = logs_query.filter(AccessLog.user_id == user_id)
        
        raw_logs = logs_query.limit(limit).all()
        
        # Format the logs for the template
        logs = []
        for log_record in raw_logs:
            access_log = log_record[0]  # The AccessLog object
            username = log_record[1]    # Username from User
            name = log_record[2]        # Name from User
            
            # Parse action into type and details
            action_type, action_details = parse_action_log(access_log.action, 
                                                          getattr(access_log, 'additional_data', None))
            
            logs.append({
                'timestamp': access_log.timestamp,
                'username': username,
                'name': name,
                'action_type': action_type,
                'action_details': action_details,
                'ip_address': access_log.ip_address
            })
    except Exception as e:
        # 컬럼이 없는 경우 additional_data 없이 로그 조회
        if 'additional_data' in str(e):
            logs_query = db.query(
                AccessLog.id, AccessLog.user_id, AccessLog.action, 
                AccessLog.ip_address, AccessLog.timestamp,
                User.username, User.name
            ).outerjoin(User, AccessLog.user_id == User.id)\
             .order_by(AccessLog.timestamp.desc())
            
            if user_id:
                logs_query = logs_query.filter(AccessLog.user_id == user_id)
            
            raw_logs = logs_query.limit(limit).all()
            
            # Format logs without additional_data
            logs = []
            for log_record in raw_logs:
                # Parse action into type and details (without additional_data)
                action_type, action_details = parse_action_log(log_record[2], None)
                
                logs.append({
                    'timestamp': log_record[4],
                    'username': log_record[5],
                    'name': log_record[6],
                    'action_type': action_type,
                    'action_details': action_details,
                    'ip_address': log_record[3]
                })
            
            flash('데이터베이스 업그레이드가 필요합니다. 관리자에게 문의하세요.', 'warning')
        else:
            # 다른 예외 처리
            flash(f'로그를 불러오는 중 오류가 발생했습니다: {str(e)}', 'error')
            logs = []
    
    # Get all users for filter
    users = db.query(User.id, User.username, User.name).order_by(User.username).all()
    
    return render_template('security_logs.html', logs=logs, users=users, current_user_id=user_id)

# Profile route for users to manage their own account
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    db = get_db()
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        session.clear()
        flash('사용자를 찾을 수 없습니다. 다시 로그인해주세요.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name')
        
        # Validate name
        if not name:
            flash('이름을 입력해주세요.', 'error')
            return render_template('profile.html', user=user)
        
        try:
            # Update name
            user.name = name
            db.commit()
            
            # Handle password change if provided
            if current_password and new_password and confirm_password:
                # Verify current password
                if not check_password_hash(user.password, current_password):
                    flash('현재 비밀번호가 일치하지 않습니다.', 'error')
                    return render_template('profile.html', user=user)
                
                # Check password match
                if new_password != confirm_password:
                    flash('새 비밀번호가 일치하지 않습니다.', 'error')
                    return render_template('profile.html', user=user)
                
                # Check password strength
                if not is_password_strong(new_password):
                    flash('비밀번호는 8자 이상이며, 대문자, 소문자, 숫자를 각각 1개 이상 포함해야 합니다.', 'error')
                    return render_template('profile.html', user=user)
                
                # Update password
                user.password = generate_password_hash(new_password)
                db.commit()
                
                # Log password change
                log_access("Changed password", user_id)
                
                flash('비밀번호가 성공적으로 변경되었습니다.', 'success')
            
            flash('프로필이 업데이트되었습니다.', 'success')
            return redirect(url_for('profile'))
                
        except Exception as e:
            db.rollback()
            flash(f'프로필 업데이트 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('profile.html', user=user)
    
    return render_template('profile.html', user=user)

def load_menu_config():
    try:
        if os.path.exists('menu_config.json'):
            with open('menu_config.json', 'r', encoding='utf-8') as f:
                return json.load(f)
    except:
        pass
    
    # Default menu configuration
    return {
        'main_menu': [
            {'id': 'calendar', 'name': '캘린더', 'url': '/calendar'},
            {'id': 'order_list', 'name': '전체 주문', 'url': '/'},
            {'id': 'measured', 'name': '실측', 'url': '/?status=MEASURED'},
            {'id': 'scheduled', 'name': '설치 예정', 'url': '/?status=SCHEDULED'},
            {'id': 'completed', 'name': '완료', 'url': '/?status=COMPLETED'},
            {'id': 'as_received', 'name': 'AS 접수', 'url': '/?status=AS_RECEIVED'},
            {'id': 'as_completed', 'name': 'AS 완료', 'url': '/?status=AS_COMPLETED'},
            {'id': 'trash', 'name': '휴지통', 'url': '/trash'}
        ]
    }

@app.context_processor
def inject_menu():
    menu_config = load_menu_config()
    return dict(menu=menu_config)

if __name__ == '__main__':
    init_db()  # 앱 시작 시 데이터베이스 초기화
    
    # 애플리케이션 컨텍스트 내에서 실행
    with app.app_context():
        try:
            db = get_db()
            # 컬럼이 존재하지 않는 경우에만 추가
            for column, column_type in [
                ('measurement_date', 'VARCHAR'),
                ('measurement_time', 'VARCHAR'),
                ('completion_date', 'VARCHAR'),
                ('manager_name', 'VARCHAR'),
                ('payment_amount', 'INTEGER') # payment_amount 컬럼 추가
            ]:
                # 해당 컬럼이 이미 존재하는지 확인
                query = text(f"""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name='orders' AND column_name='{column}'
                """)
                result = db.execute(query).fetchone()
                
                # 컬럼이 없으면 추가
                if not result:
                    alter_query = text(f"ALTER TABLE orders ADD COLUMN {column} {column_type}")
                    db.execute(alter_query)
                    print(f"Added column {column} to orders table")
            
            db.commit()
            print("Database column update completed")
        except Exception as e:
            db.rollback()
            print(f"Error updating database schema: {str(e)}")
    
    app.run(host='0.0.0.0', port=5000, debug=True)