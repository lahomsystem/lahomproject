import os
import datetime
import json
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g, session, send_file, current_app
from markupsafe import Markup # Markup import 변경
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash  # For password hashing
import re  # For validation
from sqlalchemy import or_, text, func, String  # Import or_ function, text for raw SQL, func for distinct, String for casting
import copy # 객체 복사를 위해 추가

# 데이터베이스 관련 임포트
from db import get_db, close_db, init_db
from models import Order, User, SecurityLog

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
    db = get_db()
    # action은 "주문 #번호 ..." 형태로 완전한 메시지
    log = SecurityLog(user_id=user_id, message=action)
    db.add(log)
    db.commit()

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
                log_access(f"권한 없는 접근 시도: {request.path}", user.id)
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
            log_access(f"로그인 실패: 사용자 {username} (계정 없음)") # user_id 없이 로그 기록
            flash('아이디 또는 비밀번호가 일치하지 않습니다.', 'error')
            return render_template('login.html')
        
        # Check if user is active
        if not user.is_active:
            log_access(f"로그인 실패: 비활성화된 계정 {username} (ID: {user.id})", user.id)
            flash('비활성화된 계정입니다. 관리자에게 문의하세요.', 'error')
            return render_template('login.html')
        
        # Verify password
        if not check_password_hash(user.password, password):
            log_access(f"로그인 실패: 사용자 {username} (ID: {user.id}) (비밀번호 오류)", user.id)
            flash('아이디 또는 비밀번호가 일치하지 않습니다.', 'error')
            return render_template('login.html')
        
        # Login successful
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        
        # Update last login
        update_last_login(user.id)
        
        # Log successful login
        log_access(f"로그인 성공: 사용자 {user.username} (ID: {user.id})", user.id)
        
        flash(f'{user.name}님, 환영합니다!', 'success')
        return redirect(next_url)
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']
        username = session.get('username', 'Unknown')
        user_name_for_log = session.get('name', username) # 실제 이름이 있으면 사용
        
        session.clear()
        log_access(f"로그아웃: 사용자 {user_name_for_log} (ID: {user_id})", user_id)
        
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
        
        log_access(f"초기 관리자 계정 생성: {new_user.username} (ID: {new_user.id})", new_user.id)
        
        flash('계정이 생성되었습니다. 로그인해주세요.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Removed email verification and password reset routes

# --- format_options_for_display 함수를 여기로 이동 (또는 적절한 전역 위치) ---
def format_options_for_display(options_json_str):
    if not options_json_str:
        return ""
    try:
        options_data = json.loads(options_json_str)
        key_to_korean = {
            'product_name': '제품명', 'standard': '규격', 'internal': '내부',
            'color': '색상', 'option_detail': '상세옵션', 'handle': '손잡이',
            'misc': '기타', 'quote': '견적내용'
        }
        korean_to_key = {v: k for k, v in key_to_korean.items()}

        if isinstance(options_data, dict):
            if options_data.get("option_type") == "direct" and "details" in options_data:
                details = options_data["details"]
                display_parts = []
                for key, kor_display_name in key_to_korean.items():
                    value = details.get(key)
                    if value:
                        display_parts.append(f"{kor_display_name}: {value}")
                return ", ".join(display_parts) if display_parts else "옵션 정보 없음"
            elif options_data.get("option_type") == "online" and "online_options_summary" in options_data:
                summary = options_data["online_options_summary"]
                # 줄바꿈 문자를 <br> 태그로 변경하여 반환
                return summary.replace('\n', '<br>') if summary else "온라인 옵션 요약 없음"
            elif any(key in options_data for key in key_to_korean.keys()):
                display_parts = []
                for key_eng, value in options_data.items():
                    if value and key_eng in key_to_korean:
                        display_parts.append(f"{key_to_korean[key_eng]}: {value}")
                return ", ".join(display_parts) if display_parts else "옵션 정보 없음 (구)"
            elif any(key_kor in options_data for key_kor in korean_to_key.keys()):
                display_parts = []
                for key_kor, value in options_data.items():
                    if value and key_kor in korean_to_key:
                        display_parts.append(f"{key_kor}: {value}")
                return ", ".join(display_parts) if display_parts else "옵션 정보 없음 (구-한글)"
            else:
                display_parts = []
                for key, value in options_data.items():
                    if isinstance(value, (str, int, float)):
                        display_parts.append(f"{key}: {value}")
                return ", ".join(display_parts) if display_parts else options_json_str
        else:
            return str(options_data)
    except json.JSONDecodeError:
        return options_json_str if options_json_str else "옵션 정보 없음"
    except Exception:
        return options_json_str if options_json_str else "옵션 처리 오류"
# --- format_options_for_display 함수 끝 ---

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
    orders_from_db = query.offset((page - 1) * per_page).limit(per_page).all()

    # 옵션 표시를 위한 헬퍼 함수 호출 (이제 전역 함수 사용)
    processed_orders = []
    for order_db_item in orders_from_db:
        order_display_data = copy.deepcopy(order_db_item)
        order_display_data.display_options = format_options_for_display(order_db_item.options) # 전역 함수 호출
        processed_orders.append(order_display_data)

    # 사용자 정보 가져오기 (예: 역할 기반 UI 표시용)
    user = None
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
    
    return render_template(
        'index.html',
                          orders=processed_orders, 
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
            db.flush() # 새 주문의 ID를 가져오기 위해 flush
            order_id_for_log = new_order.id # ID 저장
            customer_name_for_log = new_order.customer_name
            user_for_log = get_user_by_id(session['user_id'])
            user_name_for_log = user_for_log.name if user_for_log else "Unknown user"
            db.commit() # 커밋은 flush 이후에
            
            log_access(f"주문 #{order_id_for_log} ({customer_name_for_log}) 추가 - 담당자: {user_name_for_log} (ID: {session.get('user_id')})", session.get('user_id'))
            
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
            
            # 필드 레이블 정의 (필드명 -> 한글 레이블 매핑)
            field_labels = {
                'received_date': '접수일',
                'received_time': '접수시간',
                'customer_name': '고객명',
                'phone': '전화번호',
                'address': '주소',
                'product': '제품',
                'options': '옵션 상세',
                'notes': '비고',
                'status': '상태',
                'measurement_date': '실측일',
                'measurement_time': '실측시간',
                'completion_date': '설치완료일',
                'manager_name': '담당자',
                'payment_amount': '결제금액'
            }
            
            # 변경된 필드만 필터링하여 로그 메시지 구성
            change_descriptions = []
            for field, values in changes.items():
                if field in field_labels:
                    # None 값 안전하게 처리
                    old_val = values.get('old', '') or '없음'
                    new_val = values.get('new', '') or '없음'
                    
                    # 옵션은 JSON 문자열이므로 특별 처리
                    if field == 'options':
                        try:
                            old_json = json.loads(old_val) if old_val != '없음' and old_val else None
                            new_json = json.loads(new_val) if new_val != '없음' and new_val else None
                            
                            # 두 JSON이 실질적으로 동일한 값을 가지는지 확인
                            if old_json and new_json:
                                # 온라인 옵션 요약 비교
                                old_option_type = old_json.get('option_type', '')
                                new_option_type = new_json.get('option_type', '')
                                
                                # 타입이 다르면 변경된 것으로 간주
                                if old_option_type != new_option_type:
                                    if old_option_type == 'online':
                                        old_display = old_json.get('online_options_summary', '') or '없음'
                                    elif old_option_type == 'direct':
                                        details = old_json.get('details', {})
                                        old_display = '직접입력: ' + (details.get('product_name', '') or details.get('color', '') or '옵션')
                                    else:
                                        old_display = '옵션 있음'
                                        
                                    if new_option_type == 'online':
                                        new_display = new_json.get('online_options_summary', '') or '없음'
                                    elif new_option_type == 'direct':
                                        details = new_json.get('details', {})
                                        new_display = '직접입력: ' + (details.get('product_name', '') or details.get('color', '') or '옵션')
                                    else:
                                        new_display = '옵션 있음'
                                # 타입이 같고 온라인 옵션인 경우    
                                elif old_option_type == 'online':
                                    old_summary = old_json.get('online_options_summary', '')
                                    new_summary = new_json.get('online_options_summary', '')
                                    
                                    # 내용이 같으면 건너뛰기
                                    if old_summary == new_summary:
                                        continue
                                        
                                    old_display = old_summary or '없음'
                                    new_display = new_summary or '없음'
                                # 타입이 같고 직접 입력 옵션인 경우
                                elif old_option_type == 'direct':
                                    old_details = old_json.get('details', {})
                                    new_details = new_json.get('details', {})
                                    
                                    # 주요 필드만 비교 (product_name, color)
                                    old_key_values = old_details.get('product_name', '') + ' ' + old_details.get('color', '')
                                    new_key_values = new_details.get('product_name', '') + ' ' + new_details.get('color', '')
                                    
                                    # 내용이 같으면 건너뛰기
                                    if old_key_values.strip() == new_key_values.strip():
                                        continue
                                        
                                    old_display = old_details.get('product_name', '') or old_details.get('color', '') or '옵션 있음'
                                    new_display = new_details.get('product_name', '') or new_details.get('color', '') or '옵션 있음'
                                else:
                                    # 기타 경우는 간단하게 표시
                                    old_display = '옵션 있음'
                                    new_display = '옵션 있음'
                                    
                                    # 내용이 같아 보이면 건너뛰기
                                    if json.dumps(old_json, sort_keys=True) == json.dumps(new_json, sort_keys=True):
                                        continue
                            elif not old_json and not new_json:
                                # 둘 다 없거나 빈 값이면 건너뛰기
                                continue
                            else:
                                # 한쪽만 값이 있는 경우 (추가 또는 삭제)
                                if old_json:
                                    if old_json.get('option_type') == 'online':
                                        old_display = old_json.get('online_options_summary', '') or '옵션 있음'
                                    elif old_json.get('option_type') == 'direct':
                                        details = old_json.get('details', {})
                                        old_display = details.get('product_name', '') or details.get('color', '') or '직접입력 옵션'
                                    else:
                                        old_display = '옵션 있음'
                                else:
                                    old_display = '없음'
                                    
                                if new_json:
                                    if new_json.get('option_type') == 'online':
                                        new_display = new_json.get('online_options_summary', '') or '옵션 있음'
                                    elif new_json.get('option_type') == 'direct':
                                        details = new_json.get('details', {})
                                        new_display = details.get('product_name', '') or details.get('color', '') or '직접입력 옵션'
                                    else:
                                        new_display = '옵션 있음'
                                else:
                                    new_display = '없음'
                        except Exception as e:
                            # JSON 파싱 실패 시 원본 값 비교
                            old_display = old_val if old_val != '없음' else '없음'
                            new_display = new_val if new_val != '없음' else '없음'
                            
                            # 값이 같거나 둘 다 빈 값이면 건너뛰기
                            if old_display == new_display or (not old_display.strip() and not new_display.strip()):
                                continue
                    else:
                        # 다른 필드들은 문자열로 변환하여 비교
                        old_display = str(old_val).strip() if old_val != '없음' else '없음'
                        new_display = str(new_val).strip() if new_val != '없음' else '없음'
                        
                        # 값이 같으면 건너뛰기 (공백 제거 후 비교)
                        if old_display == new_display:
                            continue
                        
                        # 상태 코드를 한글 상태명으로 변환
                        if field == 'status':
                            old_display = STATUS.get(old_display, old_display)
                            new_display = STATUS.get(new_display, new_display)
                    
                    # 실제 값이 변경된 경우에만 표시 (위에서 필터링 이미 됨)
                    change_descriptions.append(f"{field_labels[field]}: {old_display} ⇒ {new_display}")
            
            # 주문 번호와 고객명은 필수로 포함
            user_for_log = get_user_by_id(session['user_id'])
            user_name_for_log = user_for_log.name if user_for_log else "Unknown user"
            log_message_prefix = f"주문 #{order_id} ({customer_name}) 수정 - 담당자: {user_name_for_log} (ID: {session.get('user_id')})"
            
            # 변경 내역이 있으면 추가
            if change_descriptions:
                log_message = f"{log_message_prefix} | 변경내용: {'; '.join(change_descriptions)}"
            else:
                log_message = f"{log_message_prefix} | 변경내용 없음"
            
            # 로그 저장
            log_access(log_message, session.get('user_id'))
            
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
        customer_name_for_log = order.customer_name # 로그용 고객명
        
        # Soft delete by updating status and recording original status
        order.status = 'DELETED'
        order.original_status = original_status
        order.deleted_at = deleted_at
        
        db.commit()
        
        user_for_log = get_user_by_id(session['user_id'])
        user_name_for_log = user_for_log.name if user_for_log else "Unknown user"
        log_access(f"주문 #{order_id} ({customer_name_for_log}) 삭제 - 담당자: {user_name_for_log} (ID: {session.get('user_id')})", session.get('user_id'))
        
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
        
        # 로그 기록 (한글로 변경)
        log_access(f"주문 {len(selected_ids)}개 복원", session.get('user_id'), {"count": len(selected_ids)})
        
        flash(f'{len(selected_ids)}개 주문이 성공적으로 복원되었습니다.', 'success')
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
        
        # 주문 ID 재정렬 실행
        reset_order_ids(db)
        
        # 로그 기록 (한글로 변경)
        log_access(f"주문 {len(selected_ids)}개 영구 삭제", session.get('user_id'), {"count": len(selected_ids)})
        
        flash(f'{len(selected_ids)}개의 주문이 영구적으로 삭제되었습니다.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'주문 영구 삭제 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('trash'))

@app.route('/permanent_delete_all_orders', methods=['POST'])
@login_required
@role_required(['ADMIN'])
def permanent_delete_all_orders():
    try:
        db = get_db()
        
        # 휴지통에 있는 모든 주문 조회
        deleted_orders = db.query(Order).filter(Order.status == 'DELETED').all()
        
        if not deleted_orders:
            flash('휴지통에 삭제할 주문이 없습니다.', 'warning')
            return redirect(url_for('trash'))
            
        deleted_count = len(deleted_orders)
            
        # 모든 주문 영구 삭제
        for order in deleted_orders:
            db.delete(order)
            
        db.commit()
        
        # 주문 ID 재정렬 실행
        reset_order_ids(db)
            
        # Log the action
        log_access(f"모든 주문 영구 삭제 ({deleted_count}개 항목)", session.get('user_id'), {"count": deleted_count})
            
        flash(f'모든 주문({deleted_count}개)이 영구적으로 삭제되었습니다.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'주문 영구 삭제 중 오류가 발생했습니다: {str(e)}', 'error')
        
    return redirect(url_for('trash'))

def reset_order_ids(db):
    """
    주문 ID를 1부터 연속적으로 재정렬합니다.
    관련된 로그 데이터도 함께 업데이트합니다.
    """
    try:
        # 임시 테이블 생성
        db.execute(text("CREATE TEMPORARY TABLE temp_order_mapping (old_id INT, new_id INT)"))
        
        # 현재 존재하는 모든 주문 목록 (삭제되지 않은 주문만)
        orders = db.query(Order).filter(Order.status != 'DELETED').order_by(Order.id).all()
        
        # 새로운 ID 값 배정
        new_id = 0
        for new_id, order in enumerate(orders, 1):
            # 이전 ID와 새 ID 매핑 저장
            if order.id != new_id:
                db.execute(text("INSERT INTO temp_order_mapping (old_id, new_id) VALUES (:old_id, :new_id)"), 
                          {"old_id": order.id, "new_id": new_id})
        
        # 실제 ID 업데이트 쿼리 준비
        mapping_exists = db.execute(text("SELECT COUNT(*) FROM temp_order_mapping")).scalar() > 0
        
        # 시퀀스 재설정 준비 (최대 ID 값 + 1로 설정)
        max_id = new_id if orders else 0  # 주문이 없으면 0부터 시작
        
        if mapping_exists:
            # ID 변경이 필요한 경우에만 진행
            # 매핑 테이블을 사용해 주문 ID 업데이트
            db.execute(text("""
                UPDATE orders 
                SET id = (SELECT new_id FROM temp_order_mapping WHERE temp_order_mapping.old_id = orders.id)
                WHERE id IN (SELECT old_id FROM temp_order_mapping)
            """))
            
            # 로그 데이터 업데이트 기능 제거
        
        # 시퀀스 재설정 (PostgreSQL 전용) - 항상 실행
        db.execute(text(f"ALTER SEQUENCE orders_id_seq RESTART WITH {max_id + 1}"))
        
        db.commit()
        
        # 임시 테이블 삭제
        db.execute(text("DROP TABLE IF EXISTS temp_order_mapping"))
        
    except Exception as e:
        db.rollback()
        # 오류 발생 시 임시 테이블 제거 시도
        try:
            db.execute(text("DROP TABLE IF EXISTS temp_order_mapping"))
        except:
            pass
        print(f"주문 ID 재정렬 중 오류 발생: {str(e)}")
        raise e

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
                    log_access(f"주문 #{order_id} 삭제 (일괄 작업)", current_user_id, {"order_id": order_id})
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
                    
                    log_access(f"주문 #{original_order.id}를 새 주문 #{copied_order.id}로 복사 (일괄 작업)", 
                               current_user_id, {"original_order_id": original_order.id, "new_order_id": copied_order.id})
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
                        # 상태 한글 변환
                        old_status_kr = STATUS.get(old_status, old_status)
                        new_status_kr = STATUS.get(new_status, new_status)
                        # 한글 로그 메시지
                        log_access(f"주문 #{order_id} 상태 변경: {old_status_kr} => {new_status_kr} (일괄 작업)", 
                                   current_user_id, {"order_id": order_id, "old_status": old_status, "new_status": new_status})
                        processed_count += 1
                    elif not order:
                         failed_count += 1 # 존재하지 않거나 삭제된 주문
                    # 상태가 이미 동일하면 처리하지 않음 (processed_count 증가 안함)
            else:
                 flash("'" + new_status + "'" + '는 유효하지 않은 상태입니다.', 'error')
                 return redirect(url_for('index'))

        # 모든 변경 사항을 한번에 커밋
        db.commit()

        # 성공/실패 메시지 생성
        if action.startswith('status_'):
            status_code = action.split('_', 1)[1]
            status_name = STATUS.get(status_code, status_code)
            action_display_name = f"상태를 '{status_name}'(으)로 변경"
        elif action == 'copy':
            action_display_name = "'복사'"
        elif action == 'delete':
            action_display_name = "'삭제'"
        else:
            action_display_name = f"\'{action}\'"
        
        success_msg = f"{processed_count}개의 주문에 대해 {action_display_name} 작업을 완료했습니다."
        if failed_count > 0:
            warning_msg = f"{failed_count}개의 주문은 처리할 수 없었습니다 (이미 삭제되었거나 존재하지 않음)."
            flash(warning_msg, 'warning')
        
        if processed_count > 0:
             flash(success_msg, 'success')
        elif failed_count == len(selected_ids):
             flash('선택한 주문을 처리할 수 없습니다.', 'error')
        else:
             flash('변경된 사항이 없습니다.', 'info')

    except Exception as e:
        if db:
            db.rollback()
        flash(f'일괄 작업 중 오류 발생: {str(e)}', 'error')
        current_app.logger.error(f"일괄 작업 실패: {e}", exc_info=True)
    
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN', 'MANAGER'])
def upload_excel():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'excel_file' not in request.files:
            flash('파일이 선택되지 않았습니다.', 'error')
            log_access(f"엑셀 업로드 실패: 파일이 선택되지 않음", session.get('user_id'))
            return redirect(request.url)
        
        file = request.files['excel_file']
        
        if file.filename == '':
            flash('파일이 선택되지 않았습니다.', 'error')
            log_access(f"엑셀 업로드 실패: 빈 파일명", session.get('user_id'))
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            db = get_db() # db 변수를 try 블록 외부에서도 사용 가능하도록 이동
            try:
                # Process the Excel file with pandas
                df = pd.read_excel(file_path)
                
                # Check for required columns (한글 컬럼명으로 변경)
                required_columns = ['접수일', '고객명', '전화번호', '주소', '제품']
                missing_columns = [col for col in required_columns if col not in df.columns]
                
                if missing_columns:
                    missing_cols_str = ", ".join(missing_columns)
                    flash(f'엑셀 파일에 필수 컬럼이 누락되었습니다: {missing_cols_str}', 'error')
                    log_access(f"엑셀 업로드 실패: 필수 컬럼 누락 ({missing_cols_str}) - 파일명: {filename}", session.get('user_id'))
                    # 파일 삭제 로직 추가 (오류 시)
                    try:
                        os.remove(file_path)
                    except OSError as e: # 구체적인 에러 타입 명시
                        print(f"업로드된 파일 삭제 오류: {file_path}: {e}")
                        log_access(f"업로드된 파일 삭제 오류: {file_path} - {e}", session.get('user_id'),
                                   {"filename": file_path, "error": str(e)})
                    return redirect(request.url)
                
                # Connect to database (이미 위에서 get_db() 호출)
                
                # Process each row
                order_count = 0
                added_order_ids = []
                
                for index, row in df.iterrows():
                    # Convert fields to the right format and provide defaults (한글 컬럼명 사용)
                    
                    # 날짜 필드 처리 (pd.to_datetime 사용)
                    received_date_dt = pd.to_datetime(row['접수일'], errors='coerce')
                    received_date = received_date_dt.strftime('%Y-%m-%d') if pd.notna(received_date_dt) else datetime.datetime.now().strftime('%Y-%m-%d')

                    measurement_date_dt = pd.to_datetime(row.get('실측일'), errors='coerce') # .get으로 안전하게 접근
                    measurement_date = measurement_date_dt.strftime('%Y-%m-%d') if pd.notna(measurement_date_dt) else None
                    
                    completion_date_dt = pd.to_datetime(row.get('설치완료일'), errors='coerce') # .get으로 안전하게 접근
                    completion_date = completion_date_dt.strftime('%Y-%m-%d') if pd.notna(completion_date_dt) else None

                    # 시간 필드 처리 (다양한 입력 형식 고려)
                    received_time_raw = row.get('접수시간') # .get으로 안전하게 접근
                    received_time = None
                    if pd.notna(received_time_raw):
                        if isinstance(received_time_raw, datetime.time):
                            received_time = received_time_raw.strftime('%H:%M')
                        elif isinstance(received_time_raw, datetime.datetime): # datetime 객체로 읽혔을 경우
                            received_time = received_time_raw.strftime('%H:%M')
                        elif isinstance(received_time_raw, str):
                            # 간단한 형식 검사 (예: HH:MM) - 필요시 정규식 등으로 강화
                            if re.match(r'^\d{1,2}:\d{2}$', received_time_raw.strip()):
                                received_time = received_time_raw.strip()
                            else:
                                try: # 엑셀에서 0.xxxx 와 같은 숫자형식으로 시간을 읽는 경우 대비
                                    time_float = float(received_time_raw)
                                    hours = int(time_float * 24)
                                    minutes = int((time_float * 24 * 60) % 60)
                                    received_time = f"{hours:02d}:{minutes:02d}"
                                except (ValueError, TypeError):
                                    print(f"Warning: Invalid time format for '접수시간': {received_time_raw}")
                                    received_time = None # 유효하지 않으면 None
                        # 추가: Excel에서 시간 형식이 숫자로 (예: 0.5 = 12:00 PM) 읽히는 경우 처리
                        elif isinstance(received_time_raw, (int, float)):
                            try:
                                # 소수점 형태의 시간을 HH:MM으로 변환
                                total_seconds = int(received_time_raw * 24 * 60 * 60)
                                hours = total_seconds // 3600
                                minutes = (total_seconds % 3600) // 60
                                received_time = f"{hours:02d}:{minutes:02d}"
                            except Exception:
                                 print(f"Warning: Could not convert numeric time for '접수시간': {received_time_raw}")
                                 received_time = None


                    measurement_time_raw = row.get('실측시간') # .get으로 안전하게 접근
                    measurement_time = None
                    if pd.notna(measurement_time_raw):
                        if isinstance(measurement_time_raw, datetime.time):
                            measurement_time = measurement_time_raw.strftime('%H:%M')
                        elif isinstance(measurement_time_raw, datetime.datetime):
                            measurement_time = measurement_time_raw.strftime('%H:%M')
                        elif isinstance(measurement_time_raw, str):
                            if re.match(r'^\d{1,2}:\d{2}$', measurement_time_raw.strip()):
                                measurement_time = measurement_time_raw.strip()
                            else:
                                try:
                                    time_float = float(measurement_time_raw)
                                    hours = int(time_float * 24)
                                    minutes = int((time_float * 24 * 60) % 60)
                                    measurement_time = f"{hours:02d}:{minutes:02d}"
                                except (ValueError, TypeError):
                                    print(f"Warning: Invalid time format for '실측시간': {measurement_time_raw}")
                                    measurement_time = None
                        elif isinstance(measurement_time_raw, (int, float)):
                            try:
                                total_seconds = int(measurement_time_raw * 24 * 60 * 60)
                                hours = total_seconds // 3600
                                minutes = (total_seconds % 3600) // 60
                                measurement_time = f"{hours:02d}:{minutes:02d}"
                            except Exception:
                                 print(f"Warning: Could not convert numeric time for '실측시간': {measurement_time_raw}")
                                 measurement_time = None
                    
                    # Handle options column if it exists (한글 컬럼명 '옵션')
                    options_raw = row.get('옵션') # .get으로 안전하게 접근
                    options = str(options_raw) if pd.notna(options_raw) else None # 어떤 형식이든 문자열로 저장
                    
                    # Handle notes column if it exists (한글 컬럼명 '비고')
                    notes_raw = row.get('비고') # .get으로 안전하게 접근
                    notes = str(notes_raw) if pd.notna(notes_raw) else None # 문자열로 저장

                    manager_name_raw = row.get('담당자') # .get으로 안전하게 접근
                    manager_name = str(manager_name_raw) if pd.notna(manager_name_raw) else None

                    # payment_amount 처리 (숫자형으로, 콤마 제거)
                    payment_amount_raw = row.get('결제금액')
                    payment_amount = 0 # 기본값 0
                    if pd.notna(payment_amount_raw):
                        try:
                            # 문자열일 경우 콤마 제거 후 정수 변환
                            if isinstance(payment_amount_raw, str):
                                payment_amount_str = payment_amount_raw.replace(',', '')
                                payment_amount = int(float(payment_amount_str)) # 소수점도 고려하여 float으로 먼저 변환
                            elif isinstance(payment_amount_raw, (int, float)):
                                payment_amount = int(payment_amount_raw)
                        except ValueError:
                            print(f"Warning: Invalid payment amount format for '결제금액': {payment_amount_raw}, defaulting to 0.")
                            payment_amount = 0 # 변환 실패 시 0

                    new_order = Order(
                        customer_name=str(row['고객명']) if pd.notna(row['고객명']) else '', # 문자열로 명시적 변환
                        phone=str(row['전화번호']) if pd.notna(row['전화번호']) else '', # 문자열로 명시적 변환
                        address=str(row['주소']) if pd.notna(row['주소']) else '', # 문자열로 명시적 변환
                        product=str(row['제품']) if pd.notna(row['제품']) else '', # 문자열로 명시적 변환
                        options=options,
                        notes=notes,
                        received_date=received_date,
                        received_time=received_time,
                        status='RECEIVED',  # Default status
                        measurement_date=measurement_date,
                        measurement_time=measurement_time,
                        completion_date=completion_date,
                        manager_name=manager_name,
                        payment_amount=payment_amount # 추가
                    )
                    
                    db.add(new_order)
                    db.flush() # ID 할당을 위해 flush
                    added_order_ids.append(new_order.id) # 추가된 주문 ID 저장
                    order_count += 1
                
                db.commit()
                flash(f'{order_count}개의 주문이 성공적으로 등록되었습니다.', 'success')
                log_access(f"엑셀 업로드 성공: {filename} 파일에서 {order_count}개 주문 추가", session.get('user_id'), 
                           {"filename": filename, "orders_added": order_count, "order_ids": added_order_ids})
                
            except Exception as e:
                if db: # db 객체가 초기화된 경우에만 롤백 시도
                    db.rollback()
                error_message = f'엑셀 파일 처리 중 오류가 발생했습니다: {str(e)}'
                flash(error_message, 'error')
                log_access(f"엑셀 업로드 실패: {filename} 파일 처리 중 오류 - {str(e)}", session.get('user_id'),
                           {"filename": filename, "error": str(e)})
            
            # Delete the file after processing (성공/실패 여부와 관계없이)
            try:
                os.remove(file_path)
            except OSError as e: # 구체적인 에러 타입 명시
                print(f"Error deleting uploaded file {file_path}: {e}")
                log_access(f"업로드된 파일 삭제 오류: {file_path} - {e}", session.get('user_id'),
                           {"filename": file_path, "error": str(e)})

            return redirect(url_for('index'))
        else:
            flash('허용되지 않은 파일 형식입니다. .xlsx 또는 .xls 파일만 업로드 가능합니다.', 'error')
            log_access(f"엑셀 업로드 실패: 허용되지 않은 파일 형식 - {file.filename}", session.get('user_id'),
                       {"filename": file.filename})
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
    
    # 검색어 필터 적용 (index 함수와 동일하게)
    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter( 
            or_(
                Order.id.like(search_term), # ID는 정확한 매칭이 나을 수 있으나, 일단 통일
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
                # payment_amount는 숫자형이므로 캐스팅 필요
                func.cast(Order.payment_amount, String).like(search_term)
            )
        )

    # 컬럼별 입력 필터 적용 (index 함수와 동일한 로직으로 변경)
    filterable_columns = [
        'id', 'received_date', 'received_time', 'customer_name', 'phone', 
        'address', 'product', 'options', 'notes', 'status', 
        'measurement_date', 'measurement_time', 'completion_date', 'manager_name', 'payment_amount'
    ]
    for column_name in filterable_columns:
        filter_value = request.args.get(f'filter_{column_name}', '').strip() # get 대신 getlist 사용하지 않음
        if filter_value:
            if hasattr(Order, column_name):
                try:
                    column_attr = getattr(Order, column_name)
                    # 숫자 타입 컬럼일 경우 문자열로 캐스팅 후 LIKE 적용
                    if isinstance(column_attr.type.python_type(), (int, float)):
                         query = query.filter(column_attr.cast(String).like(f"%{filter_value}%"))
                    else:
                         query = query.filter(column_attr.like(f"%{filter_value}%"))
                except AttributeError:
                    # 컬럼이 없거나 LIKE 사용 불가 시 경고 (index 함수와 동일)
                    print(f"Warning: Column {column_name} not found or cannot be filtered with LIKE in download_excel.")
            else:
                 print(f"Warning: Column {column_name} not found in Order model in download_excel.")
                
    # 정렬 적용 (루프 바깥으로 이동)
    if hasattr(Order, sort_column):
        column_to_sort = getattr(Order, sort_column)
        if sort_direction == 'asc':
            query = query.order_by(column_to_sort.asc())
        else:
            query = query.order_by(column_to_sort.desc())
    else:
        query = query.order_by(Order.id.desc()) # 기본 정렬

    orders = query.all()
    
    # 다운로드할 주문 ID 목록
    downloaded_order_ids = [order.id for order in orders] if orders else []

    if not orders:
        flash('다운로드할 데이터가 없습니다.', 'warning')
        return redirect(request.referrer or url_for('index'))
    
    # 데이터를 Pandas DataFrame으로 변환
    orders_data = []
    for order in orders:
        order_dict = order.to_dict()
        # 옵션을 한글로 변환하는 로직 추가
        order_dict['options'] = format_options_for_display(order.options) # 전역 함수 호출
        orders_data.append(order_dict)

    df = pd.DataFrame(orders_data)
    
    # 상태 코드를 한글 이름으로 변경
    if 'status' in df.columns:
        df['status'] = df['status'].map(STATUS).fillna(df['status'])
        
    # 필요한 컬럼 선택 및 순서 지정
    excel_columns = [
        'id', 'received_date', 'received_time', 'customer_name', 'phone', 'address', 
        'product', 'options', 'notes', 'payment_amount',
        'measurement_date', 'measurement_time', 'completion_date', 
        'manager_name', 'status'
    ]
    # DataFrame에 없는 컬럼이 excel_columns에 포함되어 있을 경우 KeyError 발생 방지
    df_excel_columns = [col for col in excel_columns if col in df.columns]
    df_excel = df[df_excel_columns]
    
    # 컬럼명 한글로 변경
    column_mapping_korean = {
        'id': '번호', 'received_date': '접수일', 'received_time': '접수시간', 
        'customer_name': '고객명', 'phone': '연락처', 'address': '주소', 
        'product': '제품', 'options': '옵션', 'notes': '비고', 
        'payment_amount': '결제금액', 'measurement_date': '실측일', 
        'measurement_time': '실측시간', 'completion_date': '설치완료일', 
        'manager_name': '담당자', 'status': '상태'
    }
    df_excel.rename(columns=column_mapping_korean, inplace=True)
    
    # 엑셀 파일 생성
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    excel_filename = f"furniture_orders_{timestamp}.xlsx"
    excel_path = os.path.join(app.config['UPLOAD_FOLDER'], excel_filename)
    
    df_excel.to_excel(excel_path, index=False, engine='openpyxl')
    
    # 로그 기록
    log_access(f"엑셀 다운로드: {excel_filename}", session.get('user_id'))
    
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
            # log_access(f"메뉴 설정 업데이트", session.get('user_id')) # 로그 형식 수정 필요
            user_for_log = get_user_by_id(session['user_id'])
            user_name_for_log = user_for_log.name if user_for_log else "Unknown user"
            log_access(f"메뉴 설정 업데이트 - 담당자: {user_name_for_log} (ID: {session.get('user_id')})", session.get('user_id'))
            
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
            log_access(f"사용자 추가: {username}", session.get('user_id'))
            
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
            log_access(f"사용자 #{user_id} 정보 수정", session.get('user_id'))
            
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
        log_access(f"사용자 #{user_id} 삭제", session.get('user_id'))
        
        flash('사용자가 성공적으로 삭제되었습니다.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'사용자 삭제 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('user_list'))

def translate_dict_keys(d, key_map):
    if not isinstance(d, dict):
        return d
    new_dict = {}
    for k, v in d.items():
        translated_key = key_map.get(k, k)
        if isinstance(v, dict):
            new_dict[translated_key] = translate_dict_keys(v, key_map)
        elif isinstance(v, list):
            new_dict[translated_key] = [translate_dict_keys(item, key_map) for item in v]
        else:
            new_dict[translated_key] = v
    return new_dict

def format_value_for_log(value):
    if value is None:
        return "없음"
    if isinstance(value, str) and not value.strip(): # 빈 문자열
        return "없음"
    return str(value)

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
                log_access("비밀번호 변경 완료", user_id)
                
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
        ],
        'admin_menu': [
            {'id': 'user_management', 'name': '사용자 관리', 'url': '/admin/users'},
            {'id': 'security_logs', 'name': '보안 로그', 'url': '/admin/security-logs'}
        ]
    }

@app.context_processor
def inject_menu():
    menu_config = load_menu_config()
    return dict(menu=menu_config)

# options 필드 변경 관련 헬퍼 함수는 보안 로그 재구성 이후 다시 구현할 예정
# 임시로 간단한 형태의 함수만 유지
def translate_dict_keys(d, key_map):
    if not isinstance(d, dict):
        return d
    new_dict = {}
    for k, v in d.items():
        translated_key = key_map.get(k, k)
        if isinstance(v, dict):
            new_dict[translated_key] = translate_dict_keys(v, key_map)
        elif isinstance(v, list):
            new_dict[translated_key] = [translate_dict_keys(item, key_map) for item in v]
        else:
            new_dict[translated_key] = v
    return new_dict

def format_value_for_log(value):
    if value is None:
        return "없음"
    if isinstance(value, str) and not value.strip(): # 빈 문자열
        return "없음"
    return str(value)

# Jinja 필터: 메시지 내 "주문 #<번호>"를 클릭 가능한 링크로 변환
@app.template_filter('order_link')
def order_link_filter(s):
    import re
    from flask import url_for
    def repl(m):
        oid = m.group(1)
        link = url_for('edit_order', order_id=oid)
        return Markup(f'<a href="{link}">주문 #{oid}</a>')
    return Markup(re.sub(r'주문 #(\d+)', repl, s))

# 보안 로그 목록 조회 라우트 추가 (관리자 전용)
@app.route('/security_logs')
@login_required
@role_required(['ADMIN'])
def security_logs():
    db = get_db()
    
    # 필터링 위한 사용자 목록 가져오기
    users_for_filter = db.query(User).order_by(User.username).all()
    
    query = db.query(SecurityLog)
    
    # 사용자 ID로 필터링
    filter_user_id_str = request.args.get('user_id')
    selected_user_id = None
    if filter_user_id_str and filter_user_id_str.isdigit():
        selected_user_id = int(filter_user_id_str)
        query = query.filter(SecurityLog.user_id == selected_user_id)
        
    # 표시 개수 제한
    limit_str = request.args.get('limit', '100') # 기본값 100으로 설정
    current_limit = 100 # 기본값
    if limit_str.isdigit() and int(limit_str) > 0:
        current_limit = int(limit_str)
    
    logs_from_db = query.order_by(SecurityLog.timestamp.desc()).limit(current_limit).all()
    
    # 로그에 사용자 정보(username, name)를 추가 (템플릿에서 쉽게 사용하기 위해)
    enriched_logs = []
    for log_item in logs_from_db:
        log_user = None
        if log_item.user_id:
            # get_user_by_id 함수를 사용하여 사용자 정보 가져오기
            log_user = get_user_by_id(log_item.user_id) 
        
        enriched_logs.append({
            'timestamp': log_item.timestamp,
            'message': log_item.message,
            'user_id': log_item.user_id,
            'username': log_user.username if log_user else "N/A", 
            'name': log_user.name if log_user else "System" 
        })
        
    return render_template(
        'security_logs.html',
        logs=enriched_logs,
        users=users_for_filter, 
        current_user_id=selected_user_id, 
        current_limit=current_limit 
    )

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