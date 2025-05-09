from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.services.user_service import UserService
from functools import wraps

# 상수 정의
# User roles 
ROLES = {
    'ADMIN': '관리자',     # 전체 접근 권한
    'MANAGER': '매니저',   # 주문 관리 가능, 사용자 관리 불가
    'STAFF': '직원',       # 주문 조회/추가 가능, 편집 제한
    'VIEWER': '뷰어'       # 조회만 가능
}

auth_bp = Blueprint('auth', __name__)

# 인증 데코레이터
def login_required(f):
    """로그인이 필요한 라우트에 대한 데코레이터"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'error')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    """특정 역할이 필요한 라우트에 대한 데코레이터"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('로그인이 필요합니다.', 'error')
                return redirect(url_for('auth.login', next=request.url))
            
            user = UserService.get_user_by_id(session['user_id'])
            if not user:
                session.clear()
                flash('사용자를 찾을 수 없습니다. 다시 로그인해주세요.', 'error')
                return redirect(url_for('auth.login'))
            
            if user.role not in roles:
                flash('이 페이지에 접근할 권한이 없습니다.', 'error')
                UserService.log_access(f"Unauthorized access attempt to {request.path}", user.id, request=request)
                return redirect(url_for('orders.index'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """로그인 처리"""
    if 'user_id' in session:
        return redirect(url_for('orders.index'))
    
    next_url = request.args.get('next', url_for('orders.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('아이디와 비밀번호를 모두 입력해주세요.', 'error')
            return render_template('login.html')
        
        # 사용자 조회
        user = UserService.get_user_by_username(username)
        
        if not user:
            UserService.log_access(f"Failed login attempt for username: {username}", request=request)
            flash('아이디 또는 비밀번호가 일치하지 않습니다.', 'error')
            return render_template('login.html')
        
        # 계정 활성화 상태 확인
        if not user.is_active:
            UserService.log_access(f"Inactive account login attempt: {username}", user.id, request=request)
            flash('비활성화된 계정입니다. 관리자에게 문의하세요.', 'error')
            return render_template('login.html')
        
        # 비밀번호 확인
        if UserService.verify_password(user, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            # 세션 영구 저장 설정
            session.permanent = True
            
            # 마지막 로그인 시간 업데이트
            UserService.update_last_login(user.id)
            UserService.log_access("Login successful", user.id, request=request)
            
            flash(f'{user.name}님, 환영합니다!', 'success')
            return redirect(next_url)
        else:
            UserService.log_access(f"Failed login attempt (wrong password) for username: {username}", 
                      user.id if user else None, request=request)
            flash('아이디 또는 비밀번호가 일치하지 않습니다.', 'error')
    
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    """로그아웃 처리"""
    if 'user_id' in session:
        UserService.log_access("Logout", session.get('user_id'), request=request)
        session.clear()
        flash('로그아웃되었습니다.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """회원가입 처리 (첫 관리자 계정 생성용)"""
    if 'user_id' in session:
        return redirect(url_for('orders.index'))
    
    # 시스템에 사용자가 있는지 확인
    user_count = UserService.check_admin_user_count()
    
    # 이미 사용자가 있으면 로그인 페이지로 리디렉션
    if user_count > 0:
        flash('사용자 등록은 관리자를 통해서만 가능합니다.', 'error')
        return redirect(url_for('auth.login'))
    
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
        
        if not UserService.is_password_strong(password):
            flash('비밀번호는 최소 8자 이상이며, 대문자, 소문자, 숫자를 포함해야 합니다.', 'error')
            return render_template('register.html')
        
        # 사용자명 중복 확인
        existing_user = UserService.get_user_by_username(username)
        if existing_user:
            flash('이미 사용 중인 아이디입니다.', 'error')
            return render_template('register.html')
        
        # 관리자 계정 생성
        try:
            UserService.create_user({
                'username': username,
                'password': password,
                'name': name,
                'role': 'ADMIN'  # 첫 사용자는 항상 관리자
            })
            
            UserService.log_access(f"Initial admin account created: {username}", request=request)
            
            flash('계정이 생성되었습니다. 로그인해주세요.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash(f'계정 생성 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """사용자 프로필 관리"""
    user_id = session.get('user_id')
    user = UserService.get_user_by_id(user_id)
    
    if not user:
        session.clear()
        flash('사용자를 찾을 수 없습니다. 다시 로그인해주세요.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name')
        
        # 이름 검증
        if not name:
            flash('이름을 입력해주세요.', 'error')
            return render_template('profile.html', user=user)
        
        try:
            # 기본 정보 업데이트
            UserService.update_user(user_id, {'name': name})
            
            # 비밀번호 변경 처리
            if current_password and new_password and confirm_password:
                # 현재 비밀번호 확인
                if not UserService.verify_password(user, current_password):
                    flash('현재 비밀번호가 일치하지 않습니다.', 'error')
                    return render_template('profile.html', user=user)
                
                # 새 비밀번호 일치 확인
                if new_password != confirm_password:
                    flash('새 비밀번호가 일치하지 않습니다.', 'error')
                    return render_template('profile.html', user=user)
                
                # 비밀번호 강도 확인
                if not UserService.is_password_strong(new_password):
                    flash('비밀번호는 8자 이상이며, 대문자, 소문자, 숫자를 각각 1개 이상 포함해야 합니다.', 'error')
                    return render_template('profile.html', user=user)
                
                # 비밀번호 업데이트
                UserService.update_user(user_id, {'password': new_password})
                
                # 로그 기록
                UserService.log_access("Changed password", user_id, request=request)
                
                flash('비밀번호가 성공적으로 변경되었습니다.', 'success')
            
            flash('프로필이 업데이트되었습니다.', 'success')
            return redirect(url_for('auth.profile'))
                
        except Exception as e:
            flash(f'프로필 업데이트 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('profile.html', user=user)
    
    return render_template('profile.html', user=user) 