import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from sqlalchemy import text

from app.services.user_service import UserService 
from app.routes.auth import login_required, role_required, ROLES

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# 관리자 대시보드
@admin_bp.route('/')
@login_required
@role_required(['ADMIN'])
def admin_dashboard():
    """관리자 대시보드"""
    return render_template('admin.html')

# 메뉴 관리
@admin_bp.route('/update_menu', methods=['POST'])
@login_required
@role_required(['ADMIN'])
def update_menu():
    """메뉴 구성 업데이트"""
    try:
        menu_config = request.form.get('menu_config')
        if menu_config:
            # 메뉴 구성을 파일에 저장
            with open('menu_config.json', 'w', encoding='utf-8') as f:
                f.write(menu_config)
            
            # 작업 로그
            UserService.log_access(f"Updated menu configuration", session.get('user_id'), request=request)
            
            flash('메뉴 구성이 업데이트되었습니다.', 'success')
        else:
            flash('메뉴 구성을 입력해주세요.', 'error')
    except Exception as e:
        flash(f'메뉴 업데이트 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('admin.admin_dashboard'))

# 사용자 관리
@admin_bp.route('/users')
@login_required
@role_required(['ADMIN'])
def user_list():
    """사용자 목록"""
    users = UserService.get_all_users()
    count_admin = UserService.check_admin_user_count()
    
    return render_template('user_list.html', users=users, count_admin=count_admin)

@admin_bp.route('/users/add', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
def add_user():
    """사용자 추가"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name', '사용자')
        role = request.form.get('role')
        
        # 필수 필드 검증
        if not all([username, password, role]):
            flash('모든 필수 입력 필드를 입력해주세요.', 'error')
            return render_template('add_user.html')
        
        # 비밀번호 강도 확인
        if not UserService.is_password_strong(password):
            flash('비밀번호는 8자 이상이며, 대문자, 소문자, 숫자를 각각 1개 이상 포함해야 합니다.', 'error')
            return render_template('add_user.html')
        
        # 사용자명 중복 확인
        if UserService.get_user_by_username(username):
            flash('이미 사용 중인 아이디입니다.', 'error')
            return render_template('add_user.html')
        
        # 역할 검증
        if role not in ROLES:
            flash('유효하지 않은 역할입니다.', 'error')
            return render_template('add_user.html')
        
        try:
            # 사용자 생성
            UserService.create_user({
                'username': username,
                'password': password,
                'name': name,
                'role': role,
                'is_active': True
            })
            
            # 작업 로그
            UserService.log_access(f"Added new user: {username}", session.get('user_id'), request=request)
            
            flash('사용자가 성공적으로 추가되었습니다.', 'success')
            return redirect(url_for('admin.user_list'))
                
        except Exception as e:
            flash(f'사용자 추가 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('add_user.html')
    
    return render_template('add_user.html', roles=ROLES)

@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
def edit_user(user_id):
    """사용자 수정"""
    user = UserService.get_user_by_id(user_id)
    
    if not user:
        flash('사용자를 찾을 수 없습니다.', 'error')
        return redirect(url_for('admin.user_list'))
    
    # 마지막 관리자 역할 변경 방지
    if user.role == 'ADMIN':
        admin_count = UserService.check_admin_user_count()
        
        if admin_count == 1 and request.method == 'POST' and request.form.get('role') != 'ADMIN':
            flash('마지막 관리자의 역할은 변경할 수 없습니다.', 'error')
            return redirect(url_for('admin.edit_user', user_id=user_id))
    
    if request.method == 'POST':
        name = request.form.get('name', '사용자')
        role = request.form.get('role')
        is_active = request.form.get('is_active') == 'on'
        
        # 역할 검증
        if not role:
            flash('역할은 필수 입력 필드입니다.', 'error')
            return render_template('edit_user.html', user=user)
        
        if role not in ROLES:
            flash('유효하지 않은 역할입니다.', 'error')
            return render_template('edit_user.html', user=user)
        
        try:
            # 기본 정보 업데이트
            user_data = {
                'name': name,
                'role': role,
                'is_active': is_active
            }
            
            # 비밀번호 변경 처리
            new_password = request.form.get('new_password')
            if new_password:
                if UserService.is_password_strong(new_password):
                    user_data['password'] = new_password
                    flash('비밀번호가 변경되었습니다.', 'success')
                else:
                    flash('비밀번호는 8자 이상이며, 대문자, 소문자, 숫자를 각각 1개 이상 포함해야 합니다.', 'error')
                    return render_template('edit_user.html', user=user, roles=ROLES)
            
            # 사용자 업데이트
            UserService.update_user(user_id, user_data)
            
            # 작업 로그
            UserService.log_access(f"Updated user #{user_id}", session.get('user_id'), request=request)
            
            flash('사용자 정보가 성공적으로 업데이트되었습니다.', 'success')
            return redirect(url_for('admin.user_list'))
                
        except Exception as e:
            flash(f'사용자 정보 업데이트 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('edit_user.html', user=user, roles=ROLES)
    
    return render_template('edit_user.html', user=user, roles=ROLES)

@admin_bp.route('/users/delete/<int:user_id>')
@login_required
@role_required(['ADMIN'])
def delete_user(user_id):
    """사용자 삭제"""
    # 자기 자신 삭제 방지
    if user_id == session.get('user_id'):
        flash('자신의 계정은 삭제할 수 없습니다.', 'error')
        return redirect(url_for('admin.user_list'))
    
    user = UserService.get_user_by_id(user_id)
    
    if not user:
        flash('사용자를 찾을 수 없습니다.', 'error')
        return redirect(url_for('admin.user_list'))
    
    # 마지막 관리자 삭제 방지
    if user.role == 'ADMIN':
        admin_count = UserService.check_admin_user_count()
        
        if admin_count == 1:
            flash('마지막 관리자는 삭제할 수 없습니다.', 'error')
            return redirect(url_for('admin.user_list'))
    
    try:
        # 사용자 삭제
        UserService.delete_user(user_id)
        
        # 작업 로그
        UserService.log_access(f"Deleted user #{user_id}", session.get('user_id'), request=request)
        
        flash('사용자가 성공적으로 삭제되었습니다.', 'success')
    except Exception as e:
        flash(f'사용자 삭제 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('admin.user_list'))

# 보안 로그
@admin_bp.route('/security-logs')
@login_required
@role_required(['ADMIN'])
def security_logs():
    """보안 로그 조회"""
    limit = request.args.get('limit', 100, type=int)
    user_id = request.args.get('user_id', type=int)
    
    raw_logs = UserService.get_security_logs(limit, user_id)
    
    # 로그 파싱 및 형식화
    logs = []
    for log_record in raw_logs:
        if isinstance(log_record, tuple) and len(log_record) >= 3:
            access_log = log_record[0]  # AccessLog 객체
            username = log_record[1]    # 사용자명
            name = log_record[2]        # 사용자 실명
            
            # 로그 액션 파싱 (parse_action_log 함수 대체)
            action_type = "기타"
            action_details = access_log.action
            
            # 간단한 액션 타입 분류
            if "login" in access_log.action.lower():
                action_type = "로그인"
            elif "logout" in access_log.action.lower():
                action_type = "로그아웃"
            elif "order" in access_log.action.lower():
                action_type = "주문 관리"
            elif "user" in access_log.action.lower():
                action_type = "사용자 관리"
            elif "menu" in access_log.action.lower():
                action_type = "메뉴 설정"
            elif "password" in access_log.action.lower():
                action_type = "비밀번호 변경"
            elif "uploaded" in access_log.action.lower():
                action_type = "파일 업로드"
            elif "downloaded" in access_log.action.lower():
                action_type = "파일 다운로드"
            
            logs.append({
                'timestamp': getattr(access_log, 'timestamp', ''),
                'username': username or '(익명)',
                'name': name or '',
                'action_type': action_type,
                'action_details': action_details,
                'ip_address': getattr(access_log, 'ip_address', ''),
            })
        elif isinstance(log_record, tuple) and len(log_record) >= 7:  # 대체 쿼리 결과
            # 컬럼 순서: id, user_id, action, ip_address, timestamp, username, name
            action_type = "기타"
            action = log_record[2]
            
            # 간단한 액션 타입 분류
            if "login" in action.lower():
                action_type = "로그인"
            elif "logout" in action.lower():
                action_type = "로그아웃"
            elif "order" in action.lower():
                action_type = "주문 관리"
            elif "user" in action.lower():
                action_type = "사용자 관리"
            elif "menu" in action.lower():
                action_type = "메뉴 설정"
            elif "password" in action.lower():
                action_type = "비밀번호 변경"
            elif "uploaded" in action.lower():
                action_type = "파일 업로드"
            elif "downloaded" in action.lower():
                action_type = "파일 다운로드"
            
            logs.append({
                'timestamp': log_record[4],
                'username': log_record[5] or '(익명)',
                'name': log_record[6] or '',
                'action_type': action_type,
                'action_details': action,
                'ip_address': log_record[3] or '',
            })
    
    # 사용자 목록 (필터용)
    users = UserService.get_all_users()
    
    return render_template('security_logs.html', logs=logs, users=users, current_user_id=user_id) 