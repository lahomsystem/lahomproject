import datetime
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_db
from models import User, AccessLog

class UserService:
    """사용자 관련 비즈니스 로직을 위한 서비스 클래스"""
    
    @staticmethod
    def get_user_by_username(username):
        """사용자명으로 사용자 조회"""
        db = get_db()
        return db.query(User).filter(User.username == username).first()
    
    @staticmethod
    def get_user_by_id(user_id):
        """ID로 사용자 조회"""
        db = get_db()
        return db.query(User).filter(User.id == user_id).first()
    
    @staticmethod
    def update_last_login(user_id):
        """사용자의 마지막 로그인 시간 업데이트"""
        try:
            db = get_db()
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.last_login = datetime.datetime.now()
                db.commit()
                return True
            return False
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error updating last login: {str(e)}")
            return False
    
    @staticmethod
    def is_password_strong(password):
        """비밀번호가 보안 요구사항을 충족하는지 확인"""
        if len(password) < 8:
            return False
        
        # 대문자, 소문자, 숫자 포함 확인
        has_upper = any(char.isupper() for char in password)
        has_lower = any(char.islower() for char in password)
        has_digit = any(char.isdigit() for char in password)
        
        return has_upper and has_lower and has_digit
    
    @staticmethod
    def create_user(user_data):
        """사용자 생성"""
        db = get_db()
        try:
            # 해시된 비밀번호 생성
            hashed_password = generate_password_hash(user_data['password'])
            
            # 새 사용자 생성
            new_user = User(
                username=user_data['username'],
                password=hashed_password,
                name=user_data.get('name', '사용자'),
                role=user_data['role'],
                is_active=user_data.get('is_active', True)
            )
            
            db.add(new_user)
            db.commit()
            return new_user
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error creating user: {str(e)}")
            raise
    
    @staticmethod
    def update_user(user_id, user_data):
        """사용자 정보 업데이트"""
        db = get_db()
        user = UserService.get_user_by_id(user_id)
        
        if not user:
            return None
        
        try:
            user.name = user_data.get('name', user.name)
            user.role = user_data.get('role', user.role)
            user.is_active = user_data.get('is_active', user.is_active)
            
            # 비밀번호 변경이 있는 경우
            if 'password' in user_data and user_data['password']:
                user.password = generate_password_hash(user_data['password'])
            
            db.commit()
            return user
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error updating user: {str(e)}")
            raise
    
    @staticmethod
    def delete_user(user_id):
        """사용자 삭제"""
        db = get_db()
        user = UserService.get_user_by_id(user_id)
        
        if not user:
            return False
        
        try:
            db.delete(user)
            db.commit()
            return True
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error deleting user: {str(e)}")
            raise
    
    @staticmethod
    def get_all_users():
        """모든 사용자 조회"""
        db = get_db()
        return db.query(User).order_by(User.username).all()
    
    @staticmethod
    def check_admin_user_count():
        """관리자 사용자 수 조회"""
        db = get_db()
        return db.query(User).filter(User.role == 'ADMIN').count()
    
    @staticmethod
    def verify_password(user, password):
        """비밀번호 확인"""
        if not user:
            return False
        return check_password_hash(user.password, password)
    
    @staticmethod
    def log_access(action, user_id=None, additional_data=None, request=None):
        """보안 모니터링을 위한 사용자 작업 로깅"""
        try:
            db = get_db()
            
            # 기본 로그 데이터 준비
            log_data = {
                'user_id': user_id,
                'action': action
            }
            
            # 요청 객체가 있는 경우 IP와 User-Agent 추가
            if request:
                log_data['ip_address'] = request.remote_addr
                log_data['user_agent'] = request.user_agent.string
            
            # 추가 데이터 처리
            if additional_data:
                # 문자열이 아닌 경우 JSON으로 직렬화
                if not isinstance(additional_data, str):
                    import json
                    additional_data_str = json.dumps(additional_data)
                else:
                    additional_data_str = additional_data
                
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
                    else:
                        raise e
            else:
                new_log = AccessLog(**log_data)
                db.add(new_log)
                db.commit()
                
            return True
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error logging access: {str(e)}")
            return False
    
    @staticmethod
    def get_security_logs(limit=100, user_id=None):
        """보안 로그 조회"""
        db = get_db()
        
        try:
            # 사용자 정보와 함께 로그 조회
            logs_query = db.query(AccessLog, User.username, User.name)\
                        .outerjoin(User, AccessLog.user_id == User.id)\
                        .order_by(AccessLog.timestamp.desc())
            
            if user_id:
                logs_query = logs_query.filter(AccessLog.user_id == user_id)
            
            if limit:
                logs_query = logs_query.limit(limit)
                
            return logs_query.all()
        except Exception as e:
            current_app.logger.error(f"Error fetching security logs: {str(e)}")
            # additional_data 컬럼 없는 경우 대체 쿼리 시도
            if 'additional_data' in str(e):
                try:
                    logs_query = db.query(
                        AccessLog.id, AccessLog.user_id, AccessLog.action, 
                        AccessLog.ip_address, AccessLog.timestamp,
                        User.username, User.name
                    ).outerjoin(User, AccessLog.user_id == User.id)\
                    .order_by(AccessLog.timestamp.desc())
                    
                    if user_id:
                        logs_query = logs_query.filter(AccessLog.user_id == user_id)
                    
                    if limit:
                        logs_query = logs_query.limit(limit)
                        
                    return logs_query.all()
                except Exception as nested_e:
                    current_app.logger.error(f"Error in fallback query: {str(nested_e)}")
                    return []
            return [] 