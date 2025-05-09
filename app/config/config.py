import os
from datetime import timedelta

class Config:
    """기본 설정 클래스"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'furniture_order_management_secret_key')
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)  # 세션 유효 기간 1일
    SESSION_TYPE = 'filesystem'  # 파일 시스템 기반 세션 저장
    SESSION_USE_SIGNER = True    # 쿠키에 서명 추가
    SESSION_FILE_DIR = os.path.join(os.getcwd(), 'flask_session')  # 세션 파일 저장 위치

class DevelopmentConfig(Config):
    """개발 환경 설정"""
    DEBUG = True
    SQLALCHEMY_ECHO = True  # SQL 쿼리 로깅
    
class ProductionConfig(Config):
    """운영 환경 설정"""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')  # 운영 환경에서는 반드시 환경변수로 설정
    
class TestingConfig(Config):
    """테스트 환경 설정"""
    TESTING = True
    DEBUG = True
    
# 환경별 설정 사전
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """현재 환경에 맞는 설정 반환"""
    env = os.environ.get('FLASK_ENV', 'default')
    return config.get(env, config['default']) 