import os
from flask import Flask, session, g
from flask_wtf.csrf import CSRFProtect
from flask_session import Session
import logging
from sqlalchemy import text, inspect

from app.config.config import get_config
from db import init_db, get_db, close_db

# Blueprint import
from app.routes.auth import auth_bp, ROLES
from app.routes.orders import orders_bp
from app.routes.admin import admin_bp
from app.routes.utils import utils_bp

def create_app():
    """애플리케이션 팩토리 함수"""
    app = Flask(__name__, 
                static_folder='../static',
                template_folder='../templates')
    
    # 설정 로드
    app_config = get_config()
    app.config.from_object(app_config)
    
    # CSRF 보호 활성화
    csrf = CSRFProtect(app)
    
    # Flask-Session 설정
    Session(app)
    
    # 로깅 설정
    if app.config['DEBUG']:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # 데이터베이스 연결 설정
    app.teardown_appcontext(close_db)
    
    # 템플릿에서 전역 변수 사용을 위한 context processor
    @app.context_processor
    def inject_user():
        user = None
        if 'user_id' in session:
            from app.services.user_service import UserService
            user = UserService.get_user_by_id(session['user_id'])
        return dict(current_user=user, ROLES=ROLES)
    
    # Blueprint 등록
    app.register_blueprint(auth_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(utils_bp)
    
    # 앱 시작 시 데이터베이스 초기화 및 스키마 검사
    with app.app_context():
        init_db()
        check_database_schema(app)
    
    return app

def check_database_schema(app):
    """데이터베이스 스키마 검사 및 업데이트"""
    try:
        db = get_db()
        inspector = inspect(db.get_bind())
        
        # orders 테이블의 컬럼 정보 가져오기
        existing_columns = [column['name'] for column in inspector.get_columns('orders')]
        
        # 필요한 컬럼 확인 및 추가
        for column, column_type in [
            ('measurement_date', 'VARCHAR'),
            ('measurement_time', 'VARCHAR'),
            ('completion_date', 'VARCHAR'),
            ('manager_name', 'VARCHAR')
        ]:
            # 해당 컬럼이 이미 존재하는지 확인
            if column not in existing_columns:
                alter_query = text(f"ALTER TABLE orders ADD COLUMN {column} {column_type}")
                db.execute(alter_query)
                app.logger.info(f"Added column {column} to orders table")
        
        db.commit()
        app.logger.info("Database schema check completed")
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error checking/updating database schema: {str(e)}") 