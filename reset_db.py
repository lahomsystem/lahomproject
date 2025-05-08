import os
import sqlite3
from db import init_db, db_session
from models import Order, User, AccessLog

def reset_orders_only():
    """주문 데이터만 리셋하는 함수, 사용자 및 로그 정보는 유지"""
    try:
        # DB 세션에서 모든 주문 데이터 삭제
        db_session.query(Order).delete()
        db_session.commit()
        print("주문 데이터가 성공적으로 삭제되었습니다.")
        
        # 테이블이 없는 경우 데이터베이스 초기화
        init_db()
        
        return True
    except Exception as e:
        db_session.rollback()
        print(f"주문 데이터 삭제 중 오류 발생: {str(e)}")
        return False

def create_admin_if_not_exists():
    """관리자 계정이 없으면 기본 관리자 계정 생성"""
    from werkzeug.security import generate_password_hash
    
    try:
        # 관리자 계정 확인
        admin = db_session.query(User).filter(User.username == 'admin').first()
        
        if not admin:
            # 기본 관리자 계정 생성
            admin_user = User(
                username='admin',
                password=generate_password_hash('Admin123'),
                name='관리자',
                role='ADMIN'
            )
            db_session.add(admin_user)
            db_session.commit()
            print("기본 관리자 계정이 생성되었습니다. (ID: admin, PW: Admin123)")
        else:
            print("관리자 계정이 이미 존재합니다.")
            
        return True
    except Exception as e:
        db_session.rollback()
        print(f"관리자 계정 생성 중 오류 발생: {str(e)}")
        return False

if __name__ == "__main__":
    # 주문 데이터만 초기화
    reset_orders_only()
    
    # 관리자 계정 생성 확인
    create_admin_if_not_exists()
    
    print("데이터베이스 리셋 및 초기화가 완료되었습니다.") 