from db import db_session, init_db
from models import User
from werkzeug.security import generate_password_hash

def check_and_create_admin():
    """관리자 계정을 확인하고, 없으면 생성"""
    try:
        # 관리자 계정 확인
        admin = db_session.query(User).filter(User.username == 'admin').first()
        
        if admin:
            print(f"관리자 계정이 존재합니다:")
            print(f"사용자명: {admin.username}")
            print(f"이름: {admin.name}")
            print(f"역할: {admin.role}")
        else:
            print("관리자 계정이 존재하지 않습니다. 새로 생성합니다.")
            # 기본 관리자 계정 생성
            admin_user = User(
                username='admin',
                password=generate_password_hash('Admin123'),
                name='관리자',
                role='ADMIN'
            )
            db_session.add(admin_user)
            db_session.commit()
            print("관리자 계정이 생성되었습니다. (ID: admin, PW: Admin123)")
            
    except Exception as e:
        db_session.rollback()
        print(f"관리자 계정 확인/생성 중 오류 발생: {str(e)}")
        
        # 테이블이 없는 경우 데이터베이스 초기화 시도
        try:
            print("테이블이 없을 수 있습니다. 데이터베이스 초기화를 시도합니다.")
            init_db()
            
            # 다시 관리자 계정 생성 시도
            admin_user = User(
                username='admin',
                password=generate_password_hash('Admin123'),
                name='관리자',
                role='ADMIN'
            )
            db_session.add(admin_user)
            db_session.commit()
            print("데이터베이스를 초기화하고 관리자 계정을 생성했습니다.")
        except Exception as e2:
            db_session.rollback()
            print(f"데이터베이스 초기화 후 관리자 생성 중 오류 발생: {str(e2)}")

if __name__ == "__main__":
    check_and_create_admin() 