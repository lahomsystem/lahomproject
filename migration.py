import sqlite3
import psycopg2
import os
import datetime
from werkzeug.security import generate_password_hash

# 환경 변수에서 PostgreSQL 연결 정보 가져오기
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "postgres")  # 기본값 수정
DB_NAME = os.environ.get("DB_NAME", "furniture_orders")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")

# SQLite 데이터베이스 연결
sqlite_conn = sqlite3.connect('furniture_orders.db')
sqlite_conn.row_factory = sqlite3.Row
sqlite_cursor = sqlite_conn.cursor()

# PostgreSQL 데이터베이스 연결
pg_conn = psycopg2.connect(
    host=DB_HOST,
    port=DB_PORT,
    user=DB_USER,
    password=DB_PASS,
    database=DB_NAME
)
pg_cursor = pg_conn.cursor()

def create_postgres_tables():
    """PostgreSQL 데이터베이스에 필요한 테이블 생성"""
    
    # orders 테이블 생성
    pg_cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        received_date VARCHAR NOT NULL,
        received_time VARCHAR,
        customer_name VARCHAR NOT NULL,
        phone VARCHAR NOT NULL,
        address TEXT NOT NULL,
        product VARCHAR NOT NULL,
        options TEXT,
        notes TEXT,
        status VARCHAR DEFAULT 'RECEIVED',
        original_status VARCHAR,
        deleted_at VARCHAR,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # users 테이블 생성
    pg_cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR UNIQUE NOT NULL,
        password VARCHAR NOT NULL,
        name VARCHAR NOT NULL DEFAULT '사용자',
        role VARCHAR NOT NULL DEFAULT 'VIEWER',
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    ''')
    
    # access_logs 테이블 생성
    pg_cursor.execute('''
    CREATE TABLE IF NOT EXISTS access_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR NOT NULL,
        ip_address VARCHAR,
        user_agent VARCHAR,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    pg_conn.commit()
    print("PostgreSQL 테이블 생성 완료")

def migrate_orders():
    """orders 테이블 데이터 마이그레이션"""
    print("주문 데이터 마이그레이션 시작...")
    
    try:
        # 기존 테이블 초기화
        pg_cursor.execute("TRUNCATE TABLE orders RESTART IDENTITY CASCADE")
        pg_conn.commit()
        
        # SQLite에서 orders 데이터 가져오기
        sqlite_cursor.execute("SELECT * FROM orders")
        orders = sqlite_cursor.fetchall()
        
        # PostgreSQL에 데이터 삽입
        for order in orders:
            pg_cursor.execute('''
            INSERT INTO orders (id, received_date, received_time, customer_name, phone, address, 
                            product, options, notes, status, original_status, deleted_at, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                order['id'],
                order['received_date'],
                order['received_time'],
                order['customer_name'],
                order['phone'],
                order['address'],
                order['product'],
                order['options'],
                order['notes'],
                order['status'],
                order['original_status'],
                order['deleted_at'],
                order['created_at']
            ))
        
        # ID 시퀀스 업데이트
        pg_cursor.execute("SELECT setval('orders_id_seq', (SELECT MAX(id) FROM orders))")
        
        pg_conn.commit()
        print(f"주문 데이터 {len(orders)}개 마이그레이션 완료")
    except Exception as e:
        pg_conn.rollback()
        print(f"주문 데이터 마이그레이션 중 오류: {str(e)}")

def migrate_users():
    """users 테이블 데이터 마이그레이션"""
    print("사용자 데이터 마이그레이션 시작...")
    
    try:
        # 기존 테이블 초기화
        pg_cursor.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE")
        pg_conn.commit()
        
        # SQLite에서 users 데이터 가져오기
        sqlite_cursor.execute("SELECT * FROM users")
        users = sqlite_cursor.fetchall()
        
        # PostgreSQL에 데이터 삽입 (패스워드 재해싱)
        for user in users:
            # 기존 패스워드가 해시된 형태라면 일단 기본 패스워드로 설정
            # 실제 환경에서는 사용자에게 패스워드 재설정을 요청해야 합니다
            default_password = 'Admin123'  # 복잡한 패스워드로 설정
            hashed_password = generate_password_hash(default_password)
            
            pg_cursor.execute('''
            INSERT INTO users (id, username, password, name, role, is_active, created_at, last_login)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                user['id'],
                user['username'],
                hashed_password,  # 새로 해싱한 패스워드 사용
                user['name'],
                user['role'],
                bool(user['is_active']),
                user['created_at'],
                user['last_login']
            ))
        
        # ID 시퀀스 업데이트
        pg_cursor.execute("SELECT setval('users_id_seq', (SELECT MAX(id) FROM users))")
        
        pg_conn.commit()
        print(f"사용자 데이터 {len(users)}개 마이그레이션 완료 (모든 패스워드는 'Admin123'으로 재설정됨)")
    except Exception as e:
        pg_conn.rollback()
        print(f"사용자 데이터 마이그레이션 중 오류: {str(e)}")

def migrate_access_logs():
    """access_logs 테이블 데이터 마이그레이션"""
    print("접근 로그 데이터 마이그레이션 시작...")
    
    try:
        # 기존 테이블 초기화
        pg_cursor.execute("TRUNCATE TABLE access_logs RESTART IDENTITY CASCADE")
        pg_conn.commit()
        
        # SQLite에서 access_logs 데이터 가져오기
        sqlite_cursor.execute("SELECT * FROM access_logs")
        logs = sqlite_cursor.fetchall()
        
        # PostgreSQL에 데이터 삽입
        for log in logs:
            pg_cursor.execute('''
            INSERT INTO access_logs (id, user_id, action, ip_address, user_agent, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                log['id'],
                log['user_id'],
                log['action'],
                log['ip_address'],
                log['user_agent'],
                log['timestamp']
            ))
        
        # ID 시퀀스 업데이트
        pg_cursor.execute("SELECT setval('access_logs_id_seq', (SELECT MAX(id) FROM access_logs))")
        
        pg_conn.commit()
        print(f"접근 로그 데이터 {len(logs)}개 마이그레이션 완료")
    except Exception as e:
        pg_conn.rollback()
        print(f"접근 로그 데이터 마이그레이션 중 오류: {str(e)}")

def create_admin_if_needed():
    """사용자가 없는 경우 관리자 계정 생성"""
    pg_cursor.execute("SELECT COUNT(*) FROM users")
    count = pg_cursor.fetchone()[0]
    
    if count == 0:
        print("관리자 계정 생성...")
        
        # 관리자 계정 생성 (복잡한 비밀번호 사용)
        admin_password = generate_password_hash('Admin123')  # 대소문자와 숫자를 포함한 비밀번호
        pg_cursor.execute('''
        INSERT INTO users (username, password, name, role)
        VALUES (%s, %s, %s, %s)
        ''', ('admin', admin_password, '관리자', 'ADMIN'))
        
        pg_conn.commit()
        print("관리자 계정 생성 완료 (아이디: admin, 비밀번호: Admin123)")

def main():
    try:
        # 테이블 생성
        create_postgres_tables()
        
        # 데이터 마이그레이션
        migrate_orders()
        migrate_users()
        migrate_access_logs()
        
        # 필요한 경우 관리자 계정 생성
        create_admin_if_needed()
        
        print("마이그레이션이 성공적으로 완료되었습니다.")
        
    except Exception as e:
        print(f"마이그레이션 중 오류 발생: {str(e)}")
        pg_conn.rollback()
    finally:
        # 연결 종료
        sqlite_cursor.close()
        sqlite_conn.close()
        pg_cursor.close()
        pg_conn.close()

if __name__ == "__main__":
    main() 