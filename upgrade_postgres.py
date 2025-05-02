import psycopg2
import os
import traceback

# 환경 변수에서 데이터베이스 연결 정보 가져오기 또는 기본값 사용
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "furniture_orders")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "postgres")
DB_PORT = os.environ.get("DB_PORT", "5432")

def upgrade_postgres_database():
    """PostgreSQL 데이터베이스 스키마를 업그레이드합니다."""
    print("PostgreSQL 데이터베이스 업그레이드를 시작합니다...")
    
    try:
        # PostgreSQL 데이터베이스에 연결
        print(f"데이터베이스에 연결 중: {DB_HOST}:{DB_PORT}/{DB_NAME} (사용자: {DB_USER})")
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT
        )
        conn.autocommit = False
        cursor = conn.cursor()
        
        print("데이터베이스 연결 성공!")
        
        try:
            # 테이블이 존재하는지 확인
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'access_logs'
                )
            """)
            table_exists = cursor.fetchone()[0]
            
            if not table_exists:
                print("access_logs 테이블이 존재하지 않습니다.")
                print("데이터베이스 스키마를 생성합니다...")
                
                # 먼저 users 테이블 생성
                cursor.execute('''
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
                
                # access_logs 테이블 생성 (additional_data 포함)
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_logs (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    action VARCHAR NOT NULL,
                    ip_address VARCHAR,
                    user_agent VARCHAR,
                    additional_data TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # orders 테이블 생성
                cursor.execute('''
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
                
                conn.commit()
                print("데이터베이스 스키마가 생성되었습니다.")
            else:
                # 컬럼이 존재하는지 확인
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.columns 
                        WHERE table_name = 'access_logs' AND column_name = 'additional_data'
                    )
                """)
                column_exists = cursor.fetchone()[0]
                
                if not column_exists:
                    print("access_logs 테이블에 additional_data 컬럼을 추가합니다...")
                    cursor.execute("ALTER TABLE access_logs ADD COLUMN additional_data TEXT")
                    conn.commit()
                    print("additional_data 컬럼이 추가되었습니다.")
                else:
                    print("additional_data 컬럼이 이미 존재합니다.")
            
            print("데이터베이스 업그레이드가 완료되었습니다.")
            
        except Exception as e:
            conn.rollback()
            print(f"SQL 실행 중 오류가 발생했습니다: {str(e)}")
            traceback.print_exc()
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        print(f"데이터베이스 연결 오류: {str(e)}")
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    try:
        upgrade_postgres_database()
    except Exception as e:
        print(f"스크립트 실행 중 예외 발생: {str(e)}")
        traceback.print_exc() 