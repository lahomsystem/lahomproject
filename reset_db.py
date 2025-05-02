import os
import psycopg2

# 환경 변수에서 PostgreSQL 연결 정보 가져오기
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "postgres")
DB_NAME = os.environ.get("DB_NAME", "furniture_orders")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")

# PostgreSQL 데이터베이스 연결
conn = psycopg2.connect(
    host=DB_HOST,
    port=DB_PORT,
    user=DB_USER,
    password=DB_PASS,
    database=DB_NAME
)
cursor = conn.cursor()

try:
    # 테이블 삭제
    cursor.execute("DROP TABLE IF EXISTS access_logs CASCADE")
    cursor.execute("DROP TABLE IF EXISTS users CASCADE")
    cursor.execute("DROP TABLE IF EXISTS orders CASCADE")
    
    conn.commit()
    print("데이터베이스 테이블이 성공적으로 삭제되었습니다.")
except Exception as e:
    conn.rollback()
    print(f"테이블 삭제 중 오류 발생: {str(e)}")
finally:
    cursor.close()
    conn.close() 