import sqlite3

def upgrade_database():
    """데이터베이스 스키마를 업그레이드합니다."""
    print("데이터베이스 업그레이드를 시작합니다...")
    
    # SQLite 데이터베이스에 연결
    conn = sqlite3.connect('furniture_orders.db')
    cursor = conn.cursor()
    
    try:
        # access_logs 테이블에 additional_data 컬럼 추가
        cursor.execute("PRAGMA table_info(access_logs)")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]
        
        if 'additional_data' not in column_names:
            print("access_logs 테이블에 additional_data 컬럼을 추가합니다...")
            cursor.execute("ALTER TABLE access_logs ADD COLUMN additional_data TEXT")
            conn.commit()
            print("additional_data 컬럼이 추가되었습니다.")
        else:
            print("additional_data 컬럼이 이미 존재합니다.")
        
        print("데이터베이스 업그레이드가 완료되었습니다.")
    except Exception as e:
        conn.rollback()
        print(f"오류가 발생했습니다: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    upgrade_database() 