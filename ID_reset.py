from sqlalchemy import text
from flask import Flask
import db
from app import app

# 애플리케이션 컨텍스트 생성
with app.app_context():
    db_session = db.get_db()
    
    print("⚠️ 경고: 이 스크립트는 orders 테이블의 모든 데이터를 삭제합니다! ⚠️")
    confirm = input("계속하려면 'YES'를 입력하세요: ")
    
    if confirm.upper() != 'YES':
        print("작업이 취소되었습니다.")
        exit()
    
    try:
        print("orders 테이블 데이터 삭제 및 시퀀스 초기화 시작...")
        
        # TRUNCATE로 테이블 데이터 삭제 및 시퀀스 리셋 (CASCADE 옵션 추가)
        truncate_query = "TRUNCATE TABLE orders RESTART IDENTITY CASCADE"
        db_session.execute(text(truncate_query))
        db_session.commit()
        
        # 시퀀스가 리셋되었는지 확인
        seq_query = "SELECT pg_get_serial_sequence('orders', 'id')"
        seq_name = db_session.execute(text(seq_query)).scalar()
        
        if seq_name:
            # 시퀀스 확인 (nextval 사용하지 않고)
            curr_val_query = f"SELECT last_value FROM {seq_name}"
            curr_val = db_session.execute(text(curr_val_query)).scalar()
            print(f"orders 테이블 시퀀스 현재 값: {curr_val}")
        
        print("✅ orders 테이블 데이터 삭제 및 시퀀스 초기화 완료!")
        print("⚠️ 주의: 이제 orders 테이블에는 데이터가 없으며, 다음 ID는 1부터 시작합니다.")
        
    except Exception as e:
        db_session.rollback()
        print(f"오류 발생: {str(e)}")
        print("작업이 취소되었습니다.") 