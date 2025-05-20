import os
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from flask import g

# 환경 변수에서 데이터베이스 연결 정보 가져오기
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "postgres")  # 암호 기본값 수정
DB_NAME = os.environ.get("DB_NAME", "furniture_orders")
DB_HOST = os.environ.get("DB_HOST", "localhost")
CLOUD_SQL_CONNECTION_NAME = os.environ.get("CLOUD_SQL_CONNECTION_NAME", "")

# 개발 환경과 프로덕션 환경에 따라 DB 연결 문자열 설정
if os.environ.get("GAE_ENV") == "standard":
    # App Engine에서 실행 중인 경우
    db_socket_dir = os.environ.get("DB_SOCKET_DIR", "/cloudsql")
    instance_connection_name = CLOUD_SQL_CONNECTION_NAME
    db_url = f"postgresql://{DB_USER}:{DB_PASS}@/{DB_NAME}?host={db_socket_dir}/{instance_connection_name}"
else:
    # 로컬 개발 환경에서 실행 중인 경우
    db_url = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"

# SQLAlchemy 엔진 생성 (client_encoding 추가)
engine = create_engine(
    db_url, 
    pool_size=5, 
    max_overflow=2, 
    pool_timeout=30, 
    pool_recycle=1800, 
    connect_args={"client_encoding": "utf8"}
)
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    """데이터베이스 초기화 및 테이블 생성"""
    try:
        from models import Order, User, AccessLog  # 모델 임포트
        Base.metadata.create_all(bind=engine)
        print("데이터베이스 테이블 초기화 완료")
    except Exception as e:
        print(f"데이터베이스 초기화 중 오류 발생: {str(e)}")
        
def get_db():
    """Flask 앱 컨텍스트에서 데이터베이스 세션 가져오기"""
    if 'db' not in g:
        g.db = db_session
    return g.db

def close_db(e=None):
    """앱 컨텍스트가 종료될 때 데이터베이스 세션 닫기"""
    db = g.pop('db', None)
    if db is not None:
        db.close() 