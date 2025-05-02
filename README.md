# 가구 주문 관리 시스템

이 애플리케이션은 가구 주문을 관리하기 위한 웹 기반 시스템입니다.

## 기능

- 주문 접수 및 관리
- 주문 상태 추적
- 사용자 관리
- 보안 로깅
- Excel 파일 가져오기/내보내기
- 달력 뷰

## 기술 스택

- **백엔드**: Flask (Python)
- **데이터베이스**: PostgreSQL
- **배포 환경**: Google App Engine

## 설치 및 실행 방법

### 로컬 개발 환경 설정

1. 필요한 패키지 설치:
```
pip install -r requirements.txt
```

2. PostgreSQL 데이터베이스 준비:
   - PostgreSQL 설치 확인
   - 새 데이터베이스 생성: `furniture_orders`
   ```sql
   CREATE DATABASE furniture_orders;
   ```

3. 환경 변수 설정:
```
set DB_USER=postgres
set DB_PASS=your-password
set DB_NAME=furniture_orders
set DB_HOST=localhost
```

4. 데이터 마이그레이션 (기존 SQLite에서 PostgreSQL로):
```
python migration.py
```

5. 애플리케이션 실행:
```
python app.py
```

## Google App Engine 배포 방법

1. Google Cloud 계정 및 프로젝트 준비:
   - [Google Cloud Console](https://console.cloud.google.com/)에서 새 프로젝트 생성
   - Cloud SQL API 활성화
   - App Engine 활성화

2. Cloud SQL PostgreSQL 인스턴스 생성:
   ```
   gcloud sql instances create [YOUR-INSTANCE-NAME] \
       --database-version=POSTGRES_13 \
       --tier=db-f1-micro \
       --region=us-central1
   ```

3. 데이터베이스 설정:
   ```
   gcloud sql databases create furniture_orders --instance=[YOUR-INSTANCE-NAME]
   gcloud sql users set-password postgres --instance=[YOUR-INSTANCE-NAME] --password=[YOUR-PASSWORD]
   ```

4. app.yaml 파일 수정:
   - `[YOUR-PROJECT-ID]`와 `[YOUR-INSTANCE-NAME]`을 실제 값으로 변경
   - 적절한 데이터베이스 비밀번호 설정

5. 환경 변수 설정 방법 (두 가지 옵션):

   **옵션 1: app.yaml에 직접 설정 (현재 설정 방식)**
   ```yaml
   env_variables:
     DB_USER: "postgres"
     DB_PASS: "your-password"
     DB_NAME: "furniture_orders"
     DB_HOST: "/cloudsql/[YOUR-PROJECT-ID]:us-central1:[YOUR-INSTANCE-NAME]"
     CLOUD_SQL_CONNECTION_NAME: "[YOUR-PROJECT-ID]:us-central1:[YOUR-INSTANCE-NAME]"
   ```

   **옵션 2: 별도의 .env.yaml 파일 사용**
   ```yaml
   # .env.yaml 파일 생성
   DB_USER: "postgres"
   DB_PASS: "your-password"
   DB_NAME: "furniture_orders"
   DB_HOST: "/cloudsql/[YOUR-PROJECT-ID]:us-central1:[YOUR-INSTANCE-NAME]"
   CLOUD_SQL_CONNECTION_NAME: "[YOUR-PROJECT-ID]:us-central1:[YOUR-INSTANCE-NAME]"
   ```
   그리고 배포 시 다음 명령 사용:
   ```
   gcloud app deploy --env-vars-file .env.yaml
   ```
   
   > 주의: 중요한 비밀번호와 같은 정보는 .gitignore에 .env.yaml 파일을 추가하여 버전 관리에서 제외하세요.

6. 앱 배포:
   ```
   gcloud app deploy
   ```

## 배포 후 데이터 마이그레이션

1. Cloud Shell에서 마이그레이션 스크립트 실행:
   ```
   gcloud app instances ssh --service=default --version=[YOUR-VERSION] -- 'cd /app && python migration.py'
   ```

## 환경 변수 설정

- `DB_USER`: PostgreSQL 사용자 이름 (기본값: postgres)
- `DB_PASS`: PostgreSQL 비밀번호
- `DB_NAME`: 데이터베이스 이름 (기본값: furniture_orders)
- `DB_HOST`: 데이터베이스 호스트 (로컬: localhost, GAE: /cloudsql/[CONNECTION-NAME])
- `CLOUD_SQL_CONNECTION_NAME`: Cloud SQL 연결 이름 (프로젝트ID:리전:인스턴스이름)

## 참고 사항

- Google App Engine 배포 시 app.yaml 파일의 환경 변수 값을 실제 프로젝트에 맞게 수정해야 합니다.
- 처음 실행 시 관리자 계정이 자동으로 생성됩니다. (ID: admin, 비밀번호: admin123)
- 보안을 위해 배포 후 관리자 계정 비밀번호를 변경하십시오. 