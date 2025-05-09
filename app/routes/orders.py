import os
import datetime
import json
import pandas as pd
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, send_file, current_app
from werkzeug.utils import secure_filename
import threading

from app.services.order_service import OrderService
from app.services.user_service import UserService
from app.routes.auth import login_required, role_required

# Blueprint 생성
orders_bp = Blueprint('orders', __name__)

# 상수 정의
# Order status constants
STATUS = {
    'RECEIVED': '접수',
    'MEASURED': '실측',
    'SCHEDULED': '설치 예정',
    'COMPLETED': '완료',
    'AS_RECEIVED': 'AS 접수',
    'AS_COMPLETED': 'AS 완료',
    'DELETED': '삭제됨'
}

# 일괄 작업용 상태 상수
BULK_ACTION_STATUS = {
    'RECEIVED': '접수',
    'MEASURED': '실측',
    'SCHEDULED': '설치 예정',
    'COMPLETED': '완료',
    'AS_RECEIVED': 'AS 접수',
    'AS_COMPLETED': 'AS 완료',
}

# 유틸리티 함수
def allowed_file(filename):
    """파일이 허용된 확장자인지 확인"""
    from app.config.config import get_config
    ALLOWED_EXTENSIONS = get_config().ALLOWED_EXTENSIONS
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def parse_json_string(json_string):
    """JSON 문자열을 파싱하는 유틸리티 함수"""
    if not json_string:
        return None
    try:
        return json.loads(json_string)
    except:
        return json_string

# 공통 콘텍스트 프로세서
@orders_bp.context_processor
def inject_status_list():
    """템플릿에서 상태 목록 사용 가능하도록 설정"""
    return dict(
        STATUS=STATUS, 
        BULK_ACTION_STATUS=BULK_ACTION_STATUS,
        ALL_STATUS={k: v for k, v in STATUS.items() if k != 'DELETED'}
    )

@orders_bp.context_processor
def utility_processor():
    """유틸리티 함수를 템플릿에서 사용 가능하도록 설정"""
    return dict(parse_json_string=parse_json_string)

def load_menu_config():
    """메뉴 설정 로드"""
    try:
        if os.path.exists('menu_config.json'):
            with open('menu_config.json', 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        current_app.logger.warning(f"Menu config load error: {str(e)}")
    
    # 기본 메뉴 구성
    return {
        'main_menu': [
            {'id': 'calendar', 'name': '캘린더', 'url': '/calendar'},
            {'id': 'order_list', 'name': '전체 주문', 'url': '/'},
            {'id': 'measured', 'name': '실측', 'url': '/?status=MEASURED'},
            {'id': 'scheduled', 'name': '설치 예정', 'url': '/?status=SCHEDULED'},
            {'id': 'completed', 'name': '완료', 'url': '/?status=COMPLETED'},
            {'id': 'as_received', 'name': 'AS 접수', 'url': '/?status=AS_RECEIVED'},
            {'id': 'as_completed', 'name': 'AS 완료', 'url': '/?status=AS_COMPLETED'},
            {'id': 'trash', 'name': '휴지통', 'url': '/trash'}
        ]
    }

@orders_bp.context_processor
def inject_menu():
    """메뉴 설정을 템플릿에서 사용 가능하도록 설정"""
    menu_config = load_menu_config()
    return dict(menu=menu_config)

def parse_action_log(action, additional_data=None):
    """액션 로그 파싱"""
    # 이 함수의 구현은 길기 때문에 기존 코드를 그대로 유지합니다
    # (parse_action_log 함수 구현 유지)
    pass

# 주문 관련 라우트
@orders_bp.route('/')
@login_required
def index():
    """메인 페이지 - 주문 목록 표시"""
    # URL 파라미터에서 status와 search 가져오기
    status_filter = request.args.get('status', None)
    search_term = request.args.get('search', '')
    
    # 서비스를 통해 주문 목록 조회
    orders = OrderService.get_orders(status_filter, search_term)
    
    return render_template('index.html', orders=orders, 
                           status_filter=status_filter, search_term=search_term)

@orders_bp.route('/add', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN', 'MANAGER', 'STAFF'])
def add_order():
    """주문 추가"""
    if request.method == 'POST':
        try:
            # 필수 필드 검증
            required_fields = ['customer_name', 'phone', 'address', 'product']
            for field in required_fields:
                if not request.form.get(field):
                    flash(f'{field} 필드는 필수입니다.', 'error')
                    return redirect(url_for('orders.add_order'))
            
            # 서비스를 통해 주문 생성
            order_data = {
                'received_date': request.form.get('received_date'),
                'received_time': request.form.get('received_time'),
                'customer_name': request.form.get('customer_name'),
                'phone': request.form.get('phone'),
                'address': request.form.get('address'),
                'product': request.form.get('product'),
                'notes': request.form.get('notes'),
                'status': request.form.get('status', 'RECEIVED'),
                'measurement_date': request.form.get('measurement_date'),
                'measurement_time': request.form.get('measurement_time'),
                'completion_date': request.form.get('completion_date'),
                'manager_name': request.form.get('manager_name'),
                'option_type': request.form.get('option_type'),
                'options_online': request.form.get('options_online'),
                'direct_product_name': request.form.get('direct_product_name'),
                'direct_standard': request.form.get('direct_standard'),
                'direct_internal': request.form.get('direct_internal'),
                'direct_color': request.form.get('direct_color'),
                'direct_option_detail': request.form.get('direct_option_detail'),
                'direct_handle': request.form.get('direct_handle'),
                'direct_misc': request.form.get('direct_misc'),
                'direct_quote': request.form.get('direct_quote')
            }
            
            new_order = OrderService.create_order(order_data)
            
            # 작업 로그 기록
            UserService.log_access(f"주문 추가: {new_order.customer_name}", 
                                  session.get('user_id'), request=request)
            
            flash('주문이 성공적으로 추가되었습니다.', 'success')
            return redirect(url_for('orders.index'))
            
        except Exception as e:
            flash(f'오류가 발생했습니다: {str(e)}', 'error')
            return redirect(url_for('orders.add_order'))
    
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.datetime.now().strftime('%H:%M')
    
    return render_template('add_order.html', today=today, current_time=current_time)

@orders_bp.route('/edit/<int:order_id>', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN', 'MANAGER', 'STAFF'])
def edit_order(order_id):
    """주문 수정"""
    order = OrderService.get_order_by_id(order_id)
    
    if not order:
        flash('주문을 찾을 수 없거나 이미 삭제되었습니다.', 'error')
        return redirect(url_for('orders.index'))
    
    # 옵션 데이터 처리를 위한 변수 초기화
    option_type = 'online'  # 기본 옵션 타입
    online_options = ""     # 온라인 옵션 텍스트
    direct_options = {      # 직접 입력 옵션 필드
        'product_name': '', 
        'standard': '', 
        'internal': '',
        'color': '',
        'option_detail': '',
        'handle': '',
        'misc': '',
        'quote': ''
    }
    
    # 주문 옵션 데이터 처리
    if order.options:
        try:
            # 옵션 데이터 파싱 시도
            options_data = json.loads(order.options)
            
            # 옵션 데이터가 객체고 option_type 필드가 있는 경우
            if isinstance(options_data, dict):
                # 1. option_type 필드가 있는 경우 
                if 'option_type' in options_data:
                    option_type = options_data['option_type']
                    
                    if option_type == 'direct' and 'details' in options_data:
                        # 새로운 형식: "details" 객체에서 직접 값 추출
                        details = options_data['details']
                        for key in direct_options.keys():
                            if key in details:
                                direct_options[key] = details[key]
                    elif option_type == 'online' and 'online_options_summary' in options_data:
                        online_options = options_data['online_options_summary']
                
                # 2. 구형식 - option_type 없이 직접 키가 있는 경우
                elif any(key in options_data for key in direct_options.keys()):
                    option_type = 'direct'
                    for key in direct_options.keys():
                        if key in options_data:
                            direct_options[key] = options_data[key]
                
                # 3. 한글 키 대응
                elif any(key in options_data for key in ['제품명', '규격', '내부', '색상', '상세옵션', '손잡이', '기타', '견적내용']):
                    option_type = 'direct'
                    key_mapping = {
                        '제품명': 'product_name',
                        '규격': 'standard', 
                        '내부': 'internal',
                        '색상': 'color',
                        '상세옵션': 'option_detail',
                        '손잡이': 'handle',
                        '기타': 'misc',
                        '견적내용': 'quote'
                    }
                    for k_kor, k_eng in key_mapping.items():
                        if k_kor in options_data:
                            direct_options[k_eng] = options_data[k_kor]
                
                # 4. 이외의 경우 online으로 처리하고 문자열로 표시
                else:
                    option_type = 'online'
                    online_options = order.options  # 원래 문자열 그대로 표시
            
            # 객체가 아닌 경우 온라인 옵션으로 처리
            else:
                option_type = 'online'
                online_options = order.options
                
        except json.JSONDecodeError:
            # JSON 파싱 실패 시 온라인 옵션으로 처리
            option_type = 'online'
            online_options = order.options if order.options else ""
    
    if request.method == 'POST':
        try:
            order_data = {
                'received_date': request.form.get('received_date'),
                'received_time': request.form.get('received_time'),
                'customer_name': request.form.get('customer_name'),
                'phone': request.form.get('phone'),
                'address': request.form.get('address'),
                'product': request.form.get('product'),
                'notes': request.form.get('notes'),
                'status': request.form.get('status'),
                'measurement_date': request.form.get('measurement_date'),
                'measurement_time': request.form.get('measurement_time'),
                'completion_date': request.form.get('completion_date'),
                'manager_name': request.form.get('manager_name'),
                'option_type': request.form.get('option_type'),
                'options_online': request.form.get('options_online', ''),
                'direct_product_name': request.form.get('direct_product_name', ''),
                'direct_standard': request.form.get('direct_standard', ''),
                'direct_internal': request.form.get('direct_internal', ''),
                'direct_color': request.form.get('direct_color', ''),
                'direct_option_detail': request.form.get('direct_option_detail', ''),
                'direct_handle': request.form.get('direct_handle', ''),
                'direct_misc': request.form.get('direct_misc', ''),
                'direct_quote': request.form.get('direct_quote', '')
            }
            
            updated_order, changes = OrderService.update_order(order_id, order_data)
            
            additional_data = {"order_id": order_id, "customer_name": updated_order.customer_name, "changes": changes}
            log_action = f"Updated order #{order_id}"
            UserService.log_access(log_action, session.get('user_id'), additional_data, request=request)
            
            flash('주문이 성공적으로 수정되었습니다.', 'success')
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'success'})
            
            return redirect(url_for('orders.index'))
            
        except Exception as e:
            flash(f'주문 수정 중 오류가 발생했습니다: {str(e)}', 'error')
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': str(e)})
            
            # 오류 발생 시 현재 데이터로 페이지 다시 로드
            return render_template(
                'edit_order.html', 
                order=order,
                option_type=option_type,
                online_options=online_options,
                direct_options=direct_options
            )
    
    # GET 요청에 대한 최종 반환 - 미리 처리된 옵션 데이터를 직접 템플릿에 전달
    return render_template(
        'edit_order.html', 
        order=order,
        option_type=option_type,
        online_options=online_options,
        direct_options=direct_options
    )

@orders_bp.route('/delete/<int:order_id>')
@login_required
@role_required(['ADMIN', 'MANAGER'])
def delete_order(order_id):
    """주문 삭제 (휴지통으로 이동)"""
    try:
        result = OrderService.delete_order(order_id)
        
        if not result:
            flash('주문을 찾을 수 없거나 이미 삭제되었습니다.', 'error')
            return redirect(url_for('orders.index'))
        
        UserService.log_access(f"Deleted order #{order_id}", session.get('user_id'), request=request)
        
        flash('주문이 휴지통으로 이동되었습니다.', 'success')
    except Exception as e:
        flash(f'주문 삭제 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('orders.index'))

@orders_bp.route('/trash')
@login_required
@role_required(['ADMIN', 'MANAGER'])
def trash():
    """휴지통 보기"""
    search_term = request.args.get('search', '')
    
    orders = OrderService.get_deleted_orders(search_term)
    
    return render_template('trash.html', orders=orders, search_term=search_term)

@orders_bp.route('/restore_orders', methods=['POST'])
@login_required
@role_required(['ADMIN', 'MANAGER'])
def restore_orders():
    """주문 복원"""
    selected_ids = request.form.getlist('selected_order')
    
    if not selected_ids:
        flash('복원할 주문을 선택해주세요.', 'warning')
        return redirect(url_for('orders.trash'))
    
    try:
        restored_count = OrderService.restore_orders(selected_ids)
        
        UserService.log_access(f"Restored {restored_count} orders", session.get('user_id'), request=request)
        
        flash(f'{restored_count}개의 주문이 성공적으로 복원되었습니다.', 'success')
    except Exception as e:
        flash(f'주문 복원 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('orders.trash'))

@orders_bp.route('/permanent_delete_orders', methods=['POST'])
@login_required
@role_required(['ADMIN'])
def permanent_delete_orders():
    """주문 영구 삭제"""
    selected_ids = request.form.getlist('selected_order')
    
    if not selected_ids:
        flash('영구 삭제할 주문을 선택해주세요.', 'warning')
        return redirect(url_for('orders.trash'))
    
    try:
        deleted_count = OrderService.permanent_delete_orders(selected_ids)
        
        UserService.log_access(f"Permanently deleted {deleted_count} orders", session.get('user_id'), request=request)
        
        flash(f'{deleted_count}개의 주문이 영구적으로 삭제되었습니다.', 'success')
    except Exception as e:
        flash(f'주문 영구 삭제 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('orders.trash'))

@orders_bp.route('/bulk_action', methods=['POST'])
@login_required
@role_required(['ADMIN', 'MANAGER'])
def bulk_action():
    """일괄 작업 수행"""
    action = request.form.get('action')
    selected_ids = request.form.getlist('selected_order')
    
    if not selected_ids:
        flash('선택된 주문이 없습니다.', 'error')
        return redirect(url_for('orders.index'))
    
    if not action:
        flash('실행할 작업을 선택해주세요.', 'error')
        return redirect(url_for('orders.index'))
    
    action_description = ""
    action_details = {}
    try:
        if action == 'delete':
            action_description = "휴지통으로 이동"
            OrderService.perform_bulk_action(action, selected_ids)
            flash(f'{len(selected_ids)}개의 주문을 휴지통으로 이동했습니다.', 'success')
            
        elif action == 'change_status':
            new_status = request.form.get('new_status')
            if not new_status:
                flash('변경할 상태를 선택해주세요.', 'error')
                return redirect(url_for('orders.index'))
                
            action_description = f"상태를 {STATUS.get(new_status, new_status)}로 변경"
            action_details = {'new_status': new_status}
            OrderService.perform_bulk_action(action, selected_ids, action_details)
            flash(f'{len(selected_ids)}개 주문의 상태를 {STATUS.get(new_status, new_status)}(으)로 변경했습니다.', 'success')
            
        elif action == 'change_measurement_date':
            new_measurement_date_str = request.form.get('new_measurement_date')
            if not new_measurement_date_str:
                flash('변경할 실측일을 선택해주세요.', 'error')
                return redirect(url_for('orders.index'))
                
            try:
                # 날짜 형식 검증
                datetime.datetime.strptime(new_measurement_date_str, '%Y-%m-%d')
                action_description = f"실측일을 {new_measurement_date_str}로 변경"
                action_details = {'new_measurement_date': new_measurement_date_str}
                OrderService.perform_bulk_action(action, selected_ids, action_details)
                flash(f'{len(selected_ids)}개 주문의 실측일을 {new_measurement_date_str}(으)로 변경했습니다.', 'success')
            except ValueError:
                flash('실측일 형식이 잘못되었습니다. YYYY-MM-DD 형식으로 입력해주세요.', 'error')
                return redirect(url_for('orders.index'))
                
        elif action == 'change_completion_date':
            new_completion_date_str = request.form.get('new_completion_date')
            if not new_completion_date_str:
                flash('변경할 설치일을 선택해주세요.', 'error')
                return redirect(url_for('orders.index'))
                
            try:
                # 날짜 형식 검증
                datetime.datetime.strptime(new_completion_date_str, '%Y-%m-%d')
                action_description = f"설치일을 {new_completion_date_str}로 변경"
                action_details = {'new_completion_date': new_completion_date_str}
                OrderService.perform_bulk_action(action, selected_ids, action_details)
                flash(f'{len(selected_ids)}개 주문의 설치일을 {new_completion_date_str}(으)로 변경했습니다.', 'success')
            except ValueError:
                flash('설치일 형식이 잘못되었습니다. YYYY-MM-DD 형식으로 입력해주세요.', 'error')
                return redirect(url_for('orders.index'))
                
        elif action == 'change_manager':
            new_manager_name = request.form.get('new_manager_name')
            if not new_manager_name or not new_manager_name.strip():
                flash('변경할 담당자 이름을 입력해주세요.', 'error')
                return redirect(url_for('orders.index'))
                
            action_description = f"담당자를 {new_manager_name}(으)로 변경"
            action_details = {'new_manager_name': new_manager_name}
            OrderService.perform_bulk_action(action, selected_ids, action_details)
            flash(f'{len(selected_ids)}개 주문의 담당자를 {new_manager_name.strip()}(으)로 변경했습니다.', 'success')
            
        else:
            flash('알 수 없는 작업입니다.', 'error')
            return redirect(url_for('orders.index'))
        
        # 작업 로그 기록
        UserService.log_access(f"일괄 작업: 주문 {', '.join(selected_ids)}에 대해 '{action_description}' 실행", 
                             session.get('user_id'), request=request)
            
    except Exception as e:
        flash(f'일괄 작업 중 오류 발생: {str(e)}', 'error')
        current_app.logger.error(f"Error during bulk action {action}: {e}")
    
    return redirect(url_for('orders.index', 
                           status=request.args.get('status'), 
                           search=request.args.get('search')))

@orders_bp.route('/upload', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN', 'MANAGER'])
def upload_excel():
    """엑셀 파일 업로드"""
    if request.method == 'POST':
        # 파일 확인
        if 'excel_file' not in request.files:
            flash('파일이 선택되지 않았습니다.', 'error')
            return redirect(request.url)
        
        file = request.files['excel_file']
        
        if file.filename == '':
            flash('파일이 선택되지 않았습니다.', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # 파일 저장
            filename = secure_filename(file.filename)
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            
            try:
                # pandas로 엑셀 처리
                df = pd.read_excel(file_path)
                
                # 필수 컬럼 확인
                required_columns = ['접수일', '고객명', '전화번호', '주소', '제품']
                missing_columns = [col for col in required_columns if col not in df.columns]
                
                if missing_columns:
                    flash(f'엑셀 파일에 필수 컬럼이 누락되었습니다: {", ".join(missing_columns)}', 'error')
                    return redirect(request.url)
                
                from db import get_db
                from models import Order
                
                # DB 처리
                db = get_db()
                order_count = 0
                
                for index, row in df.iterrows():
                    # 필드 변환 및 기본값 설정
                    received_date = row['접수일'].strftime('%Y-%m-%d') if pd.notna(row['접수일']) else datetime.datetime.now().strftime('%Y-%m-%d')
                    
                    # 각 필드 처리
                    received_time = None
                    if '접수시간' in df.columns and pd.notna(row['접수시간']):
                        if isinstance(row['접수시간'], datetime.time):
                            received_time = row['접수시간'].strftime('%H:%M')
                        elif isinstance(row['접수시간'], str):
                            received_time = row['접수시간']
                    
                    options = row['옵션'] if '옵션' in df.columns and pd.notna(row['옵션']) else None
                    notes = row['비고'] if '비고' in df.columns and pd.notna(row['비고']) else None
                    
                    measurement_date = row['실측일'].strftime('%Y-%m-%d') if '실측일' in df.columns and pd.notna(row['실측일']) else None
                    measurement_time = row['실측시간'].strftime('%H:%M') if '실측시간' in df.columns and pd.notna(row['실측시간']) else None
                    completion_date = row['설치완료일'].strftime('%Y-%m-%d') if '설치완료일' in df.columns and pd.notna(row['설치완료일']) else None
                    manager_name = row['담당자'] if '담당자' in df.columns and pd.notna(row['담당자']) else None
                    
                    # 주문 생성
                    new_order = Order(
                        customer_name=row['고객명'] if pd.notna(row['고객명']) else '',
                        phone=row['전화번호'] if pd.notna(row['전화번호']) else '',
                        address=row['주소'] if pd.notna(row['주소']) else '',
                        product=row['제품'] if pd.notna(row['제품']) else '',
                        options=options,
                        notes=notes,
                        received_date=received_date,
                        received_time=received_time,
                        status='RECEIVED',
                        measurement_date=measurement_date,
                        measurement_time=measurement_time,
                        completion_date=completion_date,
                        manager_name=manager_name
                    )
                    
                    db.add(new_order)
                    order_count += 1
                
                db.commit()
                UserService.log_access(f"Uploaded Excel file with {order_count} orders", session.get('user_id'), request=request)
                flash(f'{order_count}개의 주문이 성공적으로 등록되었습니다.', 'success')
                
            except Exception as e:
                if db:  # 데이터베이스 연결이 열려있는지 확인
                    db.rollback()
                flash(f'엑셀 파일 처리 중 오류가 발생했습니다: {str(e)}', 'error')
            
            # 처리 후 파일 삭제
            try:
                os.remove(file_path)
            except:
                pass
            
            return redirect(url_for('orders.index'))
        else:
            flash('허용되지 않은 파일 형식입니다. .xlsx 또는 .xls 파일만 업로드 가능합니다.', 'error')
            return redirect(request.url)
    
    return render_template('upload.html')

@orders_bp.route('/download_excel')
@login_required
def download_excel():
    """엑셀 파일 다운로드"""
    status_filter = request.args.get('status', None)
    search_term = request.args.get('search', '')
    
    # 주문 데이터 조회
    orders = OrderService.get_orders(status_filter, search_term)
    
    # 데이터프레임 생성
    data = []
    for order in orders:
        status_display = STATUS.get(order.status, order.status)
        data.append({
            '번호': order.id,
            '접수일': order.received_date,
            '접수시간': order.received_time or '',
            '고객명': order.customer_name,
            '전화번호': order.phone,
            '주소': order.address,
            '제품': order.product,
            '옵션': order.options or '',
            '비고': order.notes or '',
            '상태': status_display,
            '실측일': order.measurement_date or '',
            '실측시간': order.measurement_time or '',
            '설치완료일': order.completion_date or '',
            '담당자': order.manager_name or ''
        })
    
    df = pd.DataFrame(data)
    
    # 엑셀 파일 생성
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    excel_filename = f'furniture_orders_{timestamp}.xlsx'
    upload_folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    excel_path = os.path.join(upload_folder, excel_filename)
    
    # pandas 엑셀 작성
    writer = pd.ExcelWriter(excel_path, engine='openpyxl')
    df.to_excel(writer, sheet_name='주문목록', index=False)
    writer.close()
    
    # 작업 로그
    UserService.log_access(f"Downloaded Excel file", session.get('user_id'), request=request)
    
    # 파일 다운로드 응답 생성 및 정리 스케줄링
    response = send_file(excel_path, as_attachment=True, download_name=excel_filename, 
                        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    
    # 파일 정리를 위한 함수
    def delete_file_after_download():
        import time
        time.sleep(60)  # 60초 대기
        try:
            if os.path.exists(excel_path):
                os.remove(excel_path)
        except Exception as e:
            current_app.logger.error(f"Error removing temp file: {e}")
    
    # 백그라운드 스레드로 파일 정리 실행
    cleanup_thread = threading.Thread(target=delete_file_after_download)
    cleanup_thread.daemon = True
    cleanup_thread.start()
    
    return response

@orders_bp.route('/calendar')
@login_required
def calendar():
    """캘린더 뷰"""
    return render_template('calendar.html')

@orders_bp.route('/api/orders')
@login_required
def api_orders():
    """주문 API - 캘린더 데이터"""
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    status_filter = request.args.get('status', None)
    
    from db import get_db
    from models import Order
    
    db = get_db()
    
    # 기본 쿼리: 삭제되지 않은 주문
    query = db.query(Order).filter(Order.status != 'DELETED')
    
    # 상태 필터 적용
    if status_filter and status_filter in STATUS:
        query = query.filter(Order.status == status_filter)
    
    # 날짜 범위 필터 적용
    if start_date and end_date:
        # 날짜/시간 형식 처리
        if 'T' in start_date:  # ISO 형식 (YYYY-MM-DDTHH:MM:SS)
            start_date_only = start_date.split('T')[0]
            end_date_only = end_date.split('T')[0]
            query = query.filter(Order.received_date.between(start_date_only, end_date_only))
        else:  # 날짜만 있는 형식 (YYYY-MM-DD)
            query = query.filter(Order.received_date.between(start_date, end_date))
    
    orders = query.all()
    
    # 상태별 색상 매핑
    status_colors = {
        'RECEIVED': '#3788d8',   # 파란색
        'MEASURED': '#f39c12',   # 주황색
        'SCHEDULED': '#e74c3c',  # 빨간색
        'COMPLETED': '#2ecc71',  # 초록색
        'AS_RECEIVED': '#9b59b6', # 보라색
        'AS_COMPLETED': '#1abc9c'  # 청록색
    }
    
    # 이벤트 생성
    events = []
    for order in orders:
        start_date = order.received_date
        if order.received_time:
            start_datetime = f"{start_date}T{order.received_time}:00"
            all_day = False
        else:
            start_datetime = start_date
            all_day = True
        
        color = status_colors.get(order.status, '#3788d8')
        time_str = order.received_time if order.received_time else ''
        title = f"{order.customer_name} | {order.phone} | {order.product}"
        
        events.append({
            'id': order.id,
            'title': title,
            'start': start_datetime,
            'allDay': all_day,
            'backgroundColor': color,
            'borderColor': color,
            'extendedProps': {
                'customer_name': order.customer_name,
                'phone': order.phone,
                'address': order.address,
                'product': order.product,
                'options': order.options,
                'notes': order.notes,
                'status': order.status,
                'received_date': order.received_date,
                'received_time': order.received_time
            }
        })
    
    return jsonify(events) 