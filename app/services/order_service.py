import json
import datetime
from flask import current_app
from sqlalchemy import or_
import re

from db import get_db
from models import Order

class OrderService:
    """주문 관련 비즈니스 로직을 위한 서비스 클래스"""
    
    @staticmethod
    def get_orders(status_filter=None, search_term=None):
        """주문 목록 조회"""
        db = get_db()
        
        # 기본 쿼리: 삭제되지 않은 주문
        query = db.query(Order).filter(Order.status != 'DELETED')
        
        # 상태 필터 적용
        if status_filter and hasattr(Order, 'status'):
            query = query.filter(Order.status == status_filter)
        
        # 검색어 필터 적용
        if search_term:
            search_pattern = f"%{search_term}%"
            
            # 날짜 검색 패턴 확인
            found_date_pattern = False
            date_search = None
            
            # 단일 날짜 또는 월-일 패턴 확인
            if re.match(r'^\d{1,2}$', search_term):  # 단일 날짜 (예: '15')
                day_pattern = f'%-{search_term.zfill(2)}'
                date_search = Order.received_date.like(day_pattern)
                found_date_pattern = True
            elif re.match(r'^\d{1,2}-\d{1,2}$', search_term):  # 월-일 패턴 (예: '04-15')
                month, day = search_term.split('-')
                month_day_pattern = f'%-{month.zfill(2)}-{day.zfill(2)}'
                date_search = Order.received_date.like(month_day_pattern)
                found_date_pattern = True
            
            # 검색 대상 필드
            search_fields = [
                Order.customer_name.like(search_pattern),
                Order.phone.like(search_pattern),
                Order.address.like(search_pattern),
                Order.product.like(search_pattern),
                Order.options.like(search_pattern),
                Order.notes.like(search_pattern),
                Order.manager_name.like(search_pattern),
                Order.received_date.like(search_pattern),
                Order.measurement_date.like(search_pattern),
                Order.completion_date.like(search_pattern)
            ]

            if found_date_pattern:
                query = query.filter(or_(date_search, *search_fields))
            else:
                query = query.filter(or_(*search_fields))
        
        # 정렬: 접수일, 접수시간 기준 내림차순
        return query.order_by(Order.received_date.desc(), Order.received_time.desc()).all()
    
    @staticmethod
    def get_order_by_id(order_id):
        """주문 조회"""
        db = get_db()
        return db.query(Order).filter(Order.id == order_id, Order.status != 'DELETED').first()
    
    @staticmethod
    def create_order(order_data):
        """주문 생성"""
        db = get_db()
        try:
            # 옵션 데이터 처리
            options_data = None
            option_type = order_data.get('option_type')
            
            if option_type == 'direct':
                direct_options = {
                    'product_name': order_data.get('direct_product_name'),
                    'standard': order_data.get('direct_standard'),
                    'internal': order_data.get('direct_internal'),
                    'color': order_data.get('direct_color'),
                    'option_detail': order_data.get('direct_option_detail'),
                    'handle': order_data.get('direct_handle'),
                    'misc': order_data.get('direct_misc'),
                    'quote': order_data.get('direct_quote')
                }
                options_data = json.dumps(direct_options, ensure_ascii=False)
            else:  # 'online'
                options_data = order_data.get('options_online')
            
            # 주문 객체 생성
            new_order = Order(
                received_date=order_data.get('received_date'),
                received_time=order_data.get('received_time'),
                customer_name=order_data.get('customer_name'),
                phone=order_data.get('phone'),
                address=order_data.get('address'),
                product=order_data.get('product'),
                options=options_data,
                notes=order_data.get('notes'),
                status=order_data.get('status', 'RECEIVED'),
                measurement_date=order_data.get('measurement_date'),
                measurement_time=order_data.get('measurement_time'),
                completion_date=order_data.get('completion_date'),
                manager_name=order_data.get('manager_name')
            )
            
            db.add(new_order)
            db.commit()
            return new_order
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error creating order: {str(e)}")
            raise
    
    @staticmethod
    def update_order(order_id, order_data):
        """주문 업데이트"""
        db = get_db()
        order = OrderService.get_order_by_id(order_id)
        
        if not order:
            return None
        
        try:
            changes = {}
            
            # 옵션 데이터 처리
            options_data_json_to_save = None
            option_type = order_data.get('option_type')
            
            if option_type == 'direct':
                # 직접입력 필드 값 수집
                direct_details = {
                    'product_name': order_data.get('direct_product_name', ''),
                    'standard': order_data.get('direct_standard', ''),
                    'internal': order_data.get('direct_internal', ''),
                    'color': order_data.get('direct_color', ''),
                    'option_detail': order_data.get('direct_option_detail', ''),
                    'handle': order_data.get('direct_handle', ''),
                    'misc': order_data.get('direct_misc', ''),
                    'quote': order_data.get('direct_quote', '')
                }
                
                options_to_save_dict = {
                    "option_type": "direct",
                    "details": direct_details
                }
                options_data_json_to_save = json.dumps(options_to_save_dict, ensure_ascii=False)
            else:  # 'online'
                online_summary = order_data.get('options_online', '')
                options_to_save_dict = {
                    "option_type": "online",
                    "online_options_summary": online_summary
                }
                options_data_json_to_save = json.dumps(options_to_save_dict, ensure_ascii=False)
            
            # 변경사항 감지 및 기록
            fields = [
                ('received_date', order_data.get('received_date')),
                ('received_time', order_data.get('received_time')),
                ('customer_name', order_data.get('customer_name')),
                ('phone', order_data.get('phone')),
                ('address', order_data.get('address')),
                ('product', order_data.get('product')),
                ('options', options_data_json_to_save),
                ('notes', order_data.get('notes')),
                ('status', order_data.get('status')),
                ('measurement_date', order_data.get('measurement_date')),
                ('measurement_time', order_data.get('measurement_time')),
                ('completion_date', order_data.get('completion_date')),
                ('manager_name', order_data.get('manager_name'))
            ]
            
            for field_name, new_value in fields:
                old_value = getattr(order, field_name)
                if old_value != new_value:
                    changes[field_name] = {'old': old_value, 'new': new_value}
                    setattr(order, field_name, new_value)
            
            db.commit()
            return order, changes
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error updating order: {str(e)}")
            raise
    
    @staticmethod
    def delete_order(order_id):
        """주문 삭제 (휴지통으로 이동)"""
        db = get_db()
        order = OrderService.get_order_by_id(order_id)
        
        if not order:
            return False
        
        try:
            original_status = order.status
            deleted_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 소프트 삭제
            order.status = 'DELETED'
            order.original_status = original_status
            order.deleted_at = deleted_at
            
            db.commit()
            return True
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error deleting order: {str(e)}")
            raise
    
    @staticmethod
    def get_deleted_orders(search_term=None):
        """휴지통 주문 조회"""
        db = get_db()
        query = db.query(Order).filter(Order.status == 'DELETED')
        
        # 검색어 필터 적용
        if search_term:
            search_pattern = f"%{search_term}%"
            query = query.filter(
                or_(
                    Order.customer_name.like(search_pattern),
                    Order.phone.like(search_pattern),
                    Order.address.like(search_pattern),
                    Order.product.like(search_pattern),
                    Order.options.like(search_pattern),
                    Order.notes.like(search_pattern)
                )
            )
        
        return query.order_by(Order.deleted_at.desc()).all()
    
    @staticmethod
    def restore_orders(order_ids):
        """주문 복원"""
        db = get_db()
        restored_count = 0
        
        try:
            for order_id in order_ids:
                order = db.query(Order).filter(Order.id == order_id, Order.status == 'DELETED').first()
                
                if order:
                    original_status = order.original_status if order.original_status else 'RECEIVED'
                    order.status = original_status
                    order.original_status = None
                    order.deleted_at = None
                    restored_count += 1
            
            db.commit()
            return restored_count
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error restoring orders: {str(e)}")
            raise
    
    @staticmethod
    def permanent_delete_orders(order_ids):
        """주문 영구 삭제"""
        db = get_db()
        deleted_count = 0
        
        try:
            for order_id in order_ids:
                order = db.query(Order).filter(Order.id == order_id).first()
                
                if order:
                    db.delete(order)
                    deleted_count += 1
            
            db.commit()
            return deleted_count
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error permanently deleting orders: {str(e)}")
            raise
    
    @staticmethod
    def perform_bulk_action(action, order_ids, action_details=None):
        """일괄 작업 수행"""
        db = get_db()
        updated_count = 0
        
        try:
            orders = db.query(Order).filter(Order.id.in_([int(id) for id in order_ids])).all()
            
            if action == 'delete':
                for order in orders:
                    order.status = 'DELETED'
                    order.original_status = order.status
                    order.deleted_at = datetime.datetime.utcnow()
                    updated_count += 1
            
            elif action == 'change_status':
                new_status = action_details.get('new_status')
                if new_status:
                    for order in orders:
                        order.status = new_status
                        updated_count += 1
            
            elif action == 'change_measurement_date':
                new_date = action_details.get('new_measurement_date')
                if new_date:
                    for order in orders:
                        order.measurement_date = new_date
                        updated_count += 1
            
            elif action == 'change_completion_date':
                new_date = action_details.get('new_completion_date')
                if new_date:
                    for order in orders:
                        order.completion_date = new_date
                        updated_count += 1
            
            elif action == 'change_manager':
                new_manager = action_details.get('new_manager_name')
                if new_manager:
                    for order in orders:
                        order.manager_name = new_manager
                        updated_count += 1
            
            db.commit()
            return updated_count
        except Exception as e:
            db.rollback()
            current_app.logger.error(f"Error performing bulk action: {str(e)}")
            raise 