import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from db import Base

class Order(Base):
    __tablename__ = 'orders'
    
    id = Column(Integer, primary_key=True)
    received_date = Column(String, nullable=False)
    received_time = Column(String)
    customer_name = Column(String, nullable=False)
    phone = Column(String, nullable=False)
    address = Column(Text, nullable=False)
    product = Column(String, nullable=False)
    options = Column(Text)
    notes = Column(Text)
    status = Column(String, default='RECEIVED')
    original_status = Column(String)
    deleted_at = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.now)
    
    # New fields for request 2
    measurement_date = Column(String) # 실측일
    measurement_time = Column(String) # 실측시간
    completion_date = Column(String)  # 설치완료일
    manager_name = Column(String)     # 담당자
    
    def to_dict(self):
        return {
            'id': self.id,
            'received_date': self.received_date,
            'received_time': self.received_time,
            'customer_name': self.customer_name,
            'phone': self.phone,
            'address': self.address,
            'product': self.product,
            'options': self.options,
            'notes': self.notes,
            'status': self.status,
            'original_status': self.original_status,
            'deleted_at': self.deleted_at,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'measurement_date': self.measurement_date,
            'measurement_time': self.measurement_time,
            'completion_date': self.completion_date,
            'manager_name': self.manager_name
        }

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    name = Column(String, nullable=False, default='사용자')
    role = Column(String, nullable=False, default='VIEWER')
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now)
    last_login = Column(DateTime)
    
    access_logs = relationship("AccessLog", back_populates="user")
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'name': self.name,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None
        }

class AccessLog(Base):
    __tablename__ = 'access_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String, nullable=False)
    ip_address = Column(String)
    user_agent = Column(String)
    additional_data = Column(Text)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    
    user = relationship("User", back_populates="access_logs")
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'additional_data': self.additional_data,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None
        } 