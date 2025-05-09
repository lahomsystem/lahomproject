from flask import Blueprint, jsonify, request
from flask_wtf.csrf import generate_csrf

utils_bp = Blueprint('utils', __name__)

@utils_bp.route('/api/csrf-token')
def get_csrf_token():
    """CSRF 토큰을 반환하는 API"""
    return jsonify({'csrf_token': generate_csrf()})

@utils_bp.route('/api/heartbeat')
def heartbeat():
    """시스템 상태 확인용 API"""
    return jsonify({'status': 'ok'}) 