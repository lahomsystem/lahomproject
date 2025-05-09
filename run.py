import os
from app import create_app

if __name__ == '__main__':
    # 디버그 모드 강제 활성화
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True) 