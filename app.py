# app.py
import os
import sys
import logging
from flask import Flask, jsonify

# 设置日志
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 创建 Flask 应用
app = Flask(__name__)

@app.route('/')
def index():
    logger.info('访问首页')
    return jsonify({
        'status': 'running',
        'service': 'SM9-VSS Experiment',
        'python_version': sys.version,
        'environment': os.environ.get('PYTHON_ENV', 'development')
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'}), 200

@app.route('/api/sm9')
def sm9_info():
    # 这里可以添加 SM9 相关的 API
    return jsonify({
        'algorithm': 'SM9',
        'type': 'Identity-Based Cryptography',
        'standard': 'GM/T 0044-2016'
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logger.info(f'启动服务，端口: {port}')
    app.run(host='0.0.0.0', port=port, debug=True)