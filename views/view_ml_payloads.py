from flask import Blueprint, render_template,redirect, request, jsonify, session,url_for
from core.ml_payload_generator import ml_payload_generator

ml_payloads = Blueprint('ml_payloads', __name__, url_prefix='/ml-payloads')

@ml_payloads.route('/')
def view_ml_payloads():
    """ML Payload Generator interface"""
    if not session.get('session'):
        return redirect('/login')

    return render_template('ml_payloads.html')

@ml_payloads.route('/generate', methods=['POST'])
def generate_ml_payloads():
    """Generate ML-powered payloads"""
    if not session.get('session'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    payload_type = request.form.get('type', 'sqli')
    count = int(request.form.get('count', 10))
    creativity = float(request.form.get('creativity', 0.7))
    base_payload = request.form.get('base_payload', '')

    try:
        if base_payload:
            payloads = ml_payload_generator.generate_payload_variants(
                base_payload, payload_type, count, creativity
            )
        else:
            payloads = ml_payload_generator.generate_by_type(payload_type, count, creativity)

        return jsonify({
            'status': 'success',
            'count': len(payloads),
            'payloads': payloads
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@ml_payloads.route('/retrain', methods=['POST'])
def retrain_model():
    """Retrain the ML model"""
    if not session.get('session'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    try:
        num_payloads = ml_payload_generator.train_generative_model()
        return jsonify({
            'status': 'success',
            'message': f'Model retrained with {num_payloads} payload variants',
            'payload_count': num_payloads
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
