from flask_restful import Resource
from flask import request
import config
from core.ml_payload_generator import ml_payload_generator

class MLPayloads(Resource):
    def get(self, payload_type=None):
        """Get ML-generated payloads"""
        count = request.args.get('count', 10, type=int)
        creativity = request.args.get('creativity', 0.7, type=float)
        base_payload = request.args.get('base_payload')

        # Respect global config toggle
        if not getattr(config, 'ENABLE_ML', False):
            return {'status': 'error', 'message': 'ML features are disabled in configuration (ENABLE_ML=False).'}, 503

        try:
            if base_payload:
                # Generate variants from base payload
                payloads = ml_payload_generator.generate_payload_variants(
                    base_payload, payload_type, count, creativity
                )
            else:
                # Generate new payloads by type
                payloads = ml_payload_generator.generate_by_type(payload_type, count, creativity)

            return {
                'status': 'success',
                'count': len(payloads),
                'creativity_level': creativity,
                'payloads': payloads
            }

        except Exception as e:
            # If ML dependencies are missing, return clear guidance
            msg = str(e)
            if 'ML dependencies not available' in msg or 'ImportError' in msg:
                msg = (
                    msg + ' — install ML dependencies (numpy,pandas,scikit-learn,joblib). '
                    'On Windows prefer conda install -c conda-forge numpy pandas scikit-learn joblib'
                )
            return {'status': 'error', 'message': msg}, 500

    def post(self):
        """Advanced payload generation with ML"""
        data = request.get_json()

        payload_type = data.get('type', 'sqli')
        count = data.get('count', 10)
        creativity = data.get('creativity', 0.7)
        base_payload = data.get('base_payload')
        techniques = data.get('techniques', [])

        # Respect global config toggle
        if not getattr(config, 'ENABLE_ML', False):
            return {'status': 'error', 'message': 'ML features are disabled in configuration (ENABLE_ML=False).'}, 503

        try:
            if base_payload:
                payloads = ml_payload_generator.generate_payload_variants(
                    base_payload, payload_type, count, creativity
                )
            else:
                payloads = ml_payload_generator.generate_by_type(payload_type, count, creativity)

            # Filter by techniques if specified
            if techniques:
                payloads = [p for p in payloads if any(tech in p['payload'].lower() for tech in techniques)]

            return {
                'status': 'success',
                'count': len(payloads),
                'creativity_level': creativity,
                'payloads': payloads
            }

        except Exception as e:
            msg = str(e)
            if 'ML dependencies not available' in msg or 'ImportError' in msg:
                msg = (
                    msg + ' — install ML dependencies (numpy,pandas,scikit-learn,joblib). '
                    'On Windows prefer conda install -c conda-forge numpy pandas scikit-learn joblib'
                )
            return {'status': 'error', 'message': msg}, 500

class MLPayloadTrain(Resource):
    def post(self):
        """Retrain the ML model"""
        # Respect global config toggle
        if not getattr(config, 'ENABLE_ML', False):
            return {'status': 'error', 'message': 'ML features are disabled in configuration (ENABLE_ML=False).'}, 503

        try:
            num_payloads = ml_payload_generator.train_generative_model()
            return {
                'status': 'success',
                'message': f'ML model retrained with {num_payloads} payload variants',
                'payload_count': num_payloads
            }
        except Exception as e:
            msg = str(e)
            if 'ML dependencies not available' in msg or 'ImportError' in msg:
                msg = (
                    msg + ' — install ML dependencies (numpy,pandas,scikit-learn,joblib). '
                    'On Windows prefer conda install -c conda-forge numpy pandas scikit-learn joblib'
                )
            return {'status': 'error', 'message': msg}, 500
