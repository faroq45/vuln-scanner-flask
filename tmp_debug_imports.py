import sys, os, importlib, importlib.util
print('cwd=', os.getcwd())
print('sys.path[0]=', sys.path[0])
try:
    core = importlib.import_module('core')
    print('core imported:', getattr(core,'__file__',None), getattr(core,'__path__',None))
except Exception as e:
    print('core import failed', e)
try:
    ml = importlib.import_module('core.ml_payload_generator')
    print('core.ml_payload_generator imported:', getattr(ml,'__file__',None))
except Exception as e:
    print('core.ml_payload_generator import failed:', repr(e))
ml_path = os.path.join(os.getcwd(), 'core', 'ml_payload_generator.py')
print('ml_path exists?', os.path.exists(ml_path), 'ml_path=', ml_path)
if os.path.exists(ml_path):
    try:
        spec = importlib.util.spec_from_file_location('core.ml_payload_generator', ml_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules['core.ml_payload_generator'] = mod
        spec.loader.exec_module(mod)
        print('fallback loaded core.ml_payload_generator', getattr(mod,'__file__',None))
    except Exception as e:
        import traceback; traceback.print_exc()
print('core in sys.modules?', 'core' in sys.modules)
print('core.ml_payload_generator in sys.modules?', 'core.ml_payload_generator' in sys.modules)
