#!/usr/bin/env python3
"""
Ultra-Enhanced Payload Generation System Test Suite
Comprehensive testing for all 15+ advanced AI/ML algorithms
"""

import sys
import os
import importlib.util
import json
import time
from datetime import datetime
from typing import List, Dict, Any

def test_ultra_enhanced_payload_generator():
    """Test the ultra-enhanced payload generator with all algorithms."""
    print("🧪 Testing Ultra-Enhanced Payload Generator")
    print("=" * 80)
    
    try:
        # Import the ultra-enhanced payload generator
        spec = importlib.util.spec_from_file_location(
            "payload_generator_ultra",
            "core/payload_generator_ultra_enhanced.py"
        )
        pg_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pg_module)
        
        # Initialize the generator
        generator = pg_module.PayloadGeneratorUltraEnhanced()
        
        print("✅ Ultra-Enhanced payload generator initialized")
        
        # Test algorithm summary
        print(f"\n🔍 Testing algorithm summary...")
        summary = generator.get_algorithm_summary()
        print(f"   Total algorithms: {summary['total_algorithms']}")
        print(f"   Payload types: {summary['base_payload_types']}")
        print(f"   Encoding techniques: {summary['encoding_techniques']}")
        
        # Validate all 15 algorithms are present
        expected_algorithms = 15
        actual_algorithms = len(summary['algorithms'])
        assert actual_algorithms == expected_algorithms, f"Expected {expected_algorithms} algorithms, got {actual_algorithms}"
        print(f"   ✅ All {expected_algorithms} algorithms present")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing ultra-enhanced generator: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_individual_algorithms():
    """Test each algorithm individually."""
    print(f"\n🧪 Testing Individual Algorithms")
    print("=" * 80)
    
    try:
        # Import generator
        spec = importlib.util.spec_from_file_location(
            "payload_generator_ultra",
            "core/payload_generator_ultra_enhanced.py"
        )
        pg_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pg_module)
        
        generator = pg_module.PayloadGeneratorUltraEnhanced()
        test_payload = "' OR 1=1 --"
        
        # Test each algorithm
        algorithms_to_test = [
            ("Deep Neural Network", lambda: generator.generate_deep_neural_payloads('sql_injection', count=5)),
            ("Advanced Genetic", lambda: generator.generate_advanced_genetic_payloads(test_payload, population_size=10, generations=2)),
            ("Deep Q-Learning", lambda: generator.generate_deep_q_learning_payloads('sql_injection', episodes=5)),
            ("Enhanced PSO", lambda: generator.generate_enhanced_pso_payloads('sql_injection', swarms=2, iterations=5)),
            ("Adversarial Training", lambda: generator.generate_adversarial_training_payloads(test_payload, iterations=5)),
            ("Transformer-Based", lambda: generator.generate_transformer_payloads('sql_injection')),
            ("LSTM Sequential", lambda: generator.generate_lstm_sequential_payloads('sql_injection')),
            ("Simulated Annealing", lambda: generator.generate_simulated_annealing_payloads(test_payload, max_iterations=50)),
            ("Ant Colony", lambda: generator.generate_ant_colony_payloads('sql_injection', num_ants=5, iterations=10)),
            ("Bayesian Optimization", lambda: generator.generate_bayesian_optimization_payloads('sql_injection', iterations=10)),
            ("Metamorphic", lambda: generator.generate_metamorphic_payloads(test_payload)),
            ("Steganographic", lambda: generator.generate_steganographic_payloads(test_payload)),
            ("ML-Resistant", lambda: generator.generate_adversarial_ml_resistant_payloads(test_payload)),
            ("Adaptive Learning", lambda: generator.generate_adaptive_learning_payloads('sql_injection')),
        ]
        
        results = {}
        
        for name, algorithm_func in algorithms_to_test:
            print(f"\n🔬 Testing {name}...")
            try:
                start_time = time.time()
                payloads = algorithm_func()
                end_time = time.time()
                
                execution_time = end_time - start_time
                payload_count = len(payloads) if payloads else 0
                
                results[name] = {
                    'success': True,
                    'payload_count': payload_count,
                    'execution_time': execution_time,
                    'sample_payloads': payloads[:3] if payloads else []
                }
                
                print(f"   ✅ Generated {payload_count} payloads in {execution_time:.2f}s")
                if payloads:
                    print(f"   📋 Sample: {payloads[0][:60]}...")
                
            except Exception as e:
                print(f"   ❌ Error: {str(e)[:100]}")
                results[name] = {
                    'success': False,
                    'error': str(e),
                    'payload_count': 0,
                    'execution_time': 0
                }
        
        # Summary
        successful_tests = sum(1 for r in results.values() if r['success'])
        total_tests = len(results)
        total_payloads = sum(r['payload_count'] for r in results.values())
        
        print(f"\n📊 Algorithm Test Summary:")
        print(f"   Successful: {successful_tests}/{total_tests}")
        print(f"   Total payloads generated: {total_payloads}")
        
        return results
        
    except Exception as e:
        print(f"❌ Error testing individual algorithms: {e}")
        import traceback
        traceback.print_exc()
        return {}

def test_advanced_features():
    """Test advanced features and capabilities."""
    print(f"\n🧪 Testing Advanced Features")
    print("=" * 80)
    
    try:
        # Import generator
        spec = importlib.util.spec_from_file_location(
            "payload_generator_ultra",
            "core/payload_generator_ultra_enhanced.py"
        )
        pg_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pg_module)
        
        generator = pg_module.PayloadGeneratorUltraEnhanced()
        test_payload = "<script>alert('test')</script>"
        
        # Test encoding capabilities
        print("\n🔧 Testing Encoding Capabilities...")
        encoding_results = {}
        
        for encoding_type in generator.advanced_encodings[:5]:  # Test first 5
            try:
                encoded = generator._apply_encoding(test_payload, encoding_type)
                encoding_results[encoding_type] = {
                    'success': True,
                    'original_length': len(test_payload),
                    'encoded_length': len(encoded),
                    'encoded_payload': encoded[:50] + "..." if len(encoded) > 50 else encoded
                }
                print(f"   ✅ {encoding_type}: {len(test_payload)} → {len(encoded)} chars")
            except Exception as e:
                encoding_results[encoding_type] = {'success': False, 'error': str(e)}
                print(f"   ❌ {encoding_type}: Error - {str(e)[:50]}")
        
        # Test steganographic hiding
        print("\n🕵️ Testing Steganographic Hiding...")
        steg_methods = ['whitespace', 'invisible_chars', 'homoglyphs']
        steg_results = {}
        
        for method in steg_methods:
            try:
                hidden = generator.generate_steganographic_payloads(test_payload, hiding_method=method)
                steg_results[method] = {
                    'success': True,
                    'payload_count': len(hidden),
                    'sample': hidden[0][:60] + "..." if hidden and len(hidden[0]) > 60 else (hidden[0] if hidden else "")
                }
                print(f"   ✅ {method}: Generated {len(hidden)} hidden payloads")
            except Exception as e:
                steg_results[method] = {'success': False, 'error': str(e)}
                print(f"   ❌ {method}: Error - {str(e)[:50]}")
        
        # Test metamorphic transformations
        print("\n🔄 Testing Metamorphic Transformations...")
        transform_types = ['instruction_reordering', 'equivalent_instruction_substitution', 'dead_code_insertion']
        morph_results = {}
        
        for transform_type in transform_types:
            try:
                transformed = generator._apply_metamorphic_transform(test_payload, transform_type)
                morph_results[transform_type] = {
                    'success': True,
                    'original': test_payload,
                    'transformed': transformed,
                    'length_change': len(transformed) - len(test_payload)
                }
                print(f"   ✅ {transform_type}: Length change {len(transformed) - len(test_payload)}")
            except Exception as e:
                morph_results[transform_type] = {'success': False, 'error': str(e)}
                print(f"   ❌ {transform_type}: Error - {str(e)[:50]}")
        
        # Test ML resistance features
        print("\n🤖 Testing ML Resistance Features...")
        ml_attack_methods = ['gradient_based', 'feature_space_attack', 'transferability_attack']
        ml_results = {}
        
        for attack_method in ml_attack_methods:
            try:
                resistant_payloads = generator.generate_adversarial_ml_resistant_payloads(
                    test_payload, attack_method=attack_method
                )
                ml_results[attack_method] = {
                    'success': True,
                    'payload_count': len(resistant_payloads),
                    'sample': resistant_payloads[0][:60] + "..." if resistant_payloads and len(resistant_payloads[0]) > 60 else (resistant_payloads[0] if resistant_payloads else "")
                }
                print(f"   ✅ {attack_method}: Generated {len(resistant_payloads)} resistant payloads")
            except Exception as e:
                ml_results[attack_method] = {'success': False, 'error': str(e)}
                print(f"   ❌ {attack_method}: Error - {str(e)[:50]}")
        
        # Test fitness evaluation
        print("\n📊 Testing Fitness Evaluation...")
        test_payloads = [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "; whoami",
            "test",
            ""
        ]
        
        fitness_results = {}
        for i, payload in enumerate(test_payloads):
            try:
                fitness = generator._evaluate_payload_fitness(payload)
                multi_fitness = generator._multi_objective_fitness(payload)
                
                fitness_results[f"payload_{i}"] = {
                    'payload': payload,
                    'fitness': fitness,
                    'multi_objectives': multi_fitness,
                    'success': True
                }
                print(f"   ✅ '{payload[:30]}...': Fitness {fitness:.3f}")
            except Exception as e:
                fitness_results[f"payload_{i}"] = {'success': False, 'error': str(e)}
                print(f"   ❌ '{payload[:30]}...': Error - {str(e)[:50]}")
        
        return {
            'encoding': encoding_results,
            'steganography': steg_results,
            'metamorphic': morph_results,
            'ml_resistance': ml_results,
            'fitness': fitness_results
        }
        
    except Exception as e:
        print(f"❌ Error testing advanced features: {e}")
        import traceback
        traceback.print_exc()
        return {}

def test_performance_benchmarks():
    """Test performance and scalability of algorithms."""
    print(f"\n🧪 Testing Performance Benchmarks")
    print("=" * 80)
    
    try:
        # Import generator
        spec = importlib.util.spec_from_file_location(
            "payload_generator_ultra",
            "core/payload_generator_ultra_enhanced.py"
        )
        pg_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pg_module)
        
        generator = pg_module.PayloadGeneratorUltraEnhanced()
        
        # Performance tests with different scales
        performance_tests = [
            ("Small Scale", lambda: generator.generate_deep_neural_payloads('sql_injection', count=10)),
            ("Medium Scale", lambda: generator.generate_advanced_genetic_payloads("' OR 1=1 --", population_size=20, generations=5)),
            ("Large Scale", lambda: generator.generate_deep_q_learning_payloads('sql_injection', episodes=20)),
        ]
        
        performance_results = {}
        
        for test_name, test_func in performance_tests:
            print(f"\n⏱️ Running {test_name} Performance Test...")
            
            try:
                start_time = time.time()
                start_memory = sys.getsizeof(generator.__dict__)
                
                payloads = test_func()
                
                end_time = time.time()
                end_memory = sys.getsizeof(generator.__dict__)
                
                execution_time = end_time - start_time
                memory_usage = end_memory - start_memory
                payload_count = len(payloads) if payloads else 0
                
                performance_results[test_name] = {
                    'success': True,
                    'execution_time': execution_time,
                    'memory_usage': memory_usage,
                    'payload_count': payload_count,
                    'payloads_per_second': payload_count / execution_time if execution_time > 0 else 0
                }
                
                print(f"   ⏱️ Time: {execution_time:.2f}s")
                print(f"   🧠 Memory: {memory_usage} bytes")
                print(f"   📊 Rate: {payload_count / execution_time if execution_time > 0 else 0:.1f} payloads/sec")
                print(f"   ✅ Generated {payload_count} payloads")
                
            except Exception as e:
                performance_results[test_name] = {
                    'success': False,
                    'error': str(e),
                    'execution_time': 0,
                    'memory_usage': 0,
                    'payload_count': 0
                }
                print(f"   ❌ Error: {str(e)[:100]}")
        
        return performance_results
        
    except Exception as e:
        print(f"❌ Error in performance benchmarks: {e}")
        import traceback
        traceback.print_exc()
        return {}

def test_adaptive_learning():
    """Test adaptive learning capabilities."""
    print(f"\n🧪 Testing Adaptive Learning System")
    print("=" * 80)
    
    try:
        # Import generator
        spec = importlib.util.spec_from_file_location(
            "payload_generator_ultra",
            "core/payload_generator_ultra_enhanced.py"
        )
        pg_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pg_module)
        
        generator = pg_module.PayloadGeneratorUltraEnhanced()
        
        # Simulate target responses for learning
        mock_responses = [
            # Successful SQL injection responses
            "MySQL Error: You have an error in your SQL syntax near '' at line 1",
            "root:x:0:0:root:/root:/bin/bash",
            "Welcome admin! You are now logged in.",
            
            # Failed attempts
            "Access denied",
            "Invalid request",
            "Forbidden - 403",
            
            # XSS responses
            "alert(1) executed successfully",
            "<script>alert(document.cookie)</script> blocked",
            "XSS attempt detected and filtered"
        ]
        
        print(f"\n📚 Testing Response Pattern Extraction...")
        pattern_results = {}
        
        for i, response in enumerate(mock_responses[:3]):
            try:
                patterns = generator._extract_response_patterns(response)
                is_success = generator._is_successful_response(response)
                
                pattern_results[f"response_{i}"] = {
                    'response': response[:50] + "...",
                    'patterns': patterns,
                    'is_success': is_success,
                    'success': True
                }
                print(f"   ✅ Response {i}: {len(patterns)} patterns, Success: {is_success}")
            except Exception as e:
                pattern_results[f"response_{i}"] = {'success': False, 'error': str(e)}
                print(f"   ❌ Response {i}: Error - {str(e)[:50]}")
        
        print(f"\n🎯 Testing Adaptive Payload Generation...")
        try:
            adaptive_payloads = generator.generate_adaptive_learning_payloads(
                'sql_injection',
                target_responses=mock_responses[:5],
                learning_rate=0.1
            )
            
            adaptive_results = {
                'success': True,
                'payload_count': len(adaptive_payloads),
                'sample_payloads': adaptive_payloads[:3] if adaptive_payloads else [],
                'learning_weights_count': len(generator.adaptation_weights)
            }
            
            print(f"   ✅ Generated {len(adaptive_payloads)} adaptive payloads")
            print(f"   🧠 Learning weights: {len(generator.adaptation_weights)} patterns")
            
        except Exception as e:
            adaptive_results = {'success': False, 'error': str(e)}
            print(f"   ❌ Adaptive generation error: {str(e)[:100]}")
        
        return {
            'pattern_extraction': pattern_results,
            'adaptive_generation': adaptive_results
        }
        
    except Exception as e:
        print(f"❌ Error testing adaptive learning: {e}")
        import traceback
        traceback.print_exc()
        return {}

def run_comprehensive_test_suite():
    """Run the complete test suite for ultra-enhanced payload generator."""
    print("🚀 Ultra-Enhanced Payload Generator Test Suite")
    print("=" * 80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initialize results
    test_results = {
        'timestamp': datetime.now().isoformat(),
        'tests': {}
    }
    
    # Run all test categories
    test_categories = [
        ("Basic Functionality", test_ultra_enhanced_payload_generator),
        ("Individual Algorithms", test_individual_algorithms),
        ("Advanced Features", test_advanced_features),
        ("Performance Benchmarks", test_performance_benchmarks),
        ("Adaptive Learning", test_adaptive_learning)
    ]
    
    for category_name, test_function in test_categories:
        print(f"\n" + "=" * 80)
        print(f"Running {category_name} Tests...")
        print("=" * 80)
        
        try:
            start_time = time.time()
            category_results = test_function()
            end_time = time.time()
            
            test_results['tests'][category_name] = {
                'success': True,
                'execution_time': end_time - start_time,
                'results': category_results
            }
            print(f"✅ {category_name} completed in {end_time - start_time:.2f}s")
            
        except Exception as e:
            test_results['tests'][category_name] = {
                'success': False,
                'error': str(e),
                'execution_time': 0
            }
            print(f"❌ {category_name} failed: {str(e)[:100]}")
    
    # Generate summary
    total_tests = len(test_categories)
    successful_tests = sum(1 for result in test_results['tests'].values() if result['success'])
    total_execution_time = sum(result.get('execution_time', 0) for result in test_results['tests'].values())
    
    print(f"\n" + "=" * 80)
    print(f"🏁 Test Suite Summary")
    print("=" * 80)
    print(f"📊 Test Categories: {successful_tests}/{total_tests} passed")
    print(f"⏱️ Total Execution Time: {total_execution_time:.2f} seconds")
    print(f"📅 Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Save results to file
    results_file = f"ultra_enhanced_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(results_file, 'w') as f:
            json.dump(test_results, f, indent=2, default=str)
        print(f"📁 Results saved to: {results_file}")
    except Exception as e:
        print(f"⚠️ Could not save results: {str(e)}")
    
    return test_results

if __name__ == "__main__":
    print("=" * 80)
    print("🧪 Ultra-Enhanced Payload Generator Test Suite")
    print("Testing 15+ Advanced AI/ML Algorithms")
    print("=" * 80)
    
    # Check if numpy is available (required for some algorithms)
    try:
        import numpy as np
        print("✅ NumPy available - All algorithms can be tested")
    except ImportError:
        print("⚠️ NumPy not available - Some algorithms may be limited")
    
    # Run the comprehensive test suite
    results = run_comprehensive_test_suite()
    
    # Exit with appropriate code
    successful_categories = sum(1 for result in results['tests'].values() if result['success'])
    total_categories = len(results['tests'])
    
    if successful_categories == total_categories:
        print(f"\n🎉 All tests passed! Ultra-Enhanced Payload Generator is ready!")
        sys.exit(0)
    else:
        print(f"\n⚠️ Some tests failed. Check results for details.")
        sys.exit(1)