"""
Test script to verify the OWASP scanner is working properly
"""
import sys
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def test_scanner_import():
    """Test if the scanner modules can be imported."""
    try:
        logger.info("Testing scanner module imports...")
        
        # Test importing wrapper
        from core.owasp_wrapper import initialize_owasp_scanner, get_scan_config, get_scan_manager
        
        logger.info("✓ Successfully imported OWASP wrapper")
        
        # Initialize scanner
        logger.info("Initializing OWASP scanner...")
        result = initialize_owasp_scanner()
        
        if result:
            logger.info("✓ OWASP scanner initialized successfully")
        else:
            logger.error("✗ Failed to initialize OWASP scanner")
            return False
        
        # Get ScanConfig
        ScanConfig = get_scan_config()
        if ScanConfig:
            logger.info("✓ Got ScanConfig class")
        else:
            logger.error("✗ Failed to get ScanConfig")
            return False
        
        # Get scan manager
        scan_manager = get_scan_manager()
        if scan_manager:
            logger.info("✓ Got scan manager instance")
            logger.info(f"  Scan manager type: {type(scan_manager)}")
        else:
            logger.error("✗ Failed to get scan manager")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Error during scanner import test: {e}", exc_info=True)
        return False

def test_scanner_basic_operation():
    """Test basic scanner operation."""
    try:
        from core.owasp_wrapper import initialize_owasp_scanner, get_scan_config, get_scan_manager
        import uuid
        
        logger.info("\nTesting basic scanner operation...")
        
        # Initialize if not already done
        initialize_owasp_scanner()
        
        ScanConfig = get_scan_config()
        scan_manager = get_scan_manager()
        
        # Create test config
        scan_id = str(uuid.uuid4())
        config = ScanConfig(
            target="https://example.com",
            max_pages=1,
            concurrency=1,
            timeout=5
        )
        
        logger.info(f"Starting test scan with ID: {scan_id}")
        
        # Start scan
        result_id = scan_manager.start_scan(scan_id, config)
        logger.info(f"✓ Scan started with ID: {result_id}")
        
        # Check status immediately
        import time
        time.sleep(2)
        
        status = scan_manager.get_scan_status(scan_id)
        if status:
            logger.info(f"✓ Got scan status: {status}")
        else:
            logger.warning("⚠ Scan status not available yet")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Error during scanner operation test: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("OWASP Scanner Test Suite")
    logger.info("=" * 60)
    
    # Test 1: Module imports
    test1_passed = test_scanner_import()
    
    # Test 2: Basic operation (only if test 1 passed)
    test2_passed = False
    if test1_passed:
        test2_passed = test_scanner_basic_operation()
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Test Summary")
    logger.info("=" * 60)
    logger.info(f"Test 1 (Module Imports): {'PASSED ✓' if test1_passed else 'FAILED ✗'}")
    logger.info(f"Test 2 (Basic Operation): {'PASSED ✓' if test2_passed else 'FAILED ✗'}")
    
    if test1_passed and test2_passed:
        logger.info("\n✓ All tests passed!")
        sys.exit(0)
    else:
        logger.error("\n✗ Some tests failed")
        sys.exit(1)
