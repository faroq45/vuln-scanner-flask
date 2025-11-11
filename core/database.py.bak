"""
PostgreSQL Database integration for VulScanner
"""
import os
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

import config
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, Float, JSON, ForeignKey, Index, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.exc import SQLAlchemyError
from core.logging import logger

Base = declarative_base()

class ScanSession(Base):
    """Model for scan sessions"""
    __tablename__ = 'scan_sessions'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    status = Column(String(20), nullable=False, default='created')  # created, running, completed, failed
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    config = Column(JSON, nullable=True)
    scan_type = Column(String(20), default='quick')  # quick, full, owasp, custom
    engineer = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="session", cascade="all, delete-orphan")
    targets = relationship("Target", back_populates="session", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ScanSession(id={self.id}, session_id='{self.session_id}', status='{self.status}')>"

class Target(Base):
    """Model for scan targets (IPs, domains, URLs)"""
    __tablename__ = 'targets'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(64), ForeignKey('scan_sessions.session_id'), nullable=False, index=True)
    target_type = Column(String(20), nullable=False)  # ip, domain, url, network
    target_value = Column(String(500), nullable=False)
    status = Column(String(20), default='pending')  # pending, scanning, completed, failed
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Target details
    hostname = Column(String(255), nullable=True)
    os_fingerprint = Column(String(255), nullable=True)
    open_ports = Column(JSON, nullable=True)  # List of open ports with service info
    
    # Relationships
    session = relationship("ScanSession", back_populates="targets")
    vulnerabilities = relationship("Vulnerability", back_populates="target")
    
    __table_args__ = (
        Index('ix_targets_session_type', 'session_id', 'target_type'),
    )
    
    def __repr__(self):
        return f"<Target(id={self.id}, type='{self.target_type}', value='{self.target_value}')>"

class Vulnerability(Base):
    """Model for discovered vulnerabilities"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(64), ForeignKey('scan_sessions.session_id'), nullable=False, index=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=True, index=True)
    
    # Vulnerability identification
    rule_id = Column(String(50), nullable=False, index=True)
    rule_name = Column(String(200), nullable=False)
    rule_description = Column(Text, nullable=True)
    rule_details = Column(Text, nullable=True)
    rule_mitigation = Column(Text, nullable=True)
    
    # Severity and classification
    severity = Column(Integer, nullable=False, index=True)  # 1=Low, 2=Medium, 3=High, 4=Critical
    severity_text = Column(String(20), nullable=False)  # Low, Medium, High, Critical
    confidence = Column(Float, default=1.0)  # 0.0 - 1.0
    
    # Technical details
    ip_address = Column(String(45), nullable=True, index=True)  # IPv4/IPv6
    port = Column(Integer, nullable=True)
    protocol = Column(String(10), default='tcp')
    service = Column(String(50), nullable=True)
    url = Column(String(1000), nullable=True)
    
    # Evidence and proof
    evidence = Column(Text, nullable=True)
    proof_of_concept = Column(Text, nullable=True)
    raw_output = Column(Text, nullable=True)
    
    # OWASP and CVE classification
    owasp_category = Column(String(50), nullable=True)
    cve_ids = Column(JSON, nullable=True)  # List of CVE IDs
    cwe_id = Column(Integer, nullable=True)
    
    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow, index=True)
    verified_at = Column(DateTime, nullable=True)
    
    # Status tracking
    false_positive = Column(Boolean, default=False, index=True)
    remediated = Column(Boolean, default=False, index=True)
    notes = Column(Text, nullable=True)
    
    # Relationships
    session = relationship("ScanSession", back_populates="vulnerabilities")
    target = relationship("Target", back_populates="vulnerabilities")
    
    __table_args__ = (
        Index('ix_vulns_severity_ip', 'severity', 'ip_address'),
        Index('ix_vulns_rule_severity', 'rule_id', 'severity'),
        Index('ix_vulns_session_severity', 'session_id', 'severity'),
    )
    
    def __repr__(self):
        return f"<Vulnerability(id={self.id}, rule='{self.rule_id}', severity={self.severity})>"

class ScanStatistics(Base):
    """Model for scan statistics and metrics"""
    __tablename__ = 'scan_statistics'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(64), ForeignKey('scan_sessions.session_id'), nullable=False, unique=True)
    
    # Target counts
    total_targets = Column(Integer, default=0)
    targets_scanned = Column(Integer, default=0)
    targets_with_vulns = Column(Integer, default=0)
    
    # Vulnerability counts
    total_vulnerabilities = Column(Integer, default=0)
    critical_vulns = Column(Integer, default=0)
    high_vulns = Column(Integer, default=0)
    medium_vulns = Column(Integer, default=0)
    low_vulns = Column(Integer, default=0)
    
    # Port statistics
    total_open_ports = Column(Integer, default=0)
    unique_services = Column(Integer, default=0)
    
    # Timing
    scan_duration_minutes = Column(Float, nullable=True)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ScanStatistics(session_id='{self.session_id}', total_vulns={self.total_vulnerabilities})>"

class UserActivity(Base):
    """Model for user activity tracking"""
    __tablename__ = 'user_activity'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, index=True)
    action = Column(String(100), nullable=False)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<UserActivity(id={self.id}, user='{self.username}', action='{self.action}')>"

class DatabaseManager:
    """Database manager class for PostgreSQL operations"""
    
    def __init__(self):
        self.engine = None
        self.Session = None
        self.connected = False
        self._setup_database()
    
    def _setup_database(self):
        """Initialize database connection and create tables"""
        try:
            if config.USE_DATABASE and config.DB_URL:
                self.engine = create_engine(
                    config.DB_URL,
                    echo=config.DB_ECHO,
                    pool_pre_ping=True,
                    pool_recycle=3600
                )
                
                # Test connection
                with self.engine.connect() as conn:
                    result = conn.execute(text("SELECT 1"))
                    if config.DB_URL.startswith('sqlite'):
                        logger.info("Successfully connected to SQLite database")
                    else:
                        logger.info("Successfully connected to PostgreSQL database")
                
                # Create tables
                Base.metadata.create_all(self.engine)
                logger.info("Database tables created/verified")
                
                # Create session factory
                self.Session = sessionmaker(bind=self.engine)
                self.connected = True
                
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            self.connected = False
    
    def get_session(self) -> Optional[Session]:
        """Get a new database session"""
        if not self.connected or not self.Session:
            return None
        return self.Session()
    
    def create_scan_session(self, session_id: str, config_data: Dict[str, Any], 
                           scan_type: str = 'quick', engineer: str = None, 
                           description: str = None) -> bool:
        """Create a new scan session"""
        if not self.connected:
            return False
            
        try:
            with self.get_session() as session:
                scan_session = ScanSession(
                    session_id=session_id,
                    config=config_data,
                    scan_type=scan_type,
                    engineer=engineer,
                    description=description
                )
                session.add(scan_session)
                session.commit()
                logger.info(f"Created scan session: {session_id}")
                return True
        except Exception as e:
            logger.error(f"Error creating scan session: {e}")
            return False
    
    def update_scan_status(self, session_id: str, status: str) -> bool:
        """Update scan session status"""
        if not self.connected:
            return False
            
        try:
            with self.get_session() as session:
                scan_session = session.query(ScanSession).filter_by(session_id=session_id).first()
                if scan_session:
                    scan_session.status = status
                    if status == 'completed':
                        scan_session.end_time = datetime.utcnow()
                    session.commit()
                    return True
        except Exception as e:
            logger.error(f"Error updating scan status: {e}")
        return False
    
    def store_target(self, session_id: str, target_type: str, target_value: str, 
                    hostname: str = None, os_fingerprint: str = None, 
                    open_ports: List[Dict] = None) -> Optional[int]:
        """Store a discovered target"""
        if not self.connected:
            return None
            
        try:
            with self.get_session() as session:
                target = Target(
                    session_id=session_id,
                    target_type=target_type,
                    target_value=target_value,
                    hostname=hostname,
                    os_fingerprint=os_fingerprint,
                    open_ports=open_ports
                )
                session.add(target)
                session.commit()
                logger.debug(f"Stored target: {target_value}")
                return target.id
        except Exception as e:
            logger.error(f"Error storing target: {e}")
        return None
    
    def store_vulnerability(self, session_id: str, vuln_data: Dict[str, Any]) -> bool:
        """Store a discovered vulnerability"""
        if not self.connected:
            return False
            
        try:
            with self.get_session() as session:
                # Map severity number to text
                severity_map = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
                severity = vuln_data.get('rule_sev', 1)
                
                vulnerability = Vulnerability(
                    session_id=session_id,
                    rule_id=vuln_data.get('rule_id', ''),
                    rule_name=vuln_data.get('rule_confirm', ''),
                    rule_description=vuln_data.get('rule_desc', ''),
                    rule_details=vuln_data.get('rule_details', ''),
                    rule_mitigation=vuln_data.get('rule_mitigation', ''),
                    severity=severity,
                    severity_text=severity_map.get(severity, 'Low'),
                    ip_address=vuln_data.get('ip', ''),
                    port=vuln_data.get('port'),
                    service=vuln_data.get('service'),
                    url=vuln_data.get('url'),
                    evidence=vuln_data.get('evidence', ''),
                    owasp_category=vuln_data.get('owasp_category'),
                    cwe_id=vuln_data.get('cwe')
                )
                session.add(vulnerability)
                session.commit()
                logger.info(f"Stored vulnerability: {vuln_data.get('rule_id')}")
                return True
        except Exception as e:
            logger.error(f"Error storing vulnerability: {e}")
        return False
    
    def get_vulnerabilities(self, session_id: str = None, limit: int = None) -> List[Dict]:
        """Get vulnerabilities from database"""
        if not self.connected:
            return []
            
        try:
            with self.get_session() as session:
                query = session.query(Vulnerability)
                if session_id:
                    query = query.filter_by(session_id=session_id)
                
                query = query.order_by(Vulnerability.discovered_at.desc())
                
                if limit:
                    query = query.limit(limit)
                
                vulns = query.all()
                
                # Convert to dictionary format
                return [
                    {
                        'id': v.id,
                        'session_id': v.session_id,
                        'rule_id': v.rule_id,
                        'rule_name': v.rule_name,
                        'rule_description': v.rule_description,
                        'rule_details': v.rule_details,
                        'rule_mitigation': v.rule_mitigation,
                        'severity': v.severity,
                        'severity_text': v.severity_text,
                        'ip_address': v.ip_address,
                        'port': v.port,
                        'url': v.url,
                        'evidence': v.evidence,
                        'discovered_at': v.discovered_at.isoformat() if v.discovered_at else None
                    }
                    for v in vulns
                ]
        except Exception as e:
            logger.error(f"Error getting vulnerabilities: {e}")
        return []
    
    def get_scan_statistics(self, session_id: str = None) -> Dict[str, Any]:
        """Get scan statistics"""
        if not self.connected:
            return {}
            
        try:
            with self.get_session() as session:
                if session_id:
                    # Statistics for specific session
                    stats = session.query(ScanStatistics).filter_by(session_id=session_id).first()
                    if stats:
                        return {
                            'total_vulnerabilities': stats.total_vulnerabilities,
                            'critical_vulns': stats.critical_vulns,
                            'high_vulns': stats.high_vulns,
                            'medium_vulns': stats.medium_vulns,
                            'low_vulns': stats.low_vulns,
                            'total_targets': stats.total_targets,
                            'targets_scanned': stats.targets_scanned
                        }
                else:
                    # Overall statistics
                    total_vulns = session.query(Vulnerability).count()
                    critical_count = session.query(Vulnerability).filter_by(severity=4).count()
                    high_count = session.query(Vulnerability).filter_by(severity=3).count()
                    medium_count = session.query(Vulnerability).filter_by(severity=2).count()
                    low_count = session.query(Vulnerability).filter_by(severity=1).count()
                    
                    return {
                        'total_vulnerabilities': total_vulns,
                        'critical_vulns': critical_count,
                        'high_vulns': high_count,
                        'medium_vulns': medium_count,
                        'low_vulns': low_count
                    }
        except Exception as e:
            logger.error(f"Error getting scan statistics: {e}")
        return {}
    
    def log_user_activity(self, username: str, action: str, details: Dict = None, 
                         ip_address: str = None, user_agent: str = None) -> bool:
        """Log user activity"""
        if not self.connected:
            return False
            
        try:
            with self.get_session() as session:
                activity = UserActivity(
                    username=username,
                    action=action,
                    details=details,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                session.add(activity)
                session.commit()
                return True
        except Exception as e:
            logger.error(f"Error logging user activity: {e}")
        return False

# Global database manager instance
db_manager = DatabaseManager()