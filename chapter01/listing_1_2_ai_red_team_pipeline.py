import json
import time
import random
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    id: str
    type: str
    severity: str
    description: str
    exploit_available: bool
    access_level: str = "none"

@dataclass
class Access:
    """Represents gained access to a system"""
    system_id: str
    access_type: str
    privileges: str
    persistence: bool = False

@dataclass
class SensitiveData:
    """Represents discovered sensitive data"""
    data_type: str
    size_mb: float
    value_score: int  # 1-10
    location: str

class ReconnaissanceAI:
    """AI agent for reconnaissance phase"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def map_target(self, target: str) -> Dict[str, Any]:
        """Map the attack surface of the target"""
        self.logger.info(f"Starting reconnaissance on {target}")
        time.sleep(1)  # Simulate reconnaissance time
        
        attack_surface = {
            "target": target,
            "discovered_at": datetime.now().isoformat(),
            "systems": [
                {"id": "web-01", "type": "web_server", "technology": "nginx", "exposed": True},
                {"id": "api-01", "type": "api_server", "technology": "nodejs", "exposed": True},
                {"id": "db-01", "type": "database", "technology": "postgresql", "exposed": False},
                {"id": "admin-01", "type": "admin_panel", "technology": "django", "exposed": True}
            ],
            "network_info": {
                "external_ips": ["203.0.113.1", "203.0.113.2"],
                "internal_ranges": ["10.0.0.0/24", "172.16.0.0/24"]
            },
            "discovered_users": ["admin", "developer", "john.doe", "test_user"]
        }
        
        self.logger.info(f"Discovered {len(attack_surface['systems'])} systems")
        return attack_surface

class ExploitationAI:
    """AI agent for vulnerability analysis and exploitation"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def analyze(self, attack_surface: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze systems for vulnerabilities"""
        self.logger.info("Analyzing attack surface for vulnerabilities")
        time.sleep(1)
        
        vulnerabilities = []
        vuln_database = {
            "nginx": [
                Vulnerability("VULN-001", "misconfiguration", "medium", 
                            "Directory listing enabled", True),
                Vulnerability("VULN-002", "outdated_software", "high", 
                            "Nginx 1.14 - known CVEs", True)
            ],
            "nodejs": [
                Vulnerability("VULN-003", "injection", "critical", 
                            "SQL injection in login endpoint", True),
                Vulnerability("VULN-004", "authentication", "high", 
                            "Weak JWT secret", True)
            ],
            "django": [
                Vulnerability("VULN-005", "default_creds", "critical", 
                            "Default admin credentials", True)
            ]
        }
        
        for system in attack_surface["systems"]:
            tech = system["technology"]
            if tech in vuln_database:
                for vuln in vuln_database[tech]:
                    vuln.access_level = system["id"]
                    vulnerabilities.append(vuln)
        
        self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def exploit(self, vuln: Vulnerability) -> Optional[Access]:
        """Attempt to exploit a vulnerability"""
        self.logger.info(f"Attempting to exploit {vuln.id}: {vuln.description}")
        time.sleep(0.5)
        
        # Simulate exploitation success rate
        if vuln.exploit_available and random.random() > 0.2:  # 80% success rate
            access_types = {
                "injection": "shell",
                "default_creds": "admin_panel",
                "misconfiguration": "file_read",
                "authentication": "api_access",
                "outdated_software": "remote_shell"
            }
            
            privileges = "root" if vuln.severity == "critical" else "user"
            
            access = Access(
                system_id=vuln.access_level,
                access_type=access_types.get(vuln.type, "limited"),
                privileges=privileges
            )
            
            self.logger.info(f"Successfully exploited {vuln.id} - gained {access.access_type} access")
            return access
        else:
            self.logger.warning(f"Failed to exploit {vuln.id}")
            return None

class PersistenceAI:
    """AI agent for establishing persistence"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def establish(self, access: Access) -> Access:
        """Establish persistence on compromised system"""
        self.logger.info(f"Establishing persistence on {access.system_id}")
        time.sleep(0.5)
        
        persistence_methods = {
            "shell": "crontab backdoor",
            "admin_panel": "create hidden admin user",
            "api_access": "inject API key",
            "remote_shell": "install rootkit"
        }
        
        method = persistence_methods.get(access.access_type, "web shell")
        access.persistence = True
        
        self.logger.info(f"Persistence established using: {method}")
        return access

class ExfiltrationAI:
    """AI agent for data discovery and exfiltration"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def extract(self, access: Access) -> List[SensitiveData]:
        """Discover and extract sensitive data"""
        self.logger.info(f"Searching for sensitive data via {access.system_id}")
        time.sleep(1)
        
        sensitive_data = []
        
        # Simulate data discovery based on access type
        if access.privileges == "root":
            sensitive_data.extend([
                SensitiveData("customer_database", 523.4, 10, "/var/lib/mysql/customers.db"),
                SensitiveData("source_code", 89.2, 8, "/opt/app/src/"),
                SensitiveData("api_keys", 0.1, 9, "/etc/app/config.json"),
                SensitiveData("employee_records", 45.7, 7, "/home/hr/records/")
            ])
        else:
            sensitive_data.extend([
                SensitiveData("config_files", 2.3, 5, "/etc/app/"),
                SensitiveData("log_files", 156.8, 3, "/var/log/")
            ])
        
        self.logger.info(f"Discovered {len(sensitive_data)} sensitive data sources")
        return sensitive_data

class ReportingAI:
    """AI agent for report generation"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def generate_report(self, attack_surface: Dict[str, Any], 
                       vulnerabilities: List[Vulnerability],
                       sensitive_data: List[SensitiveData]) -> Dict[str, Any]:
        """Generate comprehensive attack report"""
        self.logger.info("Generating red team report")
        
        report = {
            "report_id": f"RT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "target": attack_surface["target"],
            "execution_time": datetime.now().isoformat(),
            "executive_summary": {
                "systems_discovered": len(attack_surface["systems"]),
                "vulnerabilities_found": len(vulnerabilities),
                "critical_vulns": len([v for v in vulnerabilities if v.severity == "critical"]),
                "data_exfiltrated_mb": sum(d.size_mb for d in sensitive_data),
                "highest_value_data": max(sensitive_data, key=lambda x: x.value_score).data_type if sensitive_data else "none"
            },
            "attack_narrative": self._generate_narrative(vulnerabilities, sensitive_data),
            "recommendations": self._generate_recommendations(vulnerabilities),
            "detailed_findings": {
                "attack_surface": attack_surface,
                "vulnerabilities": [vars(v) for v in vulnerabilities],
                "sensitive_data": [vars(d) for d in sensitive_data]
            }
        }
        
        self.logger.info("Report generation complete")
        return report
    
    def _generate_narrative(self, vulns: List[Vulnerability], data: List[SensitiveData]) -> str:
        """Generate attack narrative"""
        narrative = "The red team operation began with comprehensive reconnaissance, "
        narrative += f"identifying {len(vulns)} vulnerabilities across multiple systems. "
        
        critical_vulns = [v for v in vulns if v.severity == "critical"]
        if critical_vulns:
            narrative += f"Of particular concern were {len(critical_vulns)} critical vulnerabilities, "
            narrative += f"including {critical_vulns[0].description}. "
        
        if data:
            total_size = sum(d.size_mb for d in data)
            narrative += f"The team successfully identified and accessed {total_size:.1f}MB of sensitive data, "
            narrative += f"with the most valuable being {max(data, key=lambda x: x.value_score).data_type}."
        
        return narrative
    
    def _generate_recommendations(self, vulns: List[Vulnerability]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        vuln_types = set(v.type for v in vulns)
        
        if "default_creds" in vuln_types:
            recommendations.append("Immediately change all default credentials and implement strong password policies")
        if "injection" in vuln_types:
            recommendations.append("Implement input validation and parameterized queries across all applications")
        if "outdated_software" in vuln_types:
            recommendations.append("Establish a regular patching schedule and update all outdated software")
        if "misconfiguration" in vuln_types:
            recommendations.append("Conduct security configuration reviews and harden all systems")
        if "authentication" in vuln_types:
            recommendations.append("Strengthen authentication mechanisms and implement multi-factor authentication")
        
        return recommendations

class AIRedTeamPipeline:
    """Main pipeline orchestrating all AI agents"""
    
    def __init__(self):
        self.recon_agent = ReconnaissanceAI()
        self.exploit_agent = ExploitationAI()
        self.persistence_agent = PersistenceAI()
        self.exfil_agent = ExfiltrationAI()
        self.report_agent = ReportingAI()
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def execute_operation(self, target: str) -> Dict[str, Any]:
        """Execute full red team operation"""
        self.logger.info(f"Initiating AI Red Team operation against {target}")
        start_time = time.time()
        
        # Phase 1: Reconnaissance
        self.logger.info("=== Phase 1: Reconnaissance ===")
        attack_surface = self.recon_agent.map_target(target)
        
        # Phase 2: Vulnerability Analysis
        self.logger.info("=== Phase 2: Vulnerability Analysis ===")
        vulnerabilities = self.exploit_agent.analyze(attack_surface)
        
        # Phase 3: Exploitation
        self.logger.info("=== Phase 3: Exploitation ===")
        successful_exploits = []
        for vuln in vulnerabilities:
            if access := self.exploit_agent.exploit(vuln):
                successful_exploits.append(access)
                
                # Phase 4: Persistence
                self.logger.info("=== Phase 4: Establishing Persistence ===")
                self.persistence_agent.establish(access)
        
        # Phase 5: Data Exfiltration
        self.logger.info("=== Phase 5: Data Exfiltration ===")
        all_sensitive_data = []
        for access in successful_exploits:
            sensitive_data = self.exfil_agent.extract(access)
            all_sensitive_data.extend(sensitive_data)
        
        # Phase 6: Reporting
        self.logger.info("=== Phase 6: Report Generation ===")
        report = self.report_agent.generate_report(
            attack_surface, vulnerabilities, all_sensitive_data
        )
        
        # Add execution metrics
        execution_time = time.time() - start_time
        report["metrics"] = {
            "execution_time_seconds": execution_time,
            "exploitation_success_rate": len(successful_exploits) / len(vulnerabilities) if vulnerabilities else 0,
            "systems_compromised": len(set(a.system_id for a in successful_exploits))
        }
        
        self.logger.info(f"Operation complete in {execution_time:.2f} seconds")
        return report

# Main execution
if __name__ == "__main__":
    # Create pipeline
    pipeline = AIRedTeamPipeline()
    
    # Execute operation
    target = "example-corp.com"
    report = pipeline.execute_operation(target)
    
    # Save report
    report_filename = f"red_team_report_{report['report_id']}.json"
    with open(report_filename, "w") as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\n" + "="*50)
    print("AI RED TEAM OPERATION SUMMARY")
    print("="*50)
    print(f"Target: {report['target']}")
    print(f"Report ID: {report['report_id']}")
    print(f"Execution Time: {report['metrics']['execution_time_seconds']:.2f} seconds")
    print(f"\nFindings:")
    print(f"- Systems Discovered: {report['executive_summary']['systems_discovered']}")
    print(f"- Vulnerabilities Found: {report['executive_summary']['vulnerabilities_found']}")
    print(f"- Critical Vulnerabilities: {report['executive_summary']['critical_vulns']}")
    print(f"- Data Exfiltrated: {report['executive_summary']['data_exfiltrated_mb']:.1f} MB")
    print(f"- Success Rate: {report['metrics']['exploitation_success_rate']*100:.1f}%")
    print(f"\nFull report saved to: {report_filename}")
    print("="*50)
