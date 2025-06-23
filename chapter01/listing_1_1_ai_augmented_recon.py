import os
import time
import json
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ReconResult:
    """Stores reconnaissance findings"""
    target: str
    timestamp: str
    open_ports: List[int]
    subdomains: List[str]
    technologies: List[str]
    api_endpoints: List[str]
    potential_vulnerabilities: List[Dict[str, Any]]
    employees: List[Dict[str, str]]
    exposed_documents: List[str]
    attack_surface_score: float

class Agent:
    """Simulated AI Agent for reconnaissance"""
    def __init__(self, role: str, goal: str):
        self.role = role
        self.goal = goal
        self.findings = ReconResult(
            target="",
            timestamp=datetime.now().isoformat(),
            open_ports=[],
            subdomains=[],
            technologies=[],
            api_endpoints=[],
            potential_vulnerabilities=[],
            employees=[],
            exposed_documents=[],
            attack_surface_score=0.0
        )
        logger.info(f"Initialized {role} agent with goal: {goal}")
    
    def _simulate_port_scan(self, target: str) -> List[int]:
        """Simulates port scanning"""
        logger.info(f"Scanning ports for {target}...")
        time.sleep(1)  # Simulate network delay
        # Common ports that might be open
        possible_ports = [22, 80, 443, 3306, 5432, 8080, 8443, 9200, 27017]
        open_ports = [p for p in possible_ports if hash(target + str(p)) % 3 == 0]
        logger.info(f"Found {len(open_ports)} open ports")
        return open_ports
    
    def _simulate_subdomain_discovery(self, target: str) -> List[str]:
        """Simulates subdomain enumeration"""
        logger.info(f"Discovering subdomains for {target}...")
        time.sleep(1)
        subdomains = [
            f"www.{target}",
            f"api.{target}",
            f"admin.{target}",
            f"dev.{target}",
            f"staging.{target}",
            f"mail.{target}",
            f"vpn.{target}"
        ]
        # Randomly filter based on target hash
        found = [s for s in subdomains if hash(s) % 2 == 0]
        logger.info(f"Discovered {len(found)} subdomains")
        return found
    
    def _analyze_web_services(self, target: str, ports: List[int]) -> List[str]:
        """Simulates web service analysis"""
        logger.info("Analyzing web services...")
        time.sleep(0.5)
        technologies = []
        
        if 80 in ports or 443 in ports:
            technologies.extend(["nginx/1.18.0", "PHP/7.4.3"])
        if 8080 in ports:
            technologies.append("Apache Tomcat/9.0.46")
        if 3306 in ports:
            technologies.append("MySQL/5.7.34")
        if 5432 in ports:
            technologies.append("PostgreSQL/13.3")
        if 9200 in ports:
            technologies.append("Elasticsearch/7.13.2")
            
        logger.info(f"Identified {len(technologies)} technologies")
        return technologies
    
    def _discover_api_endpoints(self, subdomains: List[str]) -> List[str]:
        """Simulates API endpoint discovery"""
        logger.info("Discovering API endpoints...")
        time.sleep(0.5)
        endpoints = []
        
        for subdomain in subdomains:
            if "api" in subdomain:
                endpoints.extend([
                    f"https://{subdomain}/v1/users",
                    f"https://{subdomain}/v1/auth/login",
                    f"https://{subdomain}/v2/products",
                    f"https://{subdomain}/admin/config"
                ])
        
        logger.info(f"Found {len(endpoints)} API endpoints")
        return endpoints
    
    def _check_vulnerabilities(self, technologies: List[str]) -> List[Dict[str, Any]]:
        """Simulates vulnerability checking"""
        logger.info("Checking for known vulnerabilities...")
        time.sleep(0.5)
        vulns = []
        
        vuln_db = {
            "nginx/1.18.0": {"cve": "CVE-2021-23017", "severity": "Medium", "description": "DNS resolver vulnerability"},
            "PHP/7.4.3": {"cve": "CVE-2021-21702", "severity": "High", "description": "XXE vulnerability in SOAP"},
            "Elasticsearch/7.13.2": {"cve": "CVE-2021-22145", "severity": "Critical", "description": "Privilege escalation"}
        }
        
        for tech in technologies:
            if tech in vuln_db:
                vulns.append({
                    "technology": tech,
                    **vuln_db[tech]
                })
        
        logger.info(f"Identified {len(vulns)} potential vulnerabilities")
        return vulns
    
    def _discover_employees(self, target: str) -> List[Dict[str, str]]:
        """Simulates employee discovery (LinkedIn, etc.)"""
        logger.info("Discovering employee information...")
        time.sleep(0.5)
        
        # Simulated employee data
        employees = [
            {"name": "John Smith", "role": "DevOps Engineer", "profile": f"linkedin.com/in/jsmith-{target}"},
            {"name": "Sarah Johnson", "role": "Security Analyst", "profile": f"linkedin.com/in/sjohnson-{target}"},
            {"name": "Mike Chen", "role": "Backend Developer", "profile": f"linkedin.com/in/mchen-{target}"}
        ]
        
        logger.info(f"Found {len(employees)} employee profiles")
        return employees
    
    def _search_exposed_docs(self, target: str) -> List[str]:
        """Simulates searching for exposed documents"""
        logger.info("Searching for exposed documentation...")
        time.sleep(0.5)
        
        docs = [
            f"https://docs.{target}/internal/api-keys.pdf",
            f"https://wiki.{target}/architecture/database-schema.html",
            f"https://github.com/{target}/config/production.yml"
        ]
        
        # Randomly find some
        found = [d for d in docs if hash(d) % 2 == 0]
        logger.info(f"Found {len(found)} exposed documents")
        return found
    
    def _calculate_attack_surface(self, findings: ReconResult) -> float:
        """Calculates attack surface score"""
        score = 0.0
        score += len(findings.open_ports) * 2
        score += len(findings.subdomains) * 3
        score += len(findings.api_endpoints) * 5
        score += len(findings.potential_vulnerabilities) * 10
        score += len(findings.exposed_documents) * 8
        return min(score, 100.0)  # Cap at 100
    
    def run(self, target: str = "target.com") -> ReconResult:
        """Execute reconnaissance operation"""
        logger.info(f"Starting AI-augmented reconnaissance against {target}")
        self.findings.target = target
        
        # Phase 1: Port scanning
        self.findings.open_ports = self._simulate_port_scan(target)
        
        # Phase 2: Subdomain enumeration
        self.findings.subdomains = self._simulate_subdomain_discovery(target)
        
        # Phase 3: Technology identification
        self.findings.technologies = self._analyze_web_services(target, self.findings.open_ports)
        
        # Phase 4: API discovery
        self.findings.api_endpoints = self._discover_api_endpoints(self.findings.subdomains)
        
        # Phase 5: Vulnerability assessment
        self.findings.potential_vulnerabilities = self._check_vulnerabilities(self.findings.technologies)
        
        # Phase 6: OSINT - Employee discovery
        self.findings.employees = self._discover_employees(target)
        
        # Phase 7: Document search
        self.findings.exposed_documents = self._search_exposed_docs(target)
        
        # Phase 8: Calculate attack surface
        self.findings.attack_surface_score = self._calculate_attack_surface(self.findings)
        
        logger.info(f"Reconnaissance complete. Attack surface score: {self.findings.attack_surface_score}")
        return self.findings
    
    def generate_report(self) -> str:
        """Generate a formatted report of findings"""
        report = f"""
=== AI-AUGMENTED RECONNAISSANCE REPORT ===
Target: {self.findings.target}
Timestamp: {self.findings.timestamp}
Attack Surface Score: {self.findings.attack_surface_score}/100

DISCOVERED ASSETS:
- Open Ports: {len(self.findings.open_ports)} found
  {self.findings.open_ports}

- Subdomains: {len(self.findings.subdomains)} discovered
  {chr(10).join(self.findings.subdomains)}

- Technologies: {len(self.findings.technologies)} identified
  {chr(10).join(self.findings.technologies)}

- API Endpoints: {len(self.findings.api_endpoints)} found
  {chr(10).join(self.findings.api_endpoints[:3])}{"..." if len(self.findings.api_endpoints) > 3 else ""}

SECURITY FINDINGS:
- Potential Vulnerabilities: {len(self.findings.potential_vulnerabilities)}
  {json.dumps(self.findings.potential_vulnerabilities, indent=2)}

- Exposed Documents: {len(self.findings.exposed_documents)}
  {chr(10).join(self.findings.exposed_documents)}

- Employee Profiles: {len(self.findings.employees)}
  {json.dumps(self.findings.employees, indent=2)}

=== END REPORT ===
"""
        return report

# Main execution
if __name__ == "__main__":
    # Create reconnaissance agent
    recon_agent = Agent(
        role="security_researcher",
        goal="map attack surface of target.com"
    )
    
    # Run reconnaissance
    results = recon_agent.run("example-corp.com")
    
    # Generate and print report
    report = recon_agent.generate_report()
    print(report)
    
    # Save results to JSON
    with open("recon_results.json", "w") as f:
        json.dump(asdict(results), f, indent=2)
    
    logger.info("Results saved to recon_results.json")
