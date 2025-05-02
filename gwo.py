import numpy as np
from typing import Dict, List, Any, Tuple
from datetime import datetime
import random

class GWOLogAnalyzer:
    def __init__(self,
                 n_wolves: int = 30,
                 max_iterations: int = 50,
                 a_init: float = 2.0,  # Controls exploration vs. exploitation
                 domains: List[Tuple[float, float]] = None):
        self.n_wolves = n_wolves
        self.max_iterations = max_iterations
        self.a_init = a_init
        
        self.dimensions = 18
        self.domains = domains or [(0, 1) for _ in range(self.dimensions)]
        
        self.security_indicators = {
            'high_risk_locations': [
                'North Korea', 'Russia', 'Iran', 'China', 'Syria', 'Belarus'
            ],
            'medium_risk_locations': [
                'Ukraine', 'Iraq', 'Pakistan', 'Venezuela', 'Vietnam', 'Nigeria'
            ],
            'suspicious_ports': {
                'very_high': [445, 3389, 5900, 4444, 1433, 135, 139],
                'high': [22, 23, 21, 25, 3306],
                'medium': [80, 443, 8080, 8443, 53]
            },
            'suspicious_protocols': [
                'SMB', 'RDP', 'Telnet', 'SSH', 'FTP', 'VNC'
            ],
            'malicious_processes': [
                'mimikatz', 'psexec', 'pwdump', 'wce', 'procdump',
                'winexe', 'hydra', 'hashcat', 'netcat', 'nmap'
            ],
            'suspicious_files': [
                '.exe', '.dll', '.ps1', '.bat', '.vbs', '.js', '.hta',
                'exploit', 'hack', 'crack', 'trojan', 'backdoor', 'ransomware',
                'keylogger', 'worm', 'virus'
            ],
            'attack_events': [
                'lateral_movement', 'data_exfiltration', 'privilege_escalation',
                'brute_force', 'port_scan', 'file_download'
            ]
        }
        
    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not logs:
            return {
                "algorithm": "gwo",
                "threat_score": 0.0,
                "detected_threats": [],
                "hunting_progress": [],
                "top_vulnerabilities": []
            }
        
        features, log_indices = self._extract_features(logs)
        
        if len(features) == 0:
            return {
                "algorithm": "gwo",
                "threat_score": 0.0,
                "detected_threats": [],
                "hunting_progress": [],
                "top_vulnerabilities": []
            }
        
        positions = np.random.uniform(
            low=[domain[0] for domain in self.domains],
            high=[domain[1] for domain in self.domains],
            size=(self.n_wolves, self.dimensions)
        )
        
        alpha_score = float('-inf')
        alpha_pos = None
        beta_score = float('-inf')
        beta_pos = None
        delta_score = float('-inf')
        delta_pos = None
        
        hunting_progress = []
        
        for iteration in range(self.max_iterations):
            a = self.a_init - iteration * (self.a_init / self.max_iterations)
            
            for i in range(self.n_wolves):
                fitness = self._evaluate_fitness(positions[i], features)
                
                if fitness > alpha_score:
                    delta_score = beta_score
                    delta_pos = beta_pos
                    beta_score = alpha_score
                    beta_pos = alpha_pos
                    alpha_score = fitness
                    alpha_pos = positions[i].copy()
                elif fitness > beta_score:
                    delta_score = beta_score
                    delta_pos = beta_pos
                    beta_score = fitness
                    beta_pos = positions[i].copy()
                elif fitness > delta_score:
                    delta_score = fitness
                    delta_pos = positions[i].copy()
            
            hunting_progress.append(float(alpha_score))
            
            for i in range(self.n_wolves):
                for j in range(self.dimensions):
                    r1, r2 = np.random.rand(), np.random.rand()
                    A1 = 2 * a * r1 - a
                    C1 = 2 * r2
                    
                    r1, r2 = np.random.rand(), np.random.rand()
                    A2 = 2 * a * r1 - a
                    C2 = 2 * r2
                    
                    r1, r2 = np.random.rand(), np.random.rand()
                    A3 = 2 * a * r1 - a
                    C3 = 2 * r2
                    
                    D_alpha = abs(C1 * alpha_pos[j] - positions[i, j])
                    D_beta = abs(C2 * beta_pos[j] - positions[i, j])
                    D_delta = abs(C3 * delta_pos[j] - positions[i, j])
                    
                    X1 = alpha_pos[j] - A1 * D_alpha
                    X2 = beta_pos[j] - A2 * D_beta
                    X3 = delta_pos[j] - A3 * D_delta
                    
                    positions[i, j] = (X1 + X2 + X3) / 3
            
            positions = np.clip(positions, 
                               [domain[0] for domain in self.domains],
                               [domain[1] for domain in self.domains])
            
            if iteration > 10 and abs(hunting_progress[-1] - hunting_progress[-10]) < 0.001:
                break
        
        threat_scores = self._calculate_threat_scores(alpha_pos, features)
        
        threshold = 0.65
        threat_indices = np.where(threat_scores > threshold)[0]
        
        detected_threats = []
        for idx in threat_indices:
            orig_idx = log_indices[idx]
            log = logs[orig_idx]
            
            feature_contributions = self._calculate_feature_contributions(alpha_pos, features[idx])
            
            detected_threats.append({
                "log_index": int(orig_idx),
                "threat_score": float(threat_scores[idx]),
                "timestamp": log.get('timestamp', ''),
                "source_ip": log.get('source_ip', ''),
                "destination_ip": log.get('destination_ip', ''),
                "event_type": log.get('event_type', ''),
                "indicators": self._describe_threat_indicators(feature_contributions, log)
            })
        
        detected_threats.sort(key=lambda x: x["threat_score"], reverse=True)
        
        top_vulnerabilities = self._identify_top_vulnerabilities(alpha_pos, logs)
        
        overall_score = self._calculate_overall_threat(threat_scores, detected_threats)
        
        return {
            "algorithm": "gwo",
            "threat_score": float(overall_score),
            "detected_threats": detected_threats,
            "hunting_progress": hunting_progress,
            "top_vulnerabilities": top_vulnerabilities
        }

    def _extract_features(self, logs: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[int]]:
        features = []
        log_indices = []
        
        for i, log in enumerate(logs):
            if not log.get('source_ip') and not log.get('event_type'):
                continue
                
            feature_vector = np.zeros(self.dimensions)
            
            location = log.get('location', '')
            if location in self.security_indicators['high_risk_locations']:
                feature_vector[0] = 1.0
            
            elif location in self.security_indicators['medium_risk_locations']:
                feature_vector[1] = 0.5
            
            port = log.get('destination_port', 0)
            if port in self.security_indicators['suspicious_ports']['very_high']:
                feature_vector[2] = 1.0
            
            elif port in self.security_indicators['suspicious_ports']['high']:
                feature_vector[3] = 0.8
            
            elif port in self.security_indicators['suspicious_ports']['medium']:
                feature_vector[4] = 0.4
            
            protocol = log.get('protocol', '')
            if protocol in self.security_indicators['suspicious_protocols']:
                feature_vector[5] = 0.9
            
            process = log.get('process_name', '').lower()
            if any(mal_proc in process for mal_proc in self.security_indicators['malicious_processes']):
                feature_vector[6] = 1.0
            
            filename = log.get('filename', '').lower()
            if any(susp_file in filename for susp_file in self.security_indicators['suspicious_files']):
                feature_vector[7] = 0.9
            
            event_type = log.get('event_type', '')
            if event_type in self.security_indicators['attack_events']:
                feature_vector[8] = 1.0
            
            if log.get('status', '').lower() == 'failed':
                feature_vector[9] = 0.8
            
            src_ip = log.get('source_ip', '')
            if src_ip and not (src_ip.startswith('10.') or 
                           src_ip.startswith('192.168.') or 
                           (src_ip.startswith('172.') and 16 <= int(src_ip.split('.')[1]) <= 31)):
                feature_vector[10] = 0.7
            
            dst_ip = log.get('destination_ip', '')
            if dst_ip and not (dst_ip.startswith('10.') or 
                           dst_ip.startswith('192.168.') or 
                           (dst_ip.startswith('172.') and 16 <= int(dst_ip.split('.')[1]) <= 31)):
                feature_vector[11] = 0.7
            
            bytes_sent = log.get('bytes_sent', 0)
            if bytes_sent > 1000000:  # >1MB
                feature_vector[12] = 0.8
            
            bytes_received = log.get('bytes_received', 0)
            if bytes_received > 5000000:  # >5MB
                feature_vector[13] = 0.6
            
            if bytes_received > 0 and bytes_sent / bytes_received > 10:
                feature_vector[14] = 0.7
            
            timestamp = log.get('timestamp', '')
            if timestamp:
                try:
                    if timestamp.endswith('Z'):
                        timestamp = timestamp[:-1] + '+00:00'
                    dt = datetime.fromisoformat(timestamp)
                    if dt.hour < 6 or dt.hour >= 20:
                        feature_vector[15] = 0.5
                except (ValueError, TypeError):
                    pass
            
            username = log.get('username', '').lower()
            if username in ['admin', 'administrator', 'root', 'system', 'superuser']:
                feature_vector[16] = 0.6
            
            if event_type == 'login' and log.get('status', '').lower() == 'failed':
                feature_vector[17] = 0.8
            
            if np.sum(feature_vector) > 0:
                features.append(feature_vector)
                log_indices.append(i)
        
        return np.array(features), log_indices

    def _evaluate_fitness(self, position: np.ndarray, features: np.ndarray) -> float:
        if features.shape[0] == 0:
            return 0.0
            
        scores = np.dot(features, position)
        
        max_score = np.max(scores)
        if max_score > 0:
            scores = scores / max_score
        
        mean = np.mean(scores)
        std_dev = np.std(scores)
        variance = np.var(scores)
        
        skewness = 0.0
        if len(scores) > 2 and std_dev > 0:
            skewness = np.mean(((scores - mean) / std_dev) ** 3)
        
        high_threshold = 0.7
        high_ratio = np.mean(scores > high_threshold)
        
        ratio_score = 0.0
        if high_ratio > 0:
            if high_ratio <= 0.1:
                ratio_score = 1.0 - abs(0.075 - high_ratio) / 0.075
            else:
                ratio_score = max(0, 1.0 - (high_ratio - 0.1) * 5)
        
        critical_features = [0, 2, 6, 8, 9, 17]  # High-risk location, ports, malicious process, attack events, failed status, failed login
        critical_weight = np.mean(position[critical_features])
        weight_balance = critical_weight / np.mean(position) if np.mean(position) > 0 else 0
        
        fitness = (
            variance * 2.5 +                  # Reward separation between events
            max(0, skewness) * 1.5 +          # Reward positive skew
            ratio_score * 3.0 +               # Reward appropriate ratio
            weight_balance * 2.0              # Reward weighting critical features
        )
        
        return fitness

    def _calculate_threat_scores(self, position: np.ndarray, features: np.ndarray) -> np.ndarray:
        scores = np.dot(features, position)
        
        max_score = np.max(scores)
        if max_score > 0:
            scores = scores / max_score
        
        return scores

    def _calculate_feature_contributions(self, position: np.ndarray, feature_vector: np.ndarray) -> List[Tuple[int, float]]:
        contributions = [(i, position[i] * feature_vector[i]) 
                         for i in range(len(position))
                         if feature_vector[i] > 0]
        
        contributions.sort(key=lambda x: x[1], reverse=True)
        
        return contributions

    def _describe_threat_indicators(self, feature_contributions: List[Tuple[int, float]], log: Dict[str, Any]) -> List[Dict[str, Any]]:
        feature_descriptions = [
            "High-risk location",
            "Medium-risk location",
            "Very high-risk port",
            "High-risk port",
            "Medium-risk port",
            "Suspicious protocol",
            "Malicious process detected",
            "Suspicious filename",
            "Known attack event type",
            "Failed operation status",
            "External source IP",
            "External destination IP",
            "Large outbound data transfer",
            "Large inbound data transfer",
            "Unusual data transfer ratio",
            "Off-hours activity",
            "Admin/system username",
            "Failed login attempt"
        ]
        
        indicators = []
        for idx, contribution in feature_contributions:
            if contribution > 0.01:  # Skip negligible contributions
                detail = self._get_indicator_detail(idx, log)
                
                indicators.append({
                    "indicator": feature_descriptions[idx],
                    "contribution": float(contribution),
                    "detail": detail
                })
        
        return indicators[:5]

    def _get_indicator_detail(self, feature_idx: int, log: Dict[str, Any]) -> str:
        if feature_idx in [0, 1]:
            return f"Location: {log.get('location', 'unknown')}"
        elif feature_idx in [2, 3, 4]:
            return f"Port: {log.get('destination_port', 'unknown')}"
        elif feature_idx == 5:
            return f"Protocol: {log.get('protocol', 'unknown')}"
        elif feature_idx == 6:
            return f"Process: {log.get('process_name', 'unknown')}"
        elif feature_idx == 7:
            return f"File: {log.get('filename', 'unknown')}"
        elif feature_idx == 8:
            return f"Event: {log.get('event_type', 'unknown')}"
        elif feature_idx == 9:
            return f"Status: {log.get('status', 'unknown')}"
        elif feature_idx == 10:
            return f"Source IP: {log.get('source_ip', 'unknown')}"
        elif feature_idx == 11:
            return f"Destination IP: {log.get('destination_ip', 'unknown')}"
        elif feature_idx == 12:
            return f"Bytes sent: {log.get('bytes_sent', 'unknown')}"
        elif feature_idx == 13:
            return f"Bytes received: {log.get('bytes_received', 'unknown')}"
        elif feature_idx == 14:
            bytes_sent = log.get('bytes_sent', 0)
            bytes_received = log.get('bytes_received', 1)  # Avoid division by zero
            return f"Ratio: {bytes_sent/bytes_received:.2f} (sent/received)"
        elif feature_idx == 15:
            try:
                timestamp = log.get('timestamp', '')
                if timestamp.endswith('Z'):
                    timestamp = timestamp[:-1] + '+00:00'
                dt = datetime.fromisoformat(timestamp)
                return f"Time: {dt.strftime('%H:%M:%S')}"
            except (ValueError, TypeError):
                return "Time: unknown"
        elif feature_idx == 16:
            return f"Username: {log.get('username', 'unknown')}"
        elif feature_idx == 17:
            return f"Failed login by: {log.get('username', 'unknown')}"
        else:
            return ""

    def _identify_top_vulnerabilities(self, position: np.ndarray, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        top_indices = np.argsort(position)[::-1][:5]  # Top 5 features
        
        categories = {
            "Network Access": [2, 3, 4, 5, 10, 11],       # Ports, protocols, external IPs
            "Authentication": [9, 16, 17],                # Failed status, admin user, failed login
            "Malicious Activity": [6, 7, 8],             # Process, file, event type
            "Data Transfer": [12, 13, 14],               # Bytes sent/received, ratio
            "Geographic Risk": [0, 1],                   # High/medium risk locations
            "Temporal Patterns": [15]                    # Off-hours
        }
        
        category_scores = {}
        for category, indices in categories.items():
            score = sum(position[idx] for idx in indices if idx in top_indices)
            if score > 0:
                category_scores[category] = score
        
        vulnerabilities = []
        for category, score in sorted(category_scores.items(), key=lambda x: x[1], reverse=True):
            relevant_indices = []
            
            for i, log in enumerate(logs):
                if category == "Network Access":
                    port = log.get('destination_port', 0)
                    protocol = log.get('protocol', '')
                    if (port in self.security_indicators['suspicious_ports']['very_high'] or
                        port in self.security_indicators['suspicious_ports']['high'] or
                        protocol in self.security_indicators['suspicious_protocols']):
                        relevant_indices.append(i)
                        
                elif category == "Authentication":
                    if (log.get('status', '').lower() == 'failed' or
                        log.get('event_type') == 'login' and log.get('status', '').lower() == 'failed'):
                        relevant_indices.append(i)
                        
                elif category == "Malicious Activity":
                    process = log.get('process_name', '').lower()
                    filename = log.get('filename', '').lower()
                    event = log.get('event_type', '')
                    if (any(mal_proc in process for mal_proc in self.security_indicators['malicious_processes']) or
                        any(susp_file in filename for susp_file in self.security_indicators['suspicious_files']) or
                        event in self.security_indicators['attack_events']):
                        relevant_indices.append(i)
                        
                elif category == "Data Transfer":
                    bytes_sent = log.get('bytes_sent', 0)
                    bytes_received = log.get('bytes_received', 0)
                    if bytes_sent > 1000000 or bytes_received > 5000000:
                        relevant_indices.append(i)
                        
                elif category == "Geographic Risk":
                    location = log.get('location', '')
                    if location in self.security_indicators['high_risk_locations'] or \
                       location in self.security_indicators['medium_risk_locations']:
                        relevant_indices.append(i)
                        
                elif category == "Temporal Patterns":
                    timestamp = log.get('timestamp', '')
                    if timestamp:
                        try:
                            if timestamp.endswith('Z'):
                                timestamp = timestamp[:-1] + '+00:00'
                            dt = datetime.fromisoformat(timestamp)
                            if dt.hour < 6 or dt.hour >= 20:
                                relevant_indices.append(i)
                        except (ValueError, TypeError):
                            pass
            
            example_indices = relevant_indices[:3] if relevant_indices else []
            
            vulnerabilities.append({
                "category": category,
                "score": float(score),
                "example_logs": example_indices,
                "recommendation": self._get_recommendation(category)
            })
        
        return vulnerabilities[:3]  # Return top 3 vulnerability categories

    def _get_recommendation(self, category: str) -> str:
        recommendations = {
            "Network Access": "Implement stricter firewall rules and limit access to high-risk ports. Consider implementing network segmentation.",
            "Authentication": "Strengthen password policies and implement multi-factor authentication. Monitor failed login attempts.",
            "Malicious Activity": "Deploy endpoint protection solutions and monitor for suspicious processes and files.",
            "Data Transfer": "Monitor data flows and implement data loss prevention solutions to detect unusual transfers.",
            "Geographic Risk": "Review and limit connections from high-risk geographic locations.",
            "Temporal Patterns": "Implement stricter access controls during non-business hours and investigate off-hours activities."
        }
        
        return recommendations.get(category, "Review security controls and implement defense-in-depth strategies.")

    def _calculate_overall_threat(self, threat_scores: np.ndarray, detected_threats: List[Dict[str, Any]]) -> float:
        if len(threat_scores) == 0:
            return 0.0
            
        max_threat = np.max(threat_scores) if threat_scores.size > 0 else 0
        
        threat_percentage = np.mean(threat_scores > 0.7)
        threat_factor = min(1.0, threat_percentage * 5)  # Cap at 1.0
        
        severity_factor = 0.0
        if detected_threats:
            critical_events = [
                t for t in detected_threats 
                if t.get('event_type', '') in ['lateral_movement', 'data_exfiltration', 'privilege_escalation']
            ]
            
            if critical_events:
                severity_factor += 0.5
                
            if len(detected_threats) >= 3:
                severity_factor += 0.3
                
            if any(t['threat_score'] > 0.85 for t in detected_threats):
                severity_factor += 0.2
                
            severity_factor = min(1.0, severity_factor)
        
        overall_score = (
            max_threat * 0.3 +
            threat_factor * 0.3 +
            severity_factor * 0.4
        )
        
        return min(1.0, overall_score)


if __name__ == "__main__":
    import json
    import sys
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        try:
            with open(log_file, 'r') as f:
                log_data = json.load(f)
                
            analyzer = GWOLogAnalyzer()
            results = analyzer.analyze(log_data.get('logs', []))
            
            print(json.dumps(results, indent=2))
            
        except Exception as e:
            print(f"Error: {str(e)}")
    else:
        print("Please provide a log file path")