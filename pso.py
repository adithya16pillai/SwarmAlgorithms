import numpy as np
from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
import random

class PSOLogAnalyzer:
    def __init__(self, 
                 n_particles: int = 30, 
                 max_iterations: int = 100,
                 w_init: float = 0.9, 
                 w_final: float = 0.4,
                 c1: float = 2.0, 
                 c2: float = 2.0):

        self.n_particles = n_particles
        self.max_iterations = max_iterations
        self.w_init = w_init
        self.w_final = w_final
        self.c1 = c1
        self.c2 = c2
        
        self.dimensions = 15
        
        self.security_patterns = {
            'high_risk_locations': [
                'North Korea', 'Russia', 'Iran', 'China', 'Syria',
                'Ukraine', 'Belarus', 'Iraq', 'Venezuela'
            ],
            'suspicious_ports': {
                'very_high': [445, 135, 139, 4444, 1433],  # SMB, RPC, MSSQL, etc.
                'high': [22, 23, 3389, 21],  # SSH, Telnet, RDP, FTP
                'medium': [25, 53, 5900, 8080, 8443]  # SMTP, DNS, VNC, HTTP
            },
            'suspicious_protocols': [
                'SMB', 'Telnet', 'RDP', 'FTP', 'IRC'
            ],
            'malicious_processes': [
                'mimikatz', 'pwdump', 'wceaux', 'lsass',
                'psexec', 'winexe', 'wmiexec', 'xmrig',
                'nmap', 'sqlmap', 'hydra', 'medusa'
            ],
            'suspicious_files': [
                'exe', 'dll', 'ps1', 'bat', 'sh', 'py', 'pl',
                'exploit', 'backdoor', 'trojan', 'keylog',
                'crack', 'hack', 'malware', 'ransom'
            ],
            'attack_events': [
                'lateral_movement', 'data_exfiltration', 
                'privilege_escalation', 'brute_force'
            ]
        }

    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not logs:
            return {
                "algorithm": "pso",
                "risk_score": 0.0,
                "findings": [],
                "security_trends": {},
                "optimization_path": []
            }
        
        features, log_mapping = self._extract_features(logs)
        
        if len(features) == 0:
            return {
                "algorithm": "pso",
                "risk_score": 0.0,
                "findings": [],
                "security_trends": {},
                "optimization_path": []
            }
            
        positions = np.random.uniform(0, 1, (self.n_particles, self.dimensions))
        velocities = np.random.uniform(-0.1, 0.1, (self.n_particles, self.dimensions))
        
        personal_best_positions = np.copy(positions)
        personal_best_scores = np.array([self._evaluate_fitness(pos, features) for pos in positions])
        
        global_best_idx = np.argmax(personal_best_scores)
        global_best_position = np.copy(personal_best_positions[global_best_idx])
        global_best_score = personal_best_scores[global_best_idx]
        
        optimization_path = [float(global_best_score)]
        
        for iteration in range(self.max_iterations):
            w = self.w_init - (self.w_init - self.w_final) * (iteration / self.max_iterations)
            
            for i in range(self.n_particles):
                r1, r2 = np.random.rand(2)
                cognitive_velocity = self.c1 * r1 * (personal_best_positions[i] - positions[i])
                social_velocity = self.c2 * r2 * (global_best_position - positions[i])
                
                velocities[i] = w * velocities[i] + cognitive_velocity + social_velocity
                
                velocities[i] = np.clip(velocities[i], -0.5, 0.5)
                
                positions[i] += velocities[i]
                
                positions[i] = np.clip(positions[i], 0, 1)
                
                current_score = self._evaluate_fitness(positions[i], features)
                
                if current_score > personal_best_scores[i]:
                    personal_best_scores[i] = current_score
                    personal_best_positions[i] = np.copy(positions[i])
                    
                    if current_score > global_best_score:
                        global_best_score = current_score
                        global_best_position = np.copy(positions[i])
            
            optimization_path.append(float(global_best_score))
            
            if iteration > 10 and abs(optimization_path[-1] - optimization_path[-10]) < 0.001:
                break
        
        risk_scores = self._calculate_risk_scores(global_best_position, features)
        
        threshold = 0.6
        high_risk_indices = np.where(risk_scores > threshold)[0]
        findings = []
        
        for idx in high_risk_indices:
            orig_idx = log_mapping[idx]
            log = logs[orig_idx]
            
            factor_scores = self._get_factor_scores(global_best_position, features[idx])
            findings.append({
                "log_index": orig_idx,
                "risk_score": float(risk_scores[idx]),
                "timestamp": log.get('timestamp', ''),
                "source_ip": log.get('source_ip', ''),
                "destination_ip": log.get('destination_ip', ''),
                "event_type": log.get('event_type', ''),
                "contributing_factors": self._get_contributing_factors(factor_scores, log)
            })
        
        findings.sort(key=lambda x: x["risk_score"], reverse=True)
        
        security_trends = self._analyze_security_trends(logs, global_best_position)
        
        overall_risk = self._calculate_overall_risk(risk_scores, findings)
        
        return {
            "algorithm": "pso",
            "risk_score": float(overall_risk),
            "findings": findings,
            "security_trends": security_trends,
            "optimization_path": optimization_path
        }

    def _extract_features(self, logs: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[int]]:
        features = []
        log_indices = []
        
        for i, log in enumerate(logs):
            feature_vector = np.zeros(self.dimensions)
            
            location = log.get('location', '')
            if location in self.security_patterns['high_risk_locations']:
                feature_vector[0] = 1.0
            
            src_ip = log.get('source_ip', '')
            if src_ip and not (src_ip.startswith('192.168.') or src_ip.startswith('10.')):
                feature_vector[1] = 1.0
                
            dst_ip = log.get('destination_ip', '')
            if dst_ip and not (dst_ip.startswith('192.168.') or dst_ip.startswith('10.')):
                feature_vector[2] = 0.7
                
            port = log.get('destination_port', 0)
            if port in self.security_patterns['suspicious_ports']['very_high']:
                feature_vector[3] = 1.0
            elif port in self.security_patterns['suspicious_ports']['high']:
                feature_vector[4] = 0.8
            elif port in self.security_patterns['suspicious_ports']['medium']:
                feature_vector[5] = 0.5
                
            protocol = log.get('protocol', '')
            if protocol in self.security_patterns['suspicious_protocols']:
                feature_vector[6] = 0.9
                
            process = log.get('process_name', '').lower()
            for malicious in self.security_patterns['malicious_processes']:
                if malicious in process:
                    feature_vector[7] = 1.0
                    break
                    
            filename = log.get('filename', '').lower()
            if filename:
                for susp in self.security_patterns['suspicious_files']:
                    if susp in filename:
                        feature_vector[8] = 0.8
                        break
                        
            event_type = log.get('event_type', '')
            if event_type in self.security_patterns['attack_events']:
                feature_vector[9] = 1.0
                
            status = log.get('status', '').lower()
            if status == 'failed':
                feature_vector[10] = 0.7
            
            if event_type == 'login' and status == 'failed':
                feature_vector[11] = 0.9
                
            bytes_sent = log.get('bytes_sent', 0)
            bytes_received = log.get('bytes_received', 0)
            
            if bytes_sent > 1000000:  
                feature_vector[12] = 0.8
                
            if bytes_received > 5000000:  
                feature_vector[13] = 0.6
                
            if bytes_received > 0 and bytes_sent / bytes_received > 10:
                feature_vector[14] = 0.7
            
            if np.sum(feature_vector) > 0:
                features.append(feature_vector)
                log_indices.append(i)
        
        return np.array(features), log_indices

    def _evaluate_fitness(self, position: np.ndarray, features: np.ndarray) -> float:
        if features.shape[0] == 0:
            return 0.0
            
        risk_scores = np.dot(features, position)
        
        max_score = np.max(risk_scores)
        if max_score > 0:
            risk_scores = risk_scores / max_score
                
        mean_score = np.mean(risk_scores)
        variance = np.var(risk_scores)
        
        skewness = 0
        if len(risk_scores) > 2:
            std = np.std(risk_scores)
            if std > 0:
                skewness = np.mean(((risk_scores - mean_score) / std) ** 3)
        
        high_threshold = 0.7
        medium_threshold = 0.4
        
        high_risk_ratio = np.mean(risk_scores > high_threshold)
        medium_risk_ratio = np.mean((risk_scores > medium_threshold) & (risk_scores <= high_threshold))
        
        threshold_quality = (1 - min(high_risk_ratio * 10, 1.0)) * 0.6 + medium_risk_ratio * 0.4
        
        feature_utilization = np.std(position) * -1 + 0.5  
        
        key_feature_indices = [0, 3, 7, 9]  
        key_feature_alignment = np.mean(position[key_feature_indices])
        
        fitness = (
            variance * 2.0 +                  # Reward separation between events
            max(0, skewness) * 1.0 +          # Reward positive skew
            threshold_quality * 3.0 +         # Reward good threshold properties
            feature_utilization * 1.0 +       # Reward balanced feature usage
            key_feature_alignment * 2.0       # Reward security-aligned weights
        )
        
        return fitness

    def _calculate_risk_scores(self, position: np.ndarray, features: np.ndarray) -> np.ndarray:
        scores = np.dot(features, position)
        
        max_score = np.max(scores)
        if max_score > 0:
            scores = scores / max_score
        
        return scores

    def _get_factor_scores(self, position: np.ndarray, feature_vector: np.ndarray) -> List[Tuple[int, float]]:
        factor_scores = [(i, position[i] * feature_vector[i]) for i in range(self.dimensions)]
        
        factor_scores.sort(key=lambda x: x[1], reverse=True)
        
        return factor_scores

    def _get_contributing_factors(self, factor_scores: List[Tuple[int, float]], log: Dict[str, Any]) -> List[Dict[str, Any]]:
        factors = []
        
        factor_descriptions = [
            "High-risk location",
            "External source IP",
            "External destination IP",
            "Very high-risk port",
            "High-risk port",
            "Medium-risk port",
            "Suspicious protocol",
            "Malicious process",
            "Suspicious file",
            "Attack event type",
            "Failed status",
            "Failed login attempt",
            "Large outbound data transfer",
            "Large inbound data transfer",
            "Unusual data transfer ratio"
        ]
        
        for idx, score in factor_scores:
            if score > 0.01:  
                detail = self._get_factor_detail(idx, log)
                factors.append({
                    "factor": factor_descriptions[idx],
                    "contribution": float(score),
                    "detail": detail
                })
        
        return factors[:5]  

    def _get_factor_detail(self, factor_idx: int, log: Dict[str, Any]) -> str:
        if factor_idx == 0:
            return f"Location: {log.get('location', 'Unknown')}"
        elif factor_idx == 1:
            return f"Source IP: {log.get('source_ip', 'Unknown')}"
        elif factor_idx == 2:
            return f"Destination IP: {log.get('destination_ip', 'Unknown')}"
        elif factor_idx in [3, 4, 5]:
            return f"Port: {log.get('destination_port', 'Unknown')}"
        elif factor_idx == 6:
            return f"Protocol: {log.get('protocol', 'Unknown')}"
        elif factor_idx == 7:
            return f"Process: {log.get('process_name', 'Unknown')}"
        elif factor_idx == 8:
            return f"File: {log.get('filename', 'Unknown')}"
        elif factor_idx == 9:
            return f"Event type: {log.get('event_type', 'Unknown')}"
        elif factor_idx in [10, 11]:
            return f"Status: {log.get('status', 'Unknown')}"
        elif factor_idx == 12:
            return f"Bytes sent: {log.get('bytes_sent', 'Unknown')}"
        elif factor_idx == 13:
            return f"Bytes received: {log.get('bytes_received', 'Unknown')}"
        else:
            return ""

    def _analyze_security_trends(self, logs: List[Dict[str, Any]], position: np.ndarray) -> Dict[str, Any]:
        hourly_data = {}
        event_distribution = {}
        ip_risk_scores = {}
        
        for log in logs:
            if 'timestamp' not in log:
                continue
                
            try:
                if log['timestamp'].endswith('Z'):
                    timestamp = log['timestamp'][:-1] + '+00:00'
                else:
                    timestamp = log['timestamp']
                    
                dt = datetime.fromisoformat(timestamp)
                hour_key = dt.strftime('%Y-%m-%d %H:00')
                
                if hour_key not in hourly_data:
                    hourly_data[hour_key] = {'count': 0, 'risks': []}
                
                hourly_data[hour_key]['count'] += 1
                
                risk_score = 0.0
                
                if log.get('location', '') in self.security_patterns['high_risk_locations']:
                    risk_score += position[0]
                    
                port = log.get('destination_port', 0)
                if port in self.security_patterns['suspicious_ports']['very_high']:
                    risk_score += position[3]
                elif port in self.security_patterns['suspicious_ports']['high']:
                    risk_score += position[4]
                    
                if log.get('event_type', '') in self.security_patterns['attack_events']:
                    risk_score += position[9]
                    
                if log.get('status', '').lower() == 'failed':
                    risk_score += position[10]
                
                hourly_data[hour_key]['risks'].append(risk_score)
                
                event_type = log.get('event_type', 'unknown')
                if event_type not in event_distribution:
                    event_distribution[event_type] = 0
                event_distribution[event_type] += 1
                
                src_ip = log.get('source_ip', '')
                if src_ip:
                    if src_ip not in ip_risk_scores:
                        ip_risk_scores[src_ip] = {'count': 0, 'risk_sum': 0.0}
                    ip_risk_scores[src_ip]['count'] += 1
                    ip_risk_scores[src_ip]['risk_sum'] += risk_score
                
            except (ValueError, TypeError):
                continue
        
        hourly_risks = []
        for hour, data in hourly_data.items():
            if data['risks']:
                avg_risk = sum(data['risks']) / len(data['risks'])
                hourly_risks.append({
                    'hour': hour,
                    'count': data['count'],
                    'avg_risk': float(avg_risk)
                })
        
        hourly_risks.sort(key=lambda x: x['hour'])
        
        risky_ips = []
        for ip, data in ip_risk_scores.items():
            avg_risk = data['risk_sum'] / data['count']
            risky_ips.append({
                'ip': ip,
                'count': data['count'],
                'avg_risk': float(avg_risk)
            })
        
        risky_ips.sort(key=lambda x: x['avg_risk'], reverse=True)
        
        return {
            'hourly_trends': hourly_risks,
            'event_distribution': [{'event': k, 'count': v} for k, v in event_distribution.items()],
            'risky_ips': risky_ips[:5]  
        }

    def _calculate_overall_risk(self, risk_scores: np.ndarray, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score based on individual log risk scores"""
        if len(risk_scores) == 0:
            return 0.0
            
        max_risk = np.max(risk_scores)
        
        high_risk_percentage = np.mean(risk_scores > 0.7)
        
        attack_pattern_factor = 0.0
        
        attack_events = [f for f in findings 
                         if f.get('event_type', '') in self.security_patterns['attack_events']]
        
        if len(attack_events) > 0:
            attack_pattern_factor = 0.3
            
        if len(findings) >= 3:
            attack_pattern_factor += 0.2
        
        overall_risk = (
            max_risk * 0.4 +
            min(1.0, high_risk_percentage * 3) * 0.3 +
            attack_pattern_factor * 0.3
        )
        
        return min(1.0, overall_risk)


if __name__ == "__main__":
    import json
    import sys
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        try:
            with open(log_file, 'r') as f:
                log_data = json.load(f)
                
            analyzer = PSOLogAnalyzer()
            results = analyzer.analyze(log_data.get('logs', []))
            
            print(json.dumps(results, indent=2))
            
        except Exception as e:
            print(f"Error: {str(e)}")
    else:
        print("Please provide a log file path")