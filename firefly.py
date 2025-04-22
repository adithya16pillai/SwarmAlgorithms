import numpy as np
import random
from typing import Dict, List, Any, Tuple
from datetime import datetime
import math

class FireflyLogAnalyzer:
    def __init__(self,
                 n_fireflies: int = 25,
                 max_iterations: int = 50,
                 alpha: float = 0.5,     # Randomness parameter
                 alpha_decay: float = 0.97,
                 beta0: float = 1.0,     
                 gamma: float = 0.5):    
        self.n_fireflies = n_fireflies
        self.max_iterations = max_iterations
        self.alpha = alpha
        self.alpha_decay = alpha_decay
        self.beta0 = beta0
        self.gamma = gamma
        
        self.dimensions = 16
        
        self.security_indicators = {
            'high_risk_locations': [
                'North Korea', 'Russia', 'Iran', 'China', 'Syria',
                'Ukraine', 'Belarus', 'Iraq', 'Venezuela'
            ],
            
            'suspicious_ports': {
                'critical': [445, 135, 139, 1433, 1434],  # SMB, RPC, MSSQL
                'high': [22, 23, 3389, 5900, 137, 138],   # SSH, Telnet, RDP, VNC
                'medium': [21, 25, 110, 8080, 8443]       # FTP, SMTP, POP3, HTTP
            },
            
            'suspicious_protocols': [
                'SMB', 'Telnet', 'RDP', 'FTP', 'IRC'
            ],
            
            'malicious_processes': [
                'mimikatz', 'pwdump', 'psexec', 'lazagne', 'netcat',
                'wce', 'procdump', 'wmiexec', 'cain', 'hydra'
            ],
            
            'suspicious_files': [
                '.exe', '.dll', '.bat', '.ps1', '.vbs', '.js',
                'exploit', 'hack', 'crack', 'trojan', 'backdoor',
                'keylog', 'ransom', 'crypt', 'worm', 'rat'
            ],
            
            'attack_events': {
                'critical': ['data_exfiltration', 'lateral_movement', 'privilege_escalation'],
                'high': ['brute_force', 'file_download', 'port_scan'],
                'medium': ['login', 'access', 'network_scan']
            },
            
            'suspicious_hours': [0, 1, 2, 3, 4, 22, 23]  # Late night/early morning
        }
    
    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not logs:
            return {
                "algorithm": "firefly",
                "alert_score": 0.0,
                "critical_events": [],
                "suspicious_patterns": [],
                "optimization_convergence": []
            }
        
        features, log_mapping = self._extract_features(logs)
        
        if len(features) == 0:
            return {
                "algorithm": "firefly",
                "alert_score": 0.0,
                "critical_events": [],
                "suspicious_patterns": [],
                "optimization_convergence": []
            }
        
        fireflies = np.random.uniform(0, 1, (self.n_fireflies, self.dimensions))
        
        brightness = np.array([self._evaluate_fitness(pos, features) for pos in fireflies])
        
        best_idx = np.argmax(brightness)
        best_position = fireflies[best_idx].copy()
        best_fitness = brightness[best_idx]
        
        convergence = [float(best_fitness)]
        
        alpha = self.alpha
        for iteration in range(self.max_iterations):
            sorted_indices = np.argsort(-brightness)
            fireflies = fireflies[sorted_indices]
            brightness = brightness[sorted_indices]
            
            new_fireflies = np.copy(fireflies)
            
            for i in range(self.n_fireflies):
                for j in range(i+1, self.n_fireflies):
                    distance = np.linalg.norm(fireflies[i] - fireflies[j])
                    
                    beta = self.beta0 * math.exp(-self.gamma * distance**2)
                    
                    new_fireflies[j] += beta * (fireflies[i] - fireflies[j]) + \
                                      alpha * (np.random.rand(self.dimensions) - 0.5)
            
            new_fireflies = np.clip(new_fireflies, 0, 1)
            
            new_brightness = np.array([self._evaluate_fitness(pos, features) for pos in new_fireflies])
            
            fireflies = new_fireflies
            brightness = new_brightness
            
            current_best_idx = np.argmax(brightness)
            if brightness[current_best_idx] > best_fitness:
                best_position = fireflies[current_best_idx].copy()
                best_fitness = brightness[current_best_idx]
            
            convergence.append(float(best_fitness))
            
            alpha *= self.alpha_decay
            
            if iteration > 10 and abs(convergence[-1] - convergence[-10]) < 0.001:
                break
        
        alert_scores = self._calculate_alert_scores(best_position, features)
        
        threshold = 0.65
        critical_indices = np.where(alert_scores > threshold)[0]
        critical_events = []
        
        for idx in critical_indices:
            orig_idx = log_mapping[idx]
            log = logs[orig_idx]
            
            factor_scores = self._get_factor_contributions(best_position, features[idx])
            
            critical_events.append({
                "log_index": orig_idx,
                "alert_score": float(alert_scores[idx]),
                "timestamp": log.get('timestamp', ''),
                "source_ip": log.get('source_ip', ''),
                "destination_ip": log.get('destination_ip', ''),
                "port": log.get('destination_port', ''),
                "event_type": log.get('event_type', ''),
                "status": log.get('status', ''),
                "contributing_factors": self._describe_alert_factors(factor_scores, log)
            })
        
        critical_events.sort(key=lambda x: x["alert_score"], reverse=True)
        
        suspicious_patterns = self._identify_suspicious_patterns(logs, critical_events, best_position)
        
        overall_alert = self._calculate_overall_alert(alert_scores, critical_events, suspicious_patterns)
        
        return {
            "algorithm": "firefly",
            "alert_score": float(overall_alert),
            "critical_events": critical_events,
            "suspicious_patterns": suspicious_patterns,
            "optimization_convergence": convergence
        }
    
    def _extract_features(self, logs: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[int]]:
        features = []
        log_indices = []
        
        for i, log in enumerate(logs):
            feature_vector = np.zeros(self.dimensions)
            
            location = log.get('location', '')
            if location in self.security_indicators['high_risk_locations']:
                feature_vector[0] = 1.0
            
            timestamp = log.get('timestamp', '')
            if timestamp:
                try:
                    if timestamp.endswith('Z'):
                        timestamp = timestamp[:-1] + '+00:00'
                    dt = datetime.fromisoformat(timestamp)
                    if dt.hour in self.security_indicators['suspicious_hours']:
                        feature_vector[1] = 1.0
                except (ValueError, TypeError):
                    pass
            
            protocol = log.get('protocol', '')
            if protocol in self.security_indicators['suspicious_protocols']:
                feature_vector[2] = 1.0
            
            port = log.get('destination_port', 0)
            if port in self.security_indicators['suspicious_ports']['critical']:
                feature_vector[3] = 1.0
            elif port in self.security_indicators['suspicious_ports']['high']:
                feature_vector[4] = 1.0
            elif port in self.security_indicators['suspicious_ports']['medium']:
                feature_vector[5] = 1.0
            
            process = log.get('process_name', '').lower()
            if any(mal_proc in process for mal_proc in self.security_indicators['malicious_processes']):
                feature_vector[6] = 1.0
            
            filename = log.get('filename', '').lower()
            if any(susp_file in filename for susp_file in self.security_indicators['suspicious_files']):
                feature_vector[7] = 1.0
            
            event_type = log.get('event_type', '')
            if event_type in self.security_indicators['attack_events']['critical']:
                feature_vector[8] = 1.0
            elif event_type in self.security_indicators['attack_events']['high']:
                feature_vector[9] = 1.0
            elif event_type in self.security_indicators['attack_events']['medium']:
                feature_vector[10] = 1.0
            
            if log.get('status', '').lower() == 'failed':
                feature_vector[11] = 1.0
            
            src_ip = log.get('source_ip', '')
            dst_ip = log.get('destination_ip', '')
            if (src_ip and not src_ip.startswith(('10.', '172.16.', '192.168.'))) or \
               (dst_ip and not dst_ip.startswith(('10.', '172.16.', '192.168.'))):
                feature_vector[12] = 1.0
            
            bytes_sent = log.get('bytes_sent', 0)
            bytes_received = log.get('bytes_received', 0)
            if bytes_sent > 1000000 or bytes_received > 5000000 or \
               (bytes_received > 0 and bytes_sent / bytes_received > 10):
                feature_vector[13] = 1.0
            
            username = log.get('username', '').lower()
            if username in ['admin', 'administrator', 'root', 'system', 'superuser']:
                feature_vector[14] = 1.0
            
            if event_type == 'login' and log.get('status', '').lower() == 'failed':
                feature_vector[15] = 1.0
            
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
        variance = np.var(scores)
        
        skewness = 0.0
        if len(scores) > 2:
            std = np.std(scores)
            if std > 0:
                skewness = np.mean(((scores - mean) / std) ** 3)
        
        high_threshold = 0.7
        high_count = np.sum(scores > high_threshold)
        high_ratio = high_count / len(scores)
        
        ratio_quality = 0.0
        if high_ratio > 0 and high_ratio <= 0.15:
            ratio_quality = 1.0 - abs(0.07 - high_ratio) / 0.07
        elif high_ratio > 0.15:
            ratio_quality = max(0, 1.0 - (high_ratio - 0.15) * 5)
        
        critical_features = [0, 3, 6, 8, 11, 15]  # Location, critical ports, malicious process, critical events, failed status, auth risk
        critical_weight_sum = sum(position[i] for i in critical_features)
        total_weight_sum = sum(position)
        
        feature_alignment = critical_weight_sum / total_weight_sum if total_weight_sum > 0 else 0
        
        fitness = (
            variance * 2.0 +                  # Separation in scores
            max(0, skewness) * 1.5 +          # Positive skew
            ratio_quality * 3.0 +             # Good alert ratio
            feature_alignment * 2.5           # Critical feature alignment
        )
        
        return fitness
    
    def _calculate_alert_scores(self, position: np.ndarray, features: np.ndarray) -> np.ndarray:
        scores = np.dot(features, position)
        
        max_score = np.max(scores)
        if max_score > 0:
            scores = scores / max_score
        
        return scores
    
    def _get_factor_contributions(self, position: np.ndarray, feature_vector: np.ndarray) -> List[Tuple[int, float]]:
        contributions = [(i, position[i] * feature_vector[i]) 
                         for i in range(len(position))
                         if feature_vector[i] > 0]
        
        contributions.sort(key=lambda x: x[1], reverse=True)
        
        return contributions
    
    def _describe_alert_factors(self, factor_scores: List[Tuple[int, float]], log: Dict[str, Any]) -> List[Dict[str, Any]]:
        factor_descriptions = [
            "High-risk location",
            "Suspicious time (non-business hours)",
            "Suspicious protocol",
            "Critical port",
            "High-risk port",
            "Medium-risk port",
            "Malicious process detected",
            "Suspicious filename",
            "Critical security event",
            "High-risk security event",
            "Medium-risk security event",
            "Failed operation",
            "External IP communication",
            "Unusual data transfer",
            "Privileged username",
            "Failed authentication"
        ]
        
        factors = []
        for idx, score in factor_scores:
            if score > 0.01:  
                detail = self._get_specific_factor_detail(idx, log)
                
                factors.append({
                    "factor": factor_descriptions[idx],
                    "contribution": float(score),
                    "detail": detail
                })
        
        return factors[:5]  
    
    def _get_specific_factor_detail(self, factor_idx: int, log: Dict[str, Any]) -> str:
        if factor_idx == 0:
            return f"Source: {log.get('location', 'unknown')}"
        elif factor_idx == 1:
            try:
                timestamp = log.get('timestamp', '')
                if timestamp.endswith('Z'):
                    timestamp = timestamp[:-1] + '+00:00'
                dt = datetime.fromisoformat(timestamp)
                return f"Time: {dt.strftime('%H:%M:%S')}"
            except (ValueError, TypeError):
                return "Time: unknown"
        elif factor_idx == 2:
            return f"Protocol: {log.get('protocol', 'unknown')}"
        elif factor_idx in [3, 4, 5]:
            return f"Port: {log.get('destination_port', 'unknown')}"
        elif factor_idx == 6:
            return f"Process: {log.get('process_name', 'unknown')}"
        elif factor_idx == 7:
            return f"File: {log.get('filename', 'unknown')}"
        elif factor_idx in [8, 9, 10]:
            return f"Event: {log.get('event_type', 'unknown')}"
        elif factor_idx == 11:
            return f"Status: {log.get('status', 'unknown')}"
        elif factor_idx == 12:
            return f"Source IP: {log.get('source_ip', 'unknown')} → Dest IP: {log.get('destination_ip', 'unknown')}"
        elif factor_idx == 13:
            sent = log.get('bytes_sent', 0)
            received = log.get('bytes_received', 0)
            return f"Sent: {sent} bytes, Received: {received} bytes"
        elif factor_idx == 14:
            return f"Username: {log.get('username', 'unknown')}"
        elif factor_idx == 15:
            return f"Login failed for user: {log.get('username', 'unknown')}"
        else:
            return ""
    
    def _identify_suspicious_patterns(self, logs: List[Dict[str, Any]], 
                                    critical_events: List[Dict[str, Any]],
                                    best_position: np.ndarray) -> List[Dict[str, Any]]:
        patterns = []
        
        if len(critical_events) < 2:
            return patterns
        
        critical_indices = [event['log_index'] for event in critical_events]
        
        brute_force = self._detect_brute_force(logs, critical_indices)
        if brute_force:
            patterns.append(brute_force)
        
        exfiltration = self._detect_data_exfiltration(logs, critical_indices)
        if exfiltration:
            patterns.append(exfiltration)
        
        lateral_movement = self._detect_lateral_movement(logs, critical_indices)
        if lateral_movement:
            patterns.append(lateral_movement)
        
        scanning = self._detect_scanning(logs, critical_indices)
        if scanning:
            patterns.append(scanning)
            
        privesc = self._detect_privilege_escalation(logs, critical_indices)
        if privesc:
            patterns.append(privesc)
        
        return patterns
    
    def _detect_brute_force(self, logs: List[Dict[str, Any]], 
                           critical_indices: List[int]) -> Dict[str, Any]:
        failed_logins = [(i, logs[i]) for i in critical_indices 
                         if logs[i].get('event_type') == 'login' and 
                         logs[i].get('status', '').lower() == 'failed']
        
        ip_groups = {}
        for idx, log in failed_logins:
            src_ip = log.get('source_ip', '')
            if not src_ip:
                continue
                
            if src_ip not in ip_groups:
                ip_groups[src_ip] = []
            ip_groups[src_ip].append((idx, log))
        
        for ip, events in ip_groups.items():
            if len(events) >= 3:  
                return {
                    "pattern_type": "brute_force",
                    "severity": 0.8,
                    "source_ip": ip,
                    "count": len(events),
                    "log_indices": [idx for idx, _ in events],
                    "description": f"Multiple failed login attempts ({len(events)}) from {ip}"
                }
        
        return None
    
    def _detect_data_exfiltration(self, logs: List[Dict[str, Any]], 
                                critical_indices: List[int]) -> Dict[str, Any]:
        large_transfers = [(i, logs[i]) for i in critical_indices 
                         if logs[i].get('bytes_sent', 0) > 1000000]  # >1MB
        
        if large_transfers:
            total_bytes = sum(log.get('bytes_sent', 0) for _, log in large_transfers)
            return {
                "pattern_type": "data_exfiltration",
                "severity": 0.85,
                "total_bytes": total_bytes,
                "count": len(large_transfers),
                "log_indices": [idx for idx, _ in large_transfers],
                "description": f"Large outbound data transfer: {total_bytes / 1000000:.2f} MB in {len(large_transfers)} events"
            }
        
        return None
    
    def _detect_lateral_movement(self, logs: List[Dict[str, Any]], 
                               critical_indices: List[int]) -> Dict[str, Any]:
        lateral = [(i, logs[i]) for i in critical_indices 
                  if logs[i].get('event_type') == 'lateral_movement']
        
        if lateral:
            ips = set()
            for _, log in lateral:
                if log.get('source_ip'):
                    ips.add(log.get('source_ip'))
                if log.get('destination_ip'):
                    ips.add(log.get('destination_ip'))
            
            return {
                "pattern_type": "lateral_movement",
                "severity": 0.9,
                "involved_ips": list(ips),
                "count": len(lateral),
                "log_indices": [idx for idx, _ in lateral],
                "description": f"Lateral movement detected across {len(ips)} systems"
            }
        
        return None
    
    def _detect_scanning(self, logs: List[Dict[str, Any]], 
                       critical_indices: List[int]) -> Dict[str, Any]:
        port_scans = [(i, logs[i]) for i in critical_indices 
                     if logs[i].get('event_type') == 'port_scan']
        
        if port_scans:
            src_ips = set(log.get('source_ip', '') for _, log in port_scans)
            return {
                "pattern_type": "scanning",
                "severity": 0.75,
                "source_ips": list(src_ips),
                "count": len(port_scans),
                "log_indices": [idx for idx, _ in port_scans],
                "description": f"Port scanning detected from {len(src_ips)} source(s)"
            }
        
        return None
    
    def _detect_privilege_escalation(self, logs: List[Dict[str, Any]], 
                                   critical_indices: List[int]) -> Dict[str, Any]:
        privesc = [(i, logs[i]) for i in critical_indices 
                  if logs[i].get('event_type') == 'privilege_escalation']
        
        if privesc:
            return {
                "pattern_type": "privilege_escalation",
                "severity": 0.9,
                "count": len(privesc),
                "log_indices": [idx for idx, _ in privesc],
                "description": f"Privilege escalation detected in {len(privesc)} event(s)"
            }
        
        return None
    
    def _calculate_overall_alert(self, alert_scores: np.ndarray, 
                               critical_events: List[Dict[str, Any]],
                               suspicious_patterns: List[Dict[str, Any]]) -> float:
        if len(alert_scores) == 0:
            return 0.0
        
        max_score = np.max(alert_scores) if alert_scores.size > 0 else 0
        
        critical_percentage = len(critical_events) / len(alert_scores)
        critical_factor = min(1.0, critical_percentage * 5)  # Cap at 1.0
        
        pattern_severity = 0.0
        if suspicious_patterns:
            pattern_severity = max(pattern['severity'] for pattern in suspicious_patterns)
        
        overall_score = (
            max_score * 0.35 +
            critical_factor * 0.25 +
            pattern_severity * 0.4
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
                
            analyzer = FireflyLogAnalyzer()
            results = analyzer.analyze(log_data.get('logs', []))
            
            print(json.dumps(results, indent=2))
            
        except Exception as e:
            print(f"Error: {str(e)}")
    else:
        print("Please provide a log file path")