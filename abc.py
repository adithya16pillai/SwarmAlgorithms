import numpy as np
import random
from typing import Dict, List, Any, Tuple

class ABCLogAnalyzer:
    def __init__(self, colony_size: int = 20, max_iterations: int = 50, limit: int = 10):
        self.colony_size = colony_size
        self.max_iterations = max_iterations
        self.limit = limit
        
        self.suspicious_patterns = {
            'location_risk': {
                'high': ['North Korea', 'Russia', 'Iran', 'China', 'Syria'],
                'medium': ['Ukraine', 'Belarus', 'Iraq', 'Pakistan', 'Nigeria']
            },
            'port_risk': {
                'high': [22, 23, 3389, 445, 135, 139, 8080, 1433, 3306],
                'medium': [21, 8443, 5900, 5901, 6667]
            },
            'protocol_risk': {
                'high': ['SMB', 'Telnet', 'RDP', 'SSH'],
                'medium': ['FTP', 'IRC']
            },
            'process_risk': {
                'high': ['ssh_brute', 'mal_downloader', 'worm.exe', 'mimikatz', 'pwdump'],
                'medium': ['scan', 'crack', 'exploit', 'admin']
            },
            'event_risk': {
                'high': ['lateral_movement', 'data_exfiltration', 'privilege_escalation'],
                'medium': ['port_scan', 'brute_force']
            }
        }
        
    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not logs:
            return {
                "algorithm": "abc",
                "anomaly_score": 0.0,
                "detected_anomalies": [],
                "confidence": 0.0
            }
            
        feature_vectors = self._extract_features(logs)
        
        food_sources = self._initialize_food_sources(feature_vectors)
        
        trials = [0] * len(food_sources)
        best_solution = None
        best_fitness = 0
        
        for iteration in range(self.max_iterations):
            for i in range(len(food_sources)):
                new_solution = self._produce_new_solution(food_sources, i, feature_vectors)
                new_fitness = self._calculate_fitness(new_solution, feature_vectors)
                current_fitness = self._calculate_fitness(food_sources[i], feature_vectors)
                
                if new_fitness > current_fitness:
                    food_sources[i] = new_solution
                    trials[i] = 0
                else:
                    trials[i] += 1
            
            fitness_values = [self._calculate_fitness(source, feature_vectors) for source in food_sources]
            sum_fitness = sum(fitness_values)
            probabilities = [fitness / sum_fitness if sum_fitness > 0 else 1.0/len(fitness_values) for fitness in fitness_values]
            
            i = 0
            count = 0
            while count < len(food_sources):
                if random.random() < probabilities[i]:
                    count += 1
                    new_solution = self._produce_new_solution(food_sources, i, feature_vectors)
                    new_fitness = self._calculate_fitness(new_solution, feature_vectors)
                    current_fitness = self._calculate_fitness(food_sources[i], feature_vectors)
                    
                    if new_fitness > current_fitness:
                        food_sources[i] = new_solution
                        trials[i] = 0
                    else:
                        trials[i] += 1
                        
                i = (i + 1) % len(food_sources)
            
            for i in range(len(trials)):
                if trials[i] > self.limit:
                    food_sources[i] = self._generate_random_solution(feature_vectors)
                    trials[i] = 0
            
            current_best_idx = np.argmax(fitness_values)
            current_best_fitness = fitness_values[current_best_idx]
            
            if best_solution is None or current_best_fitness > best_fitness:
                best_solution = food_sources[current_best_idx]
                best_fitness = current_best_fitness
        
        anomaly_score, detected_anomalies = self._evaluate_best_solution(best_solution, logs, feature_vectors)
        
        return {
            "algorithm": "abc",
            "anomaly_score": anomaly_score,
            "detected_anomalies": detected_anomalies,
            "confidence": best_fitness
        }
        
    def _extract_features(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        features = np.zeros((len(logs), 8))
        
        for i, log in enumerate(logs):
            location = log.get('location', '')
            if location in self.suspicious_patterns['location_risk']['high']:
                features[i, 0] = 1.0
            elif location in self.suspicious_patterns['location_risk']['medium']:
                features[i, 0] = 0.5
                
            dest_port = log.get('destination_port', 0)
            if dest_port in self.suspicious_patterns['port_risk']['high']:
                features[i, 1] = 1.0
            elif dest_port in self.suspicious_patterns['port_risk']['medium']:
                features[i, 1] = 0.5
                
            protocol = log.get('protocol', '')
            if protocol in self.suspicious_patterns['protocol_risk']['high']:
                features[i, 2] = 1.0
            elif protocol in self.suspicious_patterns['protocol_risk']['medium']:
                features[i, 2] = 0.5
                
            process = log.get('process_name', '').lower()
            if any(risk in process for risk in self.suspicious_patterns['process_risk']['high']):
                features[i, 3] = 1.0
            elif any(risk in process for risk in self.suspicious_patterns['process_risk']['medium']):
                features[i, 3] = 0.5
                
            event_type = log.get('event_type', '').lower()
            if event_type in self.suspicious_patterns['event_risk']['high']:
                features[i, 4] = 1.0
            elif event_type in self.suspicious_patterns['event_risk']['medium']:
                features[i, 4] = 0.5
                
            if log.get('status', '').lower() == 'failed':
                features[i, 5] = 1.0
                
            bytes_sent = log.get('bytes_sent', 0)
            bytes_received = log.get('bytes_received', 0)
            if bytes_received > 0:
                ratio = bytes_sent / bytes_received if bytes_received > 0 else 0
                if ratio > 5.0:
                    features[i, 6] = 1.0
                elif ratio > 1.0:
                    features[i, 6] = 0.5
            elif bytes_sent > 10000:  # Large outbound with no response
                features[i, 6] = 1.0
                
            filename = log.get('filename', '').lower()
            username = log.get('username', '').lower()
            
            if filename and any(pattern in filename for pattern in ['exploit', 'malware', 'hack', 'backdoor']):
                features[i, 7] = 1.0
            elif username == 'root' or username == 'admin' or username == 'administrator':
                features[i, 7] = 0.7
        
        return features
        
    def _initialize_food_sources(self, feature_vectors: np.ndarray) -> List[np.ndarray]:
        food_sources = []
        for _ in range(self.colony_size):
            food_sources.append(self._generate_random_solution(feature_vectors))
        return food_sources
    
    def _generate_random_solution(self, feature_vectors: np.ndarray) -> np.ndarray:
        solution = np.random.uniform(0.0, 1.0, size=feature_vectors.shape[1])
        solution /= solution.sum()
        return solution
    
    def _produce_new_solution(self, food_sources: List[np.ndarray], index: int, feature_vectors: np.ndarray) -> np.ndarray:
        solution = food_sources[index].copy()
        
        other_index = random.randrange(len(food_sources))
        while other_index == index:
            other_index = random.randrange(len(food_sources))
            
        dimension = random.randrange(len(solution))
        
        phi = random.uniform(-1, 1)
        solution[dimension] += phi * (solution[dimension] - food_sources[other_index][dimension])
        
        solution[dimension] = max(0.0, min(1.0, solution[dimension]))
        
        solution /= solution.sum()
        
        return solution
    
    def _calculate_fitness(self, solution: np.ndarray, feature_vectors: np.ndarray) -> float:
        weighted_features = feature_vectors * solution
        anomaly_scores = weighted_features.sum(axis=1)
        
        if len(anomaly_scores) <= 1:
            return 0.0
            
        variance = np.var(anomaly_scores)
        
        avg_score = np.mean(anomaly_scores)
        
        skewness = np.mean(((anomaly_scores - avg_score) / np.std(anomaly_scores))**3) if np.std(anomaly_scores) > 0 else 0
        
        fitness = (variance * 2.0) + (avg_score * 0.5) + (max(0, skewness) * 1.0)
        
        return fitness
    
    def _evaluate_best_solution(self, solution: np.ndarray, logs: List[Dict[str, Any]], feature_vectors: np.ndarray) -> Tuple[float, List[Dict[str, Any]]]:
        weighted_features = feature_vectors * solution
        anomaly_scores = weighted_features.sum(axis=1)
        
        max_score = np.max(anomaly_scores) if anomaly_scores.size > 0 else 1.0
        if max_score > 0:
            anomaly_scores = anomaly_scores / max_score
        
        threshold = 0.6
        
        anomaly_indices = np.where(anomaly_scores > threshold)[0]
        detected_anomalies = []
        
        for idx in anomaly_indices:
            log = logs[idx]
            reasons = []
            
            if log.get('location', '') in self.suspicious_patterns['location_risk']['high']:
                reasons.append(f"Suspicious location: {log.get('location')}")
                
            if log.get('destination_port', 0) in self.suspicious_patterns['port_risk']['high']:
                reasons.append(f"High-risk port: {log.get('destination_port')}")
                
            if log.get('protocol', '') in self.suspicious_patterns['protocol_risk']['high']:
                reasons.append(f"Risky protocol: {log.get('protocol')}")
                
            process = log.get('process_name', '').lower()
            for risk in self.suspicious_patterns['process_risk']['high']:
                if risk in process:
                    reasons.append(f"Suspicious process: {log.get('process_name')}")
                    break
                    
            if log.get('status', '').lower() == 'failed':
                reasons.append("Failed operation")
                
            detected_anomalies.append({
                "log_index": int(idx),
                "anomaly_score": float(anomaly_scores[idx]),
                "reasons": reasons,
                "timestamp": log.get('timestamp', ''),
                "source_ip": log.get('source_ip', ''),
                "destination_ip": log.get('destination_ip', '')
            })
        
        detected_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        anomaly_percentage = len(anomaly_indices) / len(logs) if logs else 0
        avg_anomaly_score = np.mean(anomaly_scores[anomaly_indices]) if len(anomaly_indices) > 0 else 0
        max_anomaly_score = np.max(anomaly_scores) if anomaly_scores.size > 0 else 0
        
        overall_score = (anomaly_percentage * 0.3) + (avg_anomaly_score * 0.4) + (max_anomaly_score * 0.3)
        overall_score = min(1.0, overall_score)
        
        return overall_score, detected_anomalies

if __name__ == "__main__":
    import json
    import sys
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        try:
            with open(log_file, 'r') as f:
                log_data = json.load(f)
                
            analyzer = ABCLogAnalyzer()
            results = analyzer.analyze(log_data.get('logs', []))
            
            print(json.dumps(results, indent=2))
            
        except Exception as e:
            print(f"Error: {str(e)}")
    else:
        print("Please provide a log file path")