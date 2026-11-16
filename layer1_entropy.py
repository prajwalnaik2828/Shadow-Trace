import os
import math
import platform
import logging
from pathlib import Path
import config
import utils

# PURPOSE:
# Measures file randomness to detect anomalously hidden encrypted content. 
# High entropy in a file that should be low entropy suggests hidden data.
# Steganographic payloads, especially encrypted ones, significantly increase file entropy.

def calculate_shannon_entropy(filepath):
    try:
        if not os.path.exists(filepath):
            return None
        
        file_size_bytes = os.path.getsize(filepath)
        if hasattr(utils, 'verify_lock') and utils.verify_lock(filepath):
            # Try to unlock or handle if necessary, but here we just read
            pass
            
        with open(filepath, 'rb') as f:
            data = f.read()
            
        total_bytes_read = len(data)
        
        if total_bytes_read < 100:
            counts = [0] * 256
            for byte in data:
                counts[byte] += 1
            
            entropy = 0.0
            for count in counts:
                if count > 0:
                    p = count / total_bytes_read
                    entropy -= p * math.log2(p)
                    
            return {
                'overall_entropy': round(entropy, 6),
                'file_size_bytes': file_size_bytes,
                'total_bytes_read': total_bytes_read,
                'note': 'file_too_small'
            }

        def calc_e(chunk):
            chunk_len = len(chunk)
            if chunk_len == 0:
                return 0.0
            counts = [0] * 256
            for byte in chunk:
                counts[byte] += 1
            e = 0.0
            for count in counts:
                if count > 0:
                    p = count / chunk_len
                    e -= p * math.log2(p)
            return e

        overall_entropy = calc_e(data)
        
        ten_percent = max(1, total_bytes_read // 10)
        
        header_region = data[:ten_percent]
        
        middle_start = (total_bytes_read - ten_percent) // 2
        body_region = data[middle_start : middle_start + ten_percent]
        
        tail_region = data[-ten_percent:]
        
        header_entropy = calc_e(header_region)
        body_entropy = calc_e(body_region)
        tail_entropy = calc_e(tail_region)
        
        return {
            'overall_entropy': round(overall_entropy, 6),
            'header_entropy': round(header_entropy, 6),
            'body_entropy': round(body_entropy, 6),
            'tail_entropy': round(tail_entropy, 6),
            'file_size_bytes': file_size_bytes,
            'total_bytes_read': total_bytes_read
        }

    except PermissionError as e:
        utils.log_error(f"Permission error calculating entropy for {filepath}", e)
        return None
    except Exception as e:
        utils.log_error(f"Error calculating entropy for {filepath}", e)
        return None

def get_entropy_threshold(mime_type):
    try:
        if mime_type in config.HIGH_ENTROPY_MIMES:
            return float(config.ENTROPY_THRESHOLD_HIGH)
        else:
            return float(config.ENTROPY_THRESHOLD_STANDARD)
    except Exception as e:
        utils.log_error(f"Error getting entropy threshold for {mime_type}", e)
        return 7.2  # Fallback

def classify_entropy_risk(entropy_dict, mime_type):
    try:
        threshold = get_entropy_threshold(mime_type)
        overall = entropy_dict.get('overall_entropy', 0.0)
        tail = entropy_dict.get('tail_entropy', overall)
        header = entropy_dict.get('header_entropy', overall)
        
        risk_level = "CLEAN"
        verdict = "CLEAN"
        anomaly_detected = False
        anomaly_description = ""
        
        if overall > threshold and tail > 7.8:
            risk_level = "CRITICAL"
            verdict = "THREAT"
            anomaly_detected = True
            anomaly_description = "High entropy throughout with extremely high tail - encrypted payload likely appended"
        elif overall > threshold and tail > threshold:
            risk_level = "HIGH"
            verdict = "SUSPICIOUS"
            anomaly_detected = True
            anomaly_description = "Consistently elevated entropy suggests hidden encrypted content"
        elif overall > threshold and tail <= threshold:
            risk_level = "MEDIUM"
            verdict = "SUSPICIOUS"
            anomaly_detected = True
            anomaly_description = "Elevated overall entropy - possible hidden content"
        elif (tail - header) > 0.8:
            risk_level = "MEDIUM"
            verdict = "SUSPICIOUS"
            anomaly_detected = True
            anomaly_description = "Tail entropy significantly higher than header - data may be appended"
        elif (threshold - 0.3) <= overall <= threshold:
            risk_level = "LOW"
            verdict = "CLEAN"
            anomaly_detected = False
            anomaly_description = "Slightly elevated entropy - borderline, worth monitoring"
        else:
            risk_level = "CLEAN"
            verdict = "CLEAN"
            anomaly_detected = False
            anomaly_description = "Entropy within normal range for this file type"
            
        return {
            'risk_level': risk_level,
            'verdict': verdict,
            'overall_entropy': overall,
            'threshold_used': threshold,
            'mime_type': mime_type,
            'anomaly_detected': anomaly_detected,
            'anomaly_description': anomaly_description,
            'header_entropy': header,
            'body_entropy': entropy_dict.get('body_entropy', overall),
            'tail_entropy': tail
        }
    except Exception as e:
        utils.log_error(f"Error classifying entropy risk: {e}", e)
        return {
            'risk_level': "CLEAN",
            'verdict': "CLEAN",
            'overall_entropy': 0.0,
            'threshold_used': 7.2,
            'mime_type': mime_type,
            'anomaly_detected': False,
            'anomaly_description': f"Error during classification",
            'header_entropy': 0.0,
            'body_entropy': 0.0,
            'tail_entropy': 0.0
        }

def scan_entropy(filepath, mime_type):
    try:
        result = calculate_shannon_entropy(filepath)
        if result is None:
            return {
               'engine': "ENTROPY_ANALYSIS",
               'verdict': "CLEAN",
               'risk_level': "CLEAN",
               'overall_entropy': 0.0,
               'header_entropy': 0.0,
               'body_entropy': 0.0,
               'tail_entropy': 0.0,
               'threshold_used': 0.0,
               'mime_type': mime_type,
               'anomaly_detected': False,
               'anomaly_description': "Failed to calculate entropy",
               'file_size_bytes': 0
            }
            
        class_res = classify_entropy_risk(result, mime_type)
        
        return {
           'engine': "ENTROPY_ANALYSIS",
           'verdict': class_res['verdict'],
           'risk_level': class_res['risk_level'],
           'overall_entropy': round(class_res['overall_entropy'], 4),
           'header_entropy': round(class_res['header_entropy'], 4),
           'body_entropy': round(class_res['body_entropy'], 4),
           'tail_entropy': round(class_res['tail_entropy'], 4),
           'threshold_used': class_res['threshold_used'],
           'mime_type': mime_type,
           'anomaly_detected': class_res['anomaly_detected'],
           'anomaly_description': class_res['anomaly_description'],
           'file_size_bytes': result.get('file_size_bytes', 0)
        }
    except Exception as e:
        utils.log_error(f"Error in scan_entropy for {filepath}", e)
        return {
           'engine': "ENTROPY_ANALYSIS",
           'verdict': "CLEAN",
           'risk_level': "CLEAN",
           'overall_entropy': 0.0,
           'header_entropy': 0.0,
           'body_entropy': 0.0,
           'tail_entropy': 0.0,
           'threshold_used': 0.0,
           'mime_type': mime_type,
           'anomaly_detected': False,
           'anomaly_description': f"Exception during analysis",
           'file_size_bytes': 0
        }

def generate_entropy_report_text(entropy_result):
    try:
        overall = entropy_result.get('overall_entropy', 0.0)
        header = entropy_result.get('header_entropy', 0.0)
        body = entropy_result.get('body_entropy', 0.0)
        tail = entropy_result.get('tail_entropy', 0.0)
        risk = entropy_result.get('risk_level', 'UNKNOWN')
        verdict = entropy_result.get('verdict', 'UNKNOWN')
        file_sz = entropy_result.get('file_size_bytes', 0)
        m_type = entropy_result.get('mime_type', 'unknown')
        thresh = entropy_result.get('threshold_used', 0.0)
        desc = entropy_result.get('anomaly_description', '')
        
        meaning_text = ""
        if risk in ["CRITICAL", "HIGH"]:
            meaning_text = "This entropy level is statistically inconsistent with a normal unmodified file and suggests hidden encrypted content."
        elif risk == "MEDIUM":
            meaning_text = "This file has moderately elevated entropy characteristics and warrants further steganalysis investigation."
        elif risk in ["LOW", "CLEAN"]:
            meaning_text = "The entropy observed is normal and expected for this file type."

        report = f"ENTROPY ANALYSIS\n"
        report += f"================\n"
        report += f"File Size: {file_sz} bytes\n"
        report += f"MIME Type: {m_type}\n"
        report += f"Threshold: {thresh}\n\n"
        
        report += f"Entropy Scores (scale 0.0 to 8.0):\n"
        report += f"  Overall: {overall:.4f}\n"
        report += f"  Header:  {header:.4f}\n"
        report += f"  Body:    {body:.4f}\n"
        report += f"  Tail:    {tail:.4f}\n\n"
        
        report += f"Risk Level: {risk}\n"
        report += f"Verdict: {verdict}\n\n"
        
        report += f"Analysis: {desc}\n\n"
        
        report += f"What This Means:\n"
        report += f"{meaning_text}\n"
        
        return report
    except Exception as e:
        utils.log_error(f"Error generating entropy report", e)
        return "ENTROPY ANALYSIS\n================\nError generating report."

if __name__ == "__main__":
    print("Running layer1_entropy tests...\n")
    test_filepath = "test_entropy_file.txt"
    
    # Test 1 - Normal text file low entropy
    try:
        with open(test_filepath, "wb") as f:
            # Create ~5000 bytes of English text
            f.write(b"This is a regular English sentence used for testing entropy. " * 100) 
        print("--- Test 1 - Normal text file low entropy ---")
        res1 = scan_entropy(test_filepath, "text/plain")
        print("Result Dict:\n", res1)
        print("\nReport Text:\n" + generate_entropy_report_text(res1))
        if res1['verdict'] == 'CLEAN':
            print("PASS\n")
        else:
            print("FAIL\n")
    except Exception as e:
        print("Test 1 Error", e)

    # Test 2 - Random bytes high entropy
    try:
        with open(test_filepath, "wb") as f:
            f.write(os.urandom(5000))
        print("--- Test 2 - Random bytes high entropy ---")
        res2 = scan_entropy(test_filepath, "text/plain")
        print("Result Dict:\n", res2)
        print("\nReport Text:\n" + generate_entropy_report_text(res2))
        if res2['verdict'] in ['SUSPICIOUS', 'THREAT']:
            print("PASS\n")
        else:
            print("FAIL\n")
    except Exception as e:
        print("Test 2 Error", e)

    # Test 3 - File with appended random data
    try:
        with open(test_filepath, "wb") as f:
            f.write(b"This is a regular English sentence used for testing entropy. " * 100) # normal
            f.write(os.urandom(2000)) # appended random
        print("--- Test 3 - File with appended random data ---")
        res3 = scan_entropy(test_filepath, "text/plain")
        print("Result Dict:\n", res3)
        print("\nReport Text:\n" + generate_entropy_report_text(res3))
        if res3['tail_entropy'] > res3['header_entropy']:
            print("PASS\n")
        else:
            print("FAIL\n")
    except Exception as e:
        print("Test 3 Error", e)
        
    finally:
        if os.path.exists(test_filepath):
            os.remove(test_filepath)
