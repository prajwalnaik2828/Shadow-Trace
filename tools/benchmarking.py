import os
import csv
import json
import time
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import config


def compute_roc_auc(
    y_true: List[int],
    y_scores: List[float],
) -> float:
    pairs = sorted(
        zip(y_scores, y_true),
        key=lambda x: x[0],
        reverse=True
    )

    n_pos = sum(y_true)
    n_neg = len(y_true) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    
    tp_cumsum = 0
    fp_cumsum = 0
    tpr_list = [0.0]
    fpr_list = [0.0]
    
    for score, label in pairs:
        if label == 1:
            tp_cumsum += 1
        else:
            fp_cumsum += 1
        tpr_list.append(tp_cumsum / n_pos)
        fpr_list.append(fp_cumsum / n_neg)
    
    tpr_list.append(1.0)
    fpr_list.append(1.0)

    auc = 0.0
    for i in range(1, len(fpr_list)):
        auc += (fpr_list[i] - fpr_list[i-1]) * (tpr_list[i] + tpr_list[i-1]) / 2
    
    return max(0.0, min(1.0, auc))


def compute_binary_metrics(
    y_true: List[int],
    y_pred: List[int],
    y_scores: List[float] = None,
) -> Dict:
    if len(y_true) != len(y_pred):
        return {'error': 'Length mismatch'}
    if len(y_true) == 0:
        return {'error': 'Empty inputs'}

    tp = sum(1 for t,p in zip(y_true,y_pred) if t==1 and p==1)
    tn = sum(1 for t,p in zip(y_true,y_pred) if t==0 and p==0)
    fp = sum(1 for t,p in zip(y_true,y_pred) if t==0 and p==1)
    fn = sum(1 for t,p in zip(y_true,y_pred) if t==1 and p==0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / len(y_true)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr       = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    auc = None
    if y_scores is not None and len(y_scores) == len(y_true):
        auc = compute_roc_auc(y_true, y_scores)

    return {
        'true_positives': tp,
        'true_negatives': tn,
        'false_positives': fp,
        'false_negatives': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1_score': round(f1, 4),
        'accuracy': round(accuracy, 4),
        'false_positive_rate': round(fpr, 4),
        'false_negative_rate': round(fnr, 4),
        'specificity': round(specificity, 4),
        'roc_auc': round(auc, 4) if auc else None,
        'total_samples': len(y_true),
        'positive_samples': sum(y_true),
        'negative_samples': len(y_true) - sum(y_true),
    }


def benchmark_layer1_pipeline(
    test_files: List[Dict],
) -> Dict:
    if not test_files:
        return {'error': 'No test files provided'}
    
    results = []
    timings = []
    y_true = []
    y_pred = []

    for test_case in test_files:
        filepath = test_case.get('filepath')
        ground_truth = test_case.get('ground_truth', 0)
        
        if not Path(filepath).exists():
            continue
        
        start = time.time()
        try:
            import layer1_malware
            result = layer1_malware.run_layer1(
                filepath, 'BENCH_' + str(len(results)),
                'benchmark_hash'
            )
            elapsed = time.time() - start
            
            verdict = result.get('verdict', 'CLEAN')
            predicted = 1 if verdict == 'THREAT' else 0
            
            y_true.append(ground_truth)
            y_pred.append(predicted)
            timings.append(elapsed)
            
            results.append({
                'filepath': filepath,
                'ground_truth': ground_truth,
                'predicted': predicted,
                'verdict': verdict,
                'time_seconds': round(elapsed, 3),
            })
        except Exception as e:
            results.append({
                'filepath': filepath,
                'error': str(e),
            })

    metrics = compute_binary_metrics(y_true, y_pred)
    avg_time = sum(timings) / len(timings) if timings else 0

    return {
        'component': 'Layer1_MalwareScreening',
        'metrics': metrics,
        'average_time_seconds': round(avg_time, 3),
        'total_files_tested': len(test_files),
        'results': results,
    }


def benchmark_steganalysis(
    test_cases: List[Dict],
    file_type: str = 'IMAGE',
) -> Dict:
    results = []
    y_true = []
    y_pred = []
    y_scores = []
    timings = []

    for case in test_cases:
        filepath = case.get('filepath')
        ground_truth = case.get('ground_truth', 0)
        
        if not Path(filepath).exists():
            continue
        
        start = time.time()
        try:
            import layer2_steganalysis
            result = layer2_steganalysis.run_steganalysis(
                filepath,
                'BENCH_' + str(len(results)),
                'benchmark_hash'
            )
            elapsed = time.time() - start
            
            score = result.get('score', 0.0) or 0.0
            verdict = result.get('verdict', 'CLEAN')
            predicted = 1 if verdict in ['STEGO_DETECTED', 'SUSPICIOUS'] else 0
            
            y_true.append(ground_truth)
            y_pred.append(predicted)
            y_scores.append(score)
            timings.append(elapsed)
            
            results.append({
                'filepath': filepath,
                'ground_truth': ground_truth,
                'predicted': predicted,
                'score': round(score, 4),
                'verdict': verdict,
                'time_seconds': round(elapsed, 3),
            })
        except Exception as e:
            results.append({
                'filepath': filepath,
                'error': str(e),
            })

    metrics = compute_binary_metrics(
        y_true, y_pred, y_scores
    )
    avg_time = sum(timings) / len(timings) if timings else 0

    return {
        'component': 'Layer2_Steganalysis_' + file_type,
        'file_type': file_type,
        'metrics': metrics,
        'average_time_seconds': round(avg_time, 3),
        'total_files_tested': len(test_cases),
        'results': results,
    }


def run_ablation_study(
    test_cases: List[Dict],
    file_type: str = 'IMAGE',
) -> Dict:
    ablation_configs = [
        {
            'name': 'Full System (Baseline)',
            'description': 'All components active',
            'weights': {
                'tier1a': 0.30,
                'tier1b': 0.35,
                'tier3_chi': 0.175,
                'tier3_rs': 0.175,
            },
        },
        {
            'name': 'Without YedroudjNetV3',
            'description': 'Tier 1A disabled',
            'weights': {
                'tier1a': 0.00,
                'tier1b': 0.55,
                'tier3_chi': 0.225,
                'tier3_rs': 0.225,
            },
        },
        {
            'name': 'Without ALASKA2 Model',
            'description': 'Tier 1B disabled',
            'weights': {
                'tier1a': 0.60,
                'tier1b': 0.00,
                'tier3_chi': 0.20,
                'tier3_rs': 0.20,
            },
        },
        {
            'name': 'Without Statistical Analysis',
            'description': 'Chi-Square and RS Analysis disabled',
            'weights': {
                'tier1a': 0.46,
                'tier1b': 0.54,
                'tier3_chi': 0.00,
                'tier3_rs': 0.00,
            },
        },
        {
            'name': 'Statistical Only',
            'description': 'Only Chi-Square and RS Analysis',
            'weights': {
                'tier1a': 0.00,
                'tier1b': 0.00,
                'tier3_chi': 0.50,
                'tier3_rs': 0.50,
            },
        },
        {
            'name': 'Neural Only',
            'description': 'Only neural models, no statistics',
            'weights': {
                'tier1a': 0.46,
                'tier1b': 0.54,
                'tier3_chi': 0.00,
                'tier3_rs': 0.00,
            },
        },
    ]

    ablation_results = []
    
    for config_item in ablation_configs:
        config_results = []
        y_true_ab = []
        y_pred_ab = []
        y_scores_ab = []
        
        for case in test_cases:
            filepath = case.get('filepath')
            ground_truth = case.get('ground_truth', 0)
            
            if not Path(filepath).exists():
                continue
            
            try:
                import layer2_steganalysis
                
                t1a_score = 0.5
                t1b_score = 0.5
                t3_chi = 0.5
                t3_rs = 0.5
                
                result = layer2_steganalysis.run_steganalysis(
                    filepath, 'ABLATION_BENCH',
                    'benchmark_hash'
                )
                
                t1a_r = result.get('tier1a_yedroudj', {}) or {}
                t1b_r = result.get('tier1b_alaska2', {}) or {}
                t3_r = result.get('tier3_statistical', {}) or {}
                
                t1a_score = t1a_r.get('score', 0.5) or 0.5
                t1b_score = t1b_r.get('score', 0.5) or 0.5
                t3_chi = t3_r.get('chi_square', {}).get('score', 0.5) or 0.5
                t3_rs = t3_r.get('rs_analysis', {}).get('score', 0.5) or 0.5
                
                w = config_item['weights']
                total_w = sum(w.values())
                
                if total_w > 0:
                    ablated_score = (
                        t1a_score * w['tier1a'] +
                        t1b_score * w['tier1b'] +
                        t3_chi * w['tier3_chi'] +
                        t3_rs * w['tier3_rs']
                    ) / total_w
                else:
                    ablated_score = 0.5
                
                predicted = 1 if ablated_score >= 0.40 else 0
                
                y_true_ab.append(ground_truth)
                y_pred_ab.append(predicted)
                y_scores_ab.append(ablated_score)
                
                config_results.append({
                    'filepath': filepath,
                    'ground_truth': ground_truth,
                    'predicted': predicted,
                    'ablated_score': round(ablated_score, 4),
                })
            except Exception as e:
                pass
        
        metrics = compute_binary_metrics(
            y_true_ab, y_pred_ab, y_scores_ab
        )
        
        ablation_results.append({
            'config_name': config_item['name'],
            'description': config_item['description'],
            'metrics': metrics,
            'result_count': len(config_results),
        })

    return {
        'ablation_results': ablation_results,
        'file_type': file_type,
        'test_case_count': len(test_cases),
        'generated_at': datetime.now().isoformat(),
    }


def save_benchmark_results(
    results: Dict,
    output_name: str = 'benchmark',
) -> Dict:
    output_dir = config.BASE_DIR / 'logs' / 'benchmarks'
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    json_path = output_dir / (
        timestamp + '_' + output_name + '.json'
    )
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print('[BENCHMARK] JSON saved: ' + json_path.name)

    csv_path = output_dir / (
        timestamp + '_' + output_name + '_summary.csv'
    )
    
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Component', 'Precision', 'Recall',
            'F1', 'Accuracy', 'FPR', 'FNR',
            'ROC_AUC', 'TP', 'TN', 'FP', 'FN',
            'Total_Samples', 'Avg_Time_Sec'
        ])
        
        if 'ablation_results' in results:
            for ab in results['ablation_results']:
                m = ab.get('metrics', {})
                writer.writerow([
                    ab.get('config_name', ''),
                    m.get('precision', ''),
                    m.get('recall', ''),
                    m.get('f1_score', ''),
                    m.get('accuracy', ''),
                    m.get('false_positive_rate', ''),
                    m.get('false_negative_rate', ''),
                    m.get('roc_auc', ''),
                    m.get('true_positives', ''),
                    m.get('true_negatives', ''),
                    m.get('false_positives', ''),
                    m.get('false_negatives', ''),
                    m.get('total_samples', ''),
                    results.get('average_time_seconds', ''),
                ])
        elif 'metrics' in results:
            m = results.get('metrics', {})
            writer.writerow([
                results.get('component', ''),
                m.get('precision', ''),
                m.get('recall', ''),
                m.get('f1_score', ''),
                m.get('accuracy', ''),
                m.get('false_positive_rate', ''),
                m.get('false_negative_rate', ''),
                m.get('roc_auc', ''),
                m.get('true_positives', ''),
                m.get('true_negatives', ''),
                m.get('false_positives', ''),
                m.get('false_negatives', ''),
                m.get('total_samples', ''),
                results.get('average_time_seconds', ''),
            ])
    
    print('[BENCHMARK] CSV saved: ' + csv_path.name)

    return {
        'json_path': str(json_path),
        'csv_path': str(csv_path),
    }


def print_metrics_table(
    results: Dict,
    title: str = 'Benchmark Results',
):
    print()
    print('=' * 70)
    print('  ' + title)
    print('=' * 70)

    if 'ablation_results' in results:
        print(f'  {"Configuration":<35} {"F1":>6} {"Prec":>6} {"Rec":>6} {"AUC":>6} {"FPR":>6}')
        print('-' * 70)
        for ab in results['ablation_results']:
            m = ab.get('metrics', {})
            f1 = m.get('f1_score', 0) or 0
            prec = m.get('precision', 0) or 0
            rec = m.get('recall', 0) or 0
            auc = m.get('roc_auc', 0) or 0
            fpr = m.get('false_positive_rate', 0) or 0
            n = m.get('total_samples', 0) or 0
            
            if n == 0:
                print(f'  {ab["config_name"]:<35}    N/A    N/A    N/A    N/A    N/A')
            else:
                print(f'  {ab["config_name"]:<35} {f1:>6.3f} {prec:>6.3f} {rec:>6.3f} {auc:>6.3f} {fpr:>6.3f}')
    elif 'metrics' in results:
        m = results['metrics']
        for k, v in m.items():
            print(f'  {k}: {v}')

    print('=' * 70)
    print()


if __name__ == '__main__':
    print('=== BENCHMARKING MODULE TEST ===')
    print()

    print('Test 1: Metric calculation verification')

    y_true = [1,1,1,1,1,0,0,0,0,0]
    y_pred = [1,1,1,1,1,0,0,0,0,0]
    y_scores = [0.9,0.8,0.85,0.95,0.88,0.1,0.2,0.15,0.05,0.12]

    m = compute_binary_metrics(y_true, y_pred, y_scores)
    print('  Perfect classifier:')
    print('    Precision: ' + str(m['precision'])
          + ' (expected 1.0)')
    print('    Recall:    ' + str(m['recall'])
          + ' (expected 1.0)')
    print('    F1:        ' + str(m['f1_score'])
          + ' (expected 1.0)')
    print('    ROC-AUC:   ' + str(m['roc_auc'])
          + ' (expected 1.0)')
    print('    FPR:       ' + str(m['false_positive_rate'])
          + ' (expected 0.0)')

    import random
    random.seed(42)
    y_true_r = [random.randint(0,1) for _ in range(100)]
    y_pred_r = [random.randint(0,1) for _ in range(100)]
    y_scores_r = [random.random() for _ in range(100)]
    m_r = compute_binary_metrics(y_true_r, y_pred_r, y_scores_r)
    print()
    print('  Random classifier (100 samples):')
    print('    F1:      ' + str(m_r['f1_score'])
          + ' (expected ~0.5)')
    print('    ROC-AUC: ' + str(m_r['roc_auc'])
          + ' (expected ~0.5)')
    print('    Samples: TP=' + str(m_r['true_positives'])
          + ' TN=' + str(m_r['true_negatives'])
          + ' FP=' + str(m_r['false_positives'])
          + ' FN=' + str(m_r['false_negatives']))
    print()

    print('Test 2: ROC-AUC verification')
    y_t = [1,1,1,0,0,0,0,1,0,1]
    y_s = [0.9,0.8,0.7,0.6,0.5,0.4,0.3,0.75,0.35,0.85]
    auc = compute_roc_auc(y_t, y_s)
    print('  AUC on known good scores: ' + str(round(auc,4)))
    print('  (Expected: > 0.85 for these well-separated scores)')
    print()

    print('Test 3: Ablation study with synthetic data')

    example_t1a = 0.85
    example_t1b = 0.35
    example_chi = 0.92
    example_rs = 0.88

    print('  Example ablation with fixed component scores:')
    print('  T1A=0.85 T1B=0.35 Chi=0.92 RS=0.88')
    print()

    configs = [
        ('Full System', 0.30, 0.35, 0.175, 0.175),
        ('Without T1A', 0.00, 0.55, 0.225, 0.225),
        ('Without T1B', 0.60, 0.00, 0.200, 0.200),
        ('Without Stats', 0.46, 0.54, 0.000, 0.000),
        ('Stats Only', 0.00, 0.00, 0.500, 0.500),
        ('Neural Only', 0.46, 0.54, 0.000, 0.000),
    ]

    for name, w1a, w1b, wchi, wrs in configs:
        total_w = w1a + w1b + wchi + wrs
        if total_w > 0:
            score = (
                example_t1a * w1a +
                example_t1b * w1b +
                example_chi * wchi +
                example_rs * wrs
            ) / total_w
        else:
            score = 0.5
        verdict = 'STEGO' if score >= 0.65 else 'SUSPICIOUS' if score >= 0.40 else 'CLEAN'
        print(f'    {name:<25} score={score:.3f} -> {verdict}')

    print()

    print('Test 4: Results saving')
    mock_results = {
        'component': 'Test_Component',
        'metrics': m,
        'average_time_seconds': 0.5,
    }
    saved = save_benchmark_results(
        mock_results, 'test_benchmark'
    )
    print('  JSON: ' + Path(saved['json_path']).name)
    print('  CSV:  ' + Path(saved['csv_path']).name)
    print()

    print_metrics_table(mock_results, 'Test Metrics')

    print('=== TEST COMPLETE ===')
