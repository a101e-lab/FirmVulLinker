#!/usr/bin/env python3
import os
import csv
import subprocess
import time
import json
import logging
from datetime import datetime
import re
import argparse
import uuid
import threading
import signal
import sys
import multiprocessing
from multiprocessing import Process, Queue, Event, Manager
from collections import defaultdict

# 基础路径设置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA_DIR = os.path.join(BASE_DIR, "origin_data")
# 从环境变量读取结果和日志目录，如果未设置则使用默认值
RESULTS_DIR = os.environ.get('COMPARISON_RESULTS_DIR', os.path.join(BASE_DIR, "comparison_results"))
LOGS_DIR = os.environ.get('LOGS_DIR', os.path.join(BASE_DIR, "logs_medium_ngram3"))

# 确保日志目录存在
os.makedirs(LOGS_DIR, exist_ok=True)

# 设置主日志记录器
log_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
main_log_file = os.path.join(LOGS_DIR, f"batch_comparison_main_{log_timestamp}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(main_log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def read_cve_data(csv_file):
    """读取CVE数据并返回每个CVE对应的基准固件和其他固件，以及固件关系映射"""
    cve_dict = {}
    all_base_firmwares = set()
    
    # 创建固件关系映射 - 记录哪些固件应该相似
    similar_firmware_pairs = set()  # 用于存储应该相似的固件对
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)  # 跳过标题行
        
        for row in reader:
            if len(row) < 3:  # 确保每行至少有CVE编号和一个固件
                continue
                
            vuln_id = row[1]
            base_firmware = row[2]  # 基准固件
            other_firmwares = [fw for fw in row[3:] if fw.strip()]  # 获取所有非空的其他固件ID
            
            all_base_firmwares.add(base_firmware)
            
            if base_firmware and other_firmwares:
                cve_dict[vuln_id] = {
                    'base_firmware': base_firmware,
                    'other_firmwares': other_firmwares
                }
                
                # 记录固件关系：同一个CVE中的固件应该相似
                for target_firmware in other_firmwares:
                    # 创建固件对 (按字母排序确保唯一性)
                    fw_pair = tuple(sorted([base_firmware, target_firmware]))
                    similar_firmware_pairs.add(fw_pair)
    
    return cve_dict, all_base_firmwares, similar_firmware_pairs

def get_all_firmware_in_testdata():
    """获取test_data目录下的所有固件文件夹"""
    firmwares = []
    for item in os.listdir(TEST_DATA_DIR):
        item_path = os.path.join(TEST_DATA_DIR, item)
        if os.path.isdir(item_path):
            firmwares.append(item)
    return firmwares

def get_similarity_results():
    """获取已完成比较的相似度结果"""
    results = {}
    
    if not os.path.exists(RESULTS_DIR):
        return results
        
    # 遍历结果目录获取已比较的相似度结果
    for result_dir in os.listdir(RESULTS_DIR):
        result_path = os.path.join(RESULTS_DIR, result_dir)
        if not os.path.isdir(result_path):
            continue
            
        # 查找结果文件
        similarity_file = os.path.join(result_path, "similarity_result.json")
        if os.path.exists(similarity_file):
            try:
                with open(similarity_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                parts = result_dir.split('_')
                if len(parts) >= 2:
                    fw1 = parts[0]
                    fw2 = parts[1]
                    
                    total_similarity = data.get('total_similarity', 0)
                    
                    # 记录相似度结果
                    results[(fw1, fw2)] = total_similarity
                    results[(fw2, fw1)] = total_similarity
                    
            except Exception as e:
                logger.error(f"读取相似度结果文件出错: {similarity_file}, 错误: {str(e)}")
    
    return results

def compare_firmwares(firmware1, firmware2, task_id=None, similarity_threshold=0.5):
    """调用main.py比较两个固件并记录日志"""
    logger.info(f"开始比较固件: {firmware1} 与 {firmware2}")
    
    # 创建单独的日志文件
    comparison_log_file = os.path.join(LOGS_DIR, f"comparison_{firmware1}_{firmware2}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    comparison_logger = logging.getLogger(f"{firmware1}_{firmware2}")
    comparison_logger.setLevel(logging.INFO)
    
    # 添加文件处理器
    file_handler = logging.FileHandler(comparison_log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    comparison_logger.addHandler(file_handler)
    
    firmware1_path = os.path.join(TEST_DATA_DIR, firmware1)
    firmware2_path = os.path.join(TEST_DATA_DIR, firmware2)
    
    # 检查固件目录是否存在
    if not os.path.exists(firmware1_path) or not os.path.exists(firmware2_path):
        error_msg = f"固件路径不存在: {firmware1_path} 或 {firmware2_path}"
        logger.error(error_msg)
        comparison_logger.error(error_msg)
        return False, 0
    
    # 构建命令，传递输出目录参数
    cmd = ['python', 'main.py', firmware1_path, firmware2_path, '--output_dir', RESULTS_DIR]
    
    # 记录开始执行命令
    comparison_logger.info(f"执行命令: {' '.join(cmd)}")
    
    try:
        # 执行命令并捕获输出
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        # 创建一个空行检测集合，避免连续记录空行
        last_line_empty = False
        
        total_similarity = 0
        
        while True:
            stdout_line = process.stdout.readline()
            
            if stdout_line:
                line = stdout_line.strip()
                clean_line = ansi_escape.sub('', line)
                
                # 尝试从输出中提取总相似度
                if "总体相似度:" in clean_line:
                    try:
                        total_similarity = float(clean_line.split("总体相似度:")[1].strip().split()[0])
                        comparison_logger.info(f"提取到总相似度: {total_similarity}")
                    except:
                        comparison_logger.warning(f"无法从输出中提取总相似度: {clean_line}")
                
                # 跳过进度条和特殊字符行
                if '%|' in line or '[A' in line or '\r' in line or '█' in line:
                    continue
                
                # 跳过空行和只包含非可见字符的行
                if not clean_line:
                    last_line_empty = True
                    continue
                
                # 记录有意义的输出
                comparison_logger.info(clean_line)
                logger.info(clean_line)
                last_line_empty = False
            
            if not stdout_line and process.poll() is not None:
                break
        
        # 获取进程返回码
        return_code = process.wait()
        
        if return_code == 0:
            # 如果从输出中未成功获取相似度，尝试从摘要文件中读取
            if total_similarity == 0:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                # 查找最新的比较结果目录
                fw_dir = None
                for d in sorted(os.listdir(RESULTS_DIR), reverse=True):
                    if d.startswith(f"{firmware1}_{firmware2}") or d.startswith(f"{firmware2}_{firmware1}"):
                        fw_dir = d
                        break
                
                if fw_dir:
                    summary_file = os.path.join(RESULTS_DIR, fw_dir, "comparison_summary.json")
                    if os.path.exists(summary_file):
                        try:
                            with open(summary_file, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                total_similarity = data.get('total_similarity', 0)
                                comparison_logger.info(f"从摘要文件中读取到总相似度: {total_similarity}")
                        except Exception as e:
                            comparison_logger.error(f"读取摘要文件失败: {str(e)}")
            
            # 使用设定的阈值判断相似度
            is_similar = total_similarity >= similarity_threshold
            similarity_status = "相似" if is_similar else "不相似"
            
            comparison_logger.info(f"固件比较成功完成: {firmware1} 与 {firmware2}, 总相似度: {total_similarity}, 状态: {similarity_status}")
            logger.info(f"固件比较成功完成: {firmware1} 与 {firmware2}, 总相似度: {total_similarity}, 状态: {similarity_status}")
            return True, total_similarity
        else:
            comparison_logger.error(f"固件比较失败，返回码: {return_code}")
            logger.error(f"固件比较失败，返回码: {return_code}")
            return False, 0
            
    except Exception as e:
        error_msg = f"执行比较过程中发生错误: {str(e)}"
        comparison_logger.error(error_msg)
        logger.error(error_msg)
        return False, 0
    finally:
        # 关闭文件处理器
        comparison_logger.removeHandler(file_handler)
        file_handler.close()

def worker_process(worker_id, task_queue, result_queue, stop_event, similarity_threshold):
    """工作进程，从队列获取任务并执行比较"""
    worker_logger = logging.getLogger(f"worker_{worker_id}")
    worker_logger.setLevel(logging.INFO)
    # 创建单独的日志文件
    worker_log_file = os.path.join(LOGS_DIR, f"worker_{worker_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    file_handler = logging.FileHandler(worker_log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    worker_logger.addHandler(file_handler)
    
    worker_logger.info(f"工作进程 {worker_id} 启动")
    
    while not stop_event.is_set():
        try:
            # 从队列中获取任务（阻塞操作，超时2秒）
            try:
                task = task_queue.get(timeout=2)
            except:
                # 队列为空或超时，继续下一次循环
                continue
                
            # 解析任务
            task_id = task.get('id')
            base_firmware = task.get('base_firmware')
            target_firmware = task.get('target_firmware')
            vuln_id = task.get('vuln_id')
            expected_similar = task.get('expected_similar', True)  # 默认期望相似
            
            worker_logger.info(f"获取到任务 {task_id}: 比较基准固件 {base_firmware} 与 {target_firmware} (CVE: {vuln_id})")
            
            # 执行比较
            success, similarity = compare_firmwares(base_firmware, target_firmware, task_id, similarity_threshold)
            
            # 判断相似状态
            is_similar = similarity >= similarity_threshold if success else False
            
            # 将结果写回队列
            result = {
                '任务ID': task_id,
                '基准固件': base_firmware,
                '目标固件': target_firmware,
                '漏洞ID': vuln_id,
                '是否成功': success,
                '相似度': similarity,
                '是否相似': is_similar,
                '预期相似': expected_similar,
                '预测正确': is_similar == expected_similar if success else False,
                '时间戳': datetime.now().isoformat(),
                '工作进程ID': worker_id
            }
            result_queue.put(result)
            
            worker_logger.info(f"任务 {task_id} 完成: {'成功' if success else '失败'}, 相似度: {similarity}, 预期{'相似' if expected_similar else '不相似'}, 实际{'相似' if is_similar else '不相似'}")
            
        except Exception as e:
            worker_logger.error(f"工作进程处理任务时发生错误: {str(e)}")
    
    worker_logger.info(f"工作进程 {worker_id} 收到停止信号，正在退出...")
    worker_logger.removeHandler(file_handler)
    file_handler.close()

def calculate_and_log_metrics(total_tp, total_fp, total_tn, total_fn):
    """计算并记录误报率、漏报率和精确率"""
    # 计算关键指标
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    false_positive_rate = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0
    false_negative_rate = total_fn / (total_fn + total_tp) if (total_fn + total_tp) > 0 else 0
    
    # 记录整体评估指标
    logger.info("=" * 50)
    logger.info("整体评估指标:")
    logger.info(f"真阳性 (TP): {total_tp}")
    logger.info(f"假阳性 (FP): {total_fp}")
    logger.info(f"真阴性 (TN): {total_tn}")
    logger.info(f"假阴性 (FN): {total_fn}")
    logger.info(f"精确率 (Precision): {precision:.4f}")
    logger.info(f"误报率 (False Positive Rate): {false_positive_rate:.4f}")
    logger.info(f"漏报率 (False Negative Rate): {false_negative_rate:.4f}")
    logger.info("=" * 50)
    
    # 返回整体指标
    return {
        "精确率": precision,
        "误报率": false_positive_rate,
        "漏报率": false_negative_rate,
        "真阳性": total_tp,
        "假阳性": total_fp,
        "真阴性": total_tn,
        "假阴性": total_fn
    }

def main():
    parser = argparse.ArgumentParser(description='固件相似度批量比较工具')
    parser.add_argument('--workers', type=int, default=1, help='并行工作进程数量')
    parser.add_argument('--config', default='config.yaml', help='配置文件路径')
    parser.add_argument('--output-dir', help='比较结果输出目录路径')
    parser.add_argument('--logs-dir', help='日志输出目录路径')
    parser.add_argument('--similarity-threshold', type=float, default=0.5, help='相似度阈值，大于等于该值判定为相似')
    args = parser.parse_args()
    
    # 使用传入的配置文件路径
    config_path = args.config
    similarity_threshold = args.similarity_threshold
    
    # 如果指定了输出目录和日志目录，则覆盖全局变量
    global RESULTS_DIR, LOGS_DIR
    if args.output_dir:
        RESULTS_DIR = args.output_dir
        print(f"使用自定义结果目录: {RESULTS_DIR}")
    
    if args.logs_dir:
        LOGS_DIR = args.logs_dir
        print(f"使用自定义日志目录: {LOGS_DIR}")
    
    # 确保日志目录存在
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    # 重新配置日志记录器，使用新的日志目录
    global log_timestamp
    log_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    main_log_file = os.path.join(LOGS_DIR, f"batch_comparison_main_{log_timestamp}.log")
    
    # 移除现有的处理器
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # 创建新的处理器
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(main_log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    # 记录开始时间
    start_time = time.time()
    logger.info(f"开始批量固件比较任务，启动 {args.workers} 个工作进程")
    logger.info(f"相似度阈值设置为: {similarity_threshold}")
    
    # 读取CVE-固件映射
    csv_file = os.path.join(BASE_DIR, "exe2sim_cve.csv")
    cve_firmwares, all_base_firmwares, similar_firmware_pairs = read_cve_data(csv_file)
    logger.info(f"从CSV文件加载了 {len(cve_firmwares)} 个CVE项")
    logger.info(f"识别到 {len(all_base_firmwares)} 个基准固件")
    logger.info(f"识别到 {len(similar_firmware_pairs)} 对应该相似的固件对")
    
    # 获取test_data目录下的所有固件
    all_firmwares = get_all_firmware_in_testdata()
    logger.info(f"在test_data目录下发现 {len(all_firmwares)} 个固件")
    
    # 检查并记录缺失的固件
    missing_base_firmwares = set()
    for base_firmware in all_base_firmwares:
        if base_firmware not in all_firmwares:
            missing_base_firmwares.add(base_firmware)
            logger.warning(f"警告：基准固件 {base_firmware} 在test_data目录中不存在")
    
    if missing_base_firmwares:
        logger.warning(f"总共有 {len(missing_base_firmwares)} 个基准固件在test_data目录中不存在")
    
    # 获取已有的相似度结果
    similarity_results = get_similarity_results()
    logger.info(f"加载了 {len(similarity_results)//2} 对固件的相似度结果")
    
    # 统计数据
    total_comparisons = 0
    enqueued = 0
    skipped = 0
    skipped_due_to_missing = 0
    
    # 创建多进程共享队列
    manager = Manager()
    task_queue = manager.Queue()
    result_queue = manager.Queue()
    
    # 创建一个集合，记录已经加入比较任务的固件对，避免重复比较
    compared_pairs = set()
    
    # 收集所有基准固件与目标固件的比较任务
    all_comparison_tasks = []  # [(base_fw, target_fw, vuln_id, expected_similar), ...]
    
    # 对于每个基准固件，与test_data中的所有固件进行比较
    for base_firmware in all_base_firmwares:
        # 跳过不存在的基准固件
        if base_firmware not in all_firmwares:
            continue
            
        for target_firmware in all_firmwares:
            # 跳过自己与自己比较
            if base_firmware == target_firmware:
                continue
                
            # 确保每对固件只比较一次
            pair = tuple(sorted([base_firmware, target_firmware]))
            if pair in compared_pairs:
                continue
                
            # 确定是否期望相似
            expected_similar = pair in similar_firmware_pairs
            
            # 记录比较任务 (使用base_firmware所属的第一个CVE作为标识)
            vuln_id = None
            for cve_id, data in cve_firmwares.items():
                if data['base_firmware'] == base_firmware:
                    vuln_id = cve_id
                    break
            
            if not vuln_id:
                vuln_id = "unknown_cve"
                
            all_comparison_tasks.append((base_firmware, target_firmware, vuln_id, expected_similar))
            compared_pairs.add(pair)
    
    # 创建任务并放入队列
    for base_firmware, target_firmware, vuln_id, expected_similar in all_comparison_tasks:
        # 更新总比较数
        total_comparisons += 1
        
        # 确认固件在test_data目录中存在
        base_firmware_path = os.path.join(TEST_DATA_DIR, base_firmware)
        target_firmware_path = os.path.join(TEST_DATA_DIR, target_firmware)
        
        if not os.path.exists(base_firmware_path) or not os.path.exists(target_firmware_path):
            logger.warning(f"跳过比较任务: {base_firmware} 与 {target_firmware}, 原因: 固件路径不存在")
            skipped_due_to_missing += 1
            skipped += 1
            continue
        
        # 如果已经有相似度结果，检查是否需要跳过
        if (base_firmware, target_firmware) in similarity_results or (target_firmware, base_firmware) in similarity_results:
            # 获取已有的相似度结果
            similarity = similarity_results.get((base_firmware, target_firmware), 
                          similarity_results.get((target_firmware, base_firmware), 0))
            
            is_similar = similarity >= similarity_threshold
            logger.info(f"已有比较结果: {base_firmware} 与 {target_firmware}, 相似度: {similarity}, {'相似' if is_similar else '不相似'}")
            
            skipped += 1
            continue
        
        # 创建任务并加入队列
        task_id = str(uuid.uuid4())
        task = {
            'id': task_id,
            'base_firmware': base_firmware,
            'target_firmware': target_firmware,
            'vuln_id': vuln_id,
            'expected_similar': expected_similar,
            'timestamp': datetime.now().isoformat()
        }
        task_queue.put(task)
        enqueued += 1
        
        logger.info(f"已将任务加入队列: 基准固件 {base_firmware} 与 {target_firmware} (ID: {task_id}, CVE: {vuln_id}, 期望{'相似' if expected_similar else '不相似'})")
    
    # 记录任务创建阶段的统计信息
    logger.info(f"所有任务创建完成，启动工作进程...")
    logger.info(f"总计需要比较: {total_comparisons}对")
    logger.info(f"已入队任务数: {enqueued}对")
    logger.info(f"已跳过任务数: {skipped}对 (包括因固件缺失跳过的 {skipped_due_to_missing}对)")
    
    # 如果没有需要处理的任务，提前结束
    if enqueued == 0:
        logger.info("没有需要处理的任务，程序结束")
        return
    
    # 启动工作进程
    stop_event = Event()
    
    workers = []
    for i in range(args.workers):
        p = Process(
            target=worker_process, 
            args=(i+1, task_queue, result_queue, stop_event, similarity_threshold)
        )
        p.daemon = True
        p.start()
        workers.append(p)
        logger.info(f"启动工作进程 {i+1}")
    
    # 收集结果和更新统计信息
    completed = 0
    failed = 0
    active_tasks = enqueued
    
    # 统计四个指标
    total_tp = 0  # 真阳性：期望相似且实际相似
    total_fp = 0  # 假阳性：期望不相似但实际相似
    total_tn = 0  # 真阴性：期望不相似且实际不相似
    total_fn = 0  # 假阴性：期望相似但实际不相似
    
    try:
        # 处理结果，直到所有任务完成
        while completed + failed < enqueued:
            try:
                # 从结果队列获取结果（设置超时，以便可以响应键盘中断）
                try:
                    result = result_queue.get(timeout=2)
                    active_tasks -= 1
                except:
                    # 检查是否所有工作进程都已结束
                    all_workers_dead = True
                    for p in workers:
                        if p.is_alive():
                            all_workers_dead = False
                            break
                            
                    if all_workers_dead and active_tasks > 0:
                        logger.error("所有工作进程已终止，但仍有任务未完成")
                        break
                        
                    # 如果只是超时，继续下一次循环
                    continue
                
                # 修复：确保所有值正确读取并处理
                base_firmware = result.get('基准固件')
                target_firmware = result.get('目标固件')
                success = result.get('是否成功', False)
                vuln_id = result.get('漏洞ID')
                similarity = result.get('相似度', 0)
                is_similar = result.get('是否相似', False)
                expected_similar = result.get('预期相似', True)
                
                if base_firmware is None or target_firmware is None:
                    logger.error(f"结果数据错误: 基准固件或目标固件为None, 任务ID: {result.get('任务ID', 'unknown')}")
                    failed += 1
                    continue
                
                if success:
                    completed += 1
                    # 添加到已有相似度结果
                    similarity_results[(base_firmware, target_firmware)] = similarity
                    similarity_results[(target_firmware, base_firmware)] = similarity
                    
                else:
                    failed += 1
                
                # 记录结果和预测
                correct_prediction = (expected_similar == is_similar)
                prediction_result = "正确" if correct_prediction else "错误"
                logger.info(f"任务结果: 基准固件 {base_firmware} 与 {target_firmware}, 相似度: {similarity}, " +
                          f"预期{'相似' if expected_similar else '不相似'}, 实际{'相似' if is_similar else '不相似'}, 预测{prediction_result}")
                
                # 每10个结果打印一次进度，或者是最后一个结果
                if (completed + failed) % 10 == 0 or (completed + failed) == enqueued:
                    logger.info(f"进度: {completed + failed}/{enqueued} ({(completed + failed) / enqueued * 100:.1f}%) - 成功: {completed}, 失败: {failed}")
                
            except KeyboardInterrupt:
                logger.info("接收到用户中断，正在优雅退出...")
                break
                
        logger.info("所有任务处理完成，准备关闭工作进程...")
        
    except Exception as e:
        logger.error(f"主进程处理结果时发生错误: {str(e)}")
    finally:
        # 停止所有工作进程
        stop_event.set()
        
        # 等待工作进程退出
        for i, p in enumerate(workers):
            logger.info(f"等待工作进程 {i+1} 退出...")
            p.join(timeout=5)
            if p.is_alive():
                logger.warning(f"工作进程 {i+1} 未能正常退出，强制终止")
                p.terminate()
    
    # 记录总体统计信息
    elapsed_time = time.time() - start_time
    logger.info(f"批量比较任务完成，耗时: {elapsed_time:.2f}秒")
    
    # 对于每对比较过的固件，判断相似性并计算指标
    # 这部分代码需要放在main函数的最后，处理已经比较过的结果
    # 在此之前重置TP/FP/TN/FN，因为它们将在此处完全重新计算
    total_tp = 0
    total_fp = 0
    total_tn = 0
    total_fn = 0
    for pair, similarity in similarity_results.items():
        # 跳过重复的对（每对固件只统计一次）
        if pair[0] > pair[1]: # 确保只处理 (fw1, fw2) 而不是 (fw2, fw1) 的重复项
            continue
            
        base_firmware, target_firmware = pair
        
        # 判断期望相似性
        expected_similar = tuple(sorted([base_firmware, target_firmware])) in similar_firmware_pairs
        
        # 判断实际相似性
        is_similar = similarity >= similarity_threshold
        
        # 更新统计
        if expected_similar and is_similar:  # 期望相似且实际相似
            total_tp += 1
        elif expected_similar and not is_similar:  # 期望相似但实际不相似
            total_fn += 1
        elif not expected_similar and is_similar:  # 期望不相似但实际相似
            total_fp += 1
        else:  # 期望不相似且实际不相似
            total_tn += 1
    
    # 计算并记录最终指标
    metrics = calculate_and_log_metrics(total_tp, total_fp, total_tn, total_fn)
    
    # 保存结果到JSON文件
    results_file = os.path.join(LOGS_DIR, f"batch_comparison_results_{log_timestamp}.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump({
            'summary': {
                'total_comparisons': total_comparisons,
                'completed': completed,
                'failed': failed,
                'skipped': skipped,
                'skipped_due_to_missing': skipped_due_to_missing,
                'elapsed_time': elapsed_time
            },
            'metrics': metrics,
            'missing_firmwares': list(missing_base_firmwares)
        }, f, indent=2, ensure_ascii=False)
    
    logger.info(f"比较结果已保存到: {results_file}")
    logger.info("批量比较任务完成")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"程序执行过程中发生错误: {str(e)}")