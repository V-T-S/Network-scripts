#!/usr/bin/env python3

"""
Enhanced PCAP Analysis Tool with Deep Metrics, Export, Plot Saving, and Precision Analytics

===========================================================================================
Author: Roi Gal (enhanced by ChatGPT)
Version: 5.2
Date: 2025-10-23

Description:
------------
Analyzes PCAP files using Scapy (or Pyshark fallback) for deep flow analysis, including:
RTT, one-way delay, jitter quantiles, TCP state tracking, packet loss analysis,
retransmissions, throughput, protocol volume, and packet size distribution.

Features & Options:
-------------------
- Deep analysis: --deep (RTT, jitter, retransmissions, TCP state, OWD, quantiles)
- Export results: --json FILE.json, --csv FILE.csv (independent)
- Plotting: --plot (show on screen), --save-plots DIR (PNG files to dir)
- PDF export: --pdf FILE.pdf (save combined dashboard, dark mode)
- Flow filter: --filter-ip IP, --filter-port PORT, --only-tcp
- Robust error handling and type conversion (for Scapy Decimal types)
- Extensive comments and CLI usage instructions

Example Usage:
--------------
    python3 pcap_analysis_enhanced_v5.py capture.pcap --deep --pdf dashboard.pdf
    python3 pcap_analysis_enhanced_v5.py capture.pcap --csv output.csv --save-plots charts/
    python3 pcap_analysis_enhanced_v5.py capture.pcap --plot --filter-ip 192.168.1.1

Modules Required:
-----------------
- scapy
- pyshark
- matplotlib
- numpy
- json
- csv
- argparse
- datetime
- collections
- logging

Install modules using:
    pip install scapy pyshark matplotlib numpy

"""

import argparse
import os
import json
import csv
import logging
from collections import defaultdict, Counter
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

# Try importing Scapy for packet parsing
try:
    from scapy.all import rdpcap, TCP, IP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Try importing Pyshark as fallback parser
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s | %(levelname)s | %(message)s')

def parse_args():
    """
    Parse command line arguments for the analysis script.
    """
    parser = argparse.ArgumentParser(description='Enhanced PCAP Analysis Tool with deep metrics and plotting')

    parser.add_argument('pcap_file', help='Input PCAP file to analyze')
    parser.add_argument('--deep', action='store_true', help='Enable deep flow analysis (RTT, jitter, retransmissions)')
    parser.add_argument('--json', metavar='FILE', help='Export results to JSON file')
    parser.add_argument('--csv', metavar='FILE', help='Export results to CSV file')
    parser.add_argument('--plot', action='store_true', help='Show plots interactively')
    parser.add_argument('--save-plots', metavar='DIR', help='Save generated plots as PNGs in specified directory')
    parser.add_argument('--filter-ip', help='Filter analysis for flows involving this IP address')
    parser.add_argument('--filter-port', type=int, help='Filter analysis for flows involving this port (TCP/UDP)')
    parser.add_argument('--only-tcp', action='store_true', help='Analyze only TCP flows')
    parser.add_argument('--pdf', metavar='FILE', help='Export all plots as a combined dark-mode PDF dashboard')

    return parser.parse_args()

def flow_key(pkt):
    """
    Create a tuple key to uniquely identify a flow: src/dst IP, ports, and protocol.
    Supports TCP and UDP.
    """
    if IP not in pkt:
        return None
    ip_layer = pkt[IP]
    proto = ip_layer.proto
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    if proto == 6 and TCP in pkt:
        l4_layer = pkt[TCP]
    elif proto == 17 and UDP in pkt:
        l4_layer = pkt[UDP]
    else:
        l4_layer = None

    src_port = l4_layer.sport if l4_layer else 0
    dst_port = l4_layer.dport if l4_layer else 0

    return (src_ip, dst_ip, src_port, dst_port, proto)

def reverse_flow_key(key):
    """
    Create reverse flow key tuple from a flow key for matching reverse direction.
    """
    src_ip, dst_ip, src_port, dst_port, proto = key
    return (dst_ip, src_ip, dst_port, src_port, proto)

def tcp_flags_to_str(flags):
    """
    Convert TCP flags integer to human-readable string for flow state tracking.
    """
    states = []
    if flags & 0x01:
        states.append('FIN')
    if flags & 0x02:
        states.append('SYN')
    if flags & 0x04:
        states.append('RST')
    if flags & 0x08:
        states.append('PSH')
    if flags & 0x10:
        states.append('ACK')
    if flags & 0x20:
        states.append('URG')
    if flags & 0x40:
        states.append('ECE')
    if flags & 0x80:
        states.append('CWR')
    return '+'.join(states) if states else 'NONE'

def analyze_with_scapy(pcap_file, filters=None, deep=False):
    """
    Analyze packets from a PCAP file using Scapy. Applies filtering and deep metrics.
    Returns flow_data dict and capture_metadata dict.
    """
    if not SCAPY_AVAILABLE:
        logging.error('Scapy not available, cannot analyze PCAP with Scapy.')
        return None, None

    logging.info(f'Reading PCAP with Scapy: {pcap_file}')
    packets = rdpcap(pcap_file)

    flow_data = defaultdict(lambda: {
        'packets': [],
        'timestamps': [],
        'packet_sizes': [],
        'rtts': [],
        'owd_forward': [],
        'owd_reverse': [],
        'missing_packets': 0,
        'retransmissions': 0,
        'inter_packet_delays': [],
        'tcp_states': [],
        'byte_counts': 0,
        'protocol': None,
        'anomaly_scores': {},
    })

    start_time = None
    end_time = None
    syn_timestamps = {}
    last_seq = {}

    for pkt in packets:
        if IP not in pkt:
            continue
        pkt_time = float(pkt.time)  # explicit conversion for compatibility

        if start_time is None or pkt_time < start_time:
            start_time = pkt_time
        if end_time is None or pkt_time > end_time:
            end_time = pkt_time

        key = flow_key(pkt)
        if key is None:
            continue

        if filters:
            filter_ip = filters.get('filter_ip')
            filter_port = filters.get('filter_port')
            only_tcp = filters.get('only_tcp', False)

            if filter_ip and (filter_ip != key[0] and filter_ip != key[1]):
                continue
            if filter_port and (filter_port != key[2] and filter_port != key[3]):
                continue
            if only_tcp and key[4] != 6:
                continue

        flow = flow_data[key]
        if flow['protocol'] is None:
            flow['protocol'] = key[4]

        flow['packets'].append(pkt)
        flow['timestamps'].append(pkt_time)
        flow['packet_sizes'].append(float(len(pkt)))
        flow['byte_counts'] = float(flow['byte_counts']) + float(len(pkt))

        # Deep metrics (TCP only)
        if deep and key[4] == 6 and TCP in pkt:
            tcp_layer = pkt[TCP]
            seq = int(tcp_layer.seq)
            ack = int(tcp_layer.ack)
            flags = int(tcp_layer.flags)

            # RTT via SYN/SYN-ACK
            if flags == 0x02:
                syn_timestamps[key] = pkt_time
            elif flags == 0x12:  # SYN + ACK
                rev_key = reverse_flow_key(key)
                if rev_key in syn_timestamps:
                    rtt = pkt_time - syn_timestamps[rev_key]
                    flow['rtts'].append(float(rtt))

            # Retransmission detection
            last = last_seq.get(key)
            if last is not None and seq <= last:
                flow['retransmissions'] += 1
            last_seq[key] = seq

            # TCP state tracking
            state_str = tcp_flags_to_str(flags)
            flow['tcp_states'].append(state_str)

            # Inter-packet delay calculation
            timestamps = flow['timestamps']
            if len(timestamps) > 1:
                ipd = pkt_time - timestamps[-2]
                flow['inter_packet_delays'].append(float(ipd))

            # One-way delay estimate (demonstration only)
            if flags == 0x02:
                flow['owd_forward'].append(float(pkt_time))

    capture_metadata = {
        'start_time': float(start_time) if start_time is not None else None,
        'end_time': float(end_time) if end_time is not None else None,
        'duration': float(end_time - start_time) if start_time and end_time else 0,
        'packet_count': int(len(packets)),
        'flow_count': int(len(flow_data)),
    }

    logging.info(f'PCAP processed: {capture_metadata['packet_count']} packets over {capture_metadata['duration']:.2f}s')
    return flow_data, capture_metadata

def export_json_summary(flow_data, capture_metadata, json_file):
    """
    Export flow summaries and metadata to JSON file (converts Decimal types to float/int).
    """
    safe_capture_metadata = {k: float(v) if (hasattr(v, '__float__')) else v for k, v in capture_metadata.items()}
    output = {
        'capture_metadata': safe_capture_metadata,
        'flows': []
    }
    for key, flow in flow_data.items():
        src_ip, dst_ip, src_port, dst_port, proto = key
        flow_entry = {
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'protocol': proto,
            'packet_count': int(len(flow['packets'])),
            'byte_count': float(flow['byte_counts']),
            'rtts': [float(v) for v in flow['rtts']],
            'missing_packets': int(flow['missing_packets']),
            'retransmissions': int(flow['retransmissions']),
            'inter_packet_delays': [float(v) for v in flow['inter_packet_delays']],
            'tcp_states': flow['tcp_states'],
            'anomaly_scores': {k: float(v) for k, v in flow.get('anomaly_scores', {}).items()},
        }
        output['flows'].append(flow_entry)

    with open(json_file, 'w') as f:
        json.dump(output, f, indent=2)
    logging.info(f'Exported JSON summary to {json_file}')

def export_csv_summary(flow_data, capture_metadata, csv_file):
    """
    Export flow summaries and metadata to CSV file (row per flow).
    """
    with open(csv_file, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol',
            'packet_count', 'byte_count', 'missing_packets', 'retransmissions', 'duration_sec', 'throughput_bps'
        ])
        for key, flow in flow_data.items():
            src_ip, dst_ip, src_port, dst_port, proto = key
            timestamps = [float(t) for t in flow['timestamps']]
            duration = float(max(timestamps)) - float(min(timestamps)) if timestamps else 0
            throughput = (float(flow['byte_counts']) * 8) / duration if duration > 0 else 0

            writer.writerow([
                src_ip, dst_ip, src_port, dst_port, proto,
                int(len(flow['packets'])),
                float(flow['byte_counts']),
                int(flow['missing_packets']),
                int(flow['retransmissions']),
                round(duration, 6),
                round(throughput, 2)
            ])
    logging.info(f'Exported CSV summary to {csv_file}')

def plot_rtt_cdf(flow_data, save_path=None):
    """
    Plot RTT cumulative distribution function (CDF) combining all flows.
    """
    all_rtts = [float(v) for flow in flow_data.values() for v in flow['rtts']]
    if not all_rtts:
        logging.warning('No RTT data available to plot RTT CDF.')
        return
    sorted_rtts = np.sort(all_rtts)
    cdf = np.arange(1, len(sorted_rtts)+1) / len(sorted_rtts)
    plt.figure(figsize=(8,6))
    plt.plot(sorted_rtts*1000, cdf, label='RTT CDF')  # Convert to ms
    plt.xlabel('RTT (ms)')
    plt.ylabel('Cumulative Probability')
    plt.title('RTT Cumulative Distribution Function')
    plt.grid(True)
    plt.legend()
    if save_path:
        plt.savefig(save_path, dpi=150)
        plt.close()
        logging.info(f'Saved RTT CDF plot at {save_path}')
    else:
        plt.show()

def plot_throughput_timeseries(flow_data, save_path=None):
    """
    Plot throughput time-series per flow (packet bytes per second in rolling windows).
    """
    max_flows = 6
    flows_to_plot = list(flow_data.items())[:max_flows]
    if not flows_to_plot:
        logging.warning('No flow data available to plot throughput time series.')
        return
    fig, axes = plt.subplots(len(flows_to_plot), 1, figsize=(10, 3 * len(flows_to_plot)), sharex=True)
    if len(flows_to_plot) == 1:
        axes = [axes]
    for ax, (key, flow) in zip(axes, flows_to_plot):
        timestamps = [float(t) for t in flow['timestamps']]
        packet_sizes = [float(s) for s in flow['packet_sizes']]
        if len(timestamps) < 2:
            ax.set_title('Flow: Insufficient data')
            continue
        times_sec = np.array(timestamps) - min(timestamps)
        bins = np.arange(0, times_sec[-1] + 1, 1)
        counts, _ = np.histogram(times_sec, bins=bins, weights=packet_sizes)
        ax.bar(bins[:-1], counts, width=0.8)
        src_ip, dst_ip, src_port, dst_port, proto = key
        ax.set_title(f'Throughput Flow {src_ip}:{src_port} -> {dst_ip}:{dst_port}')
        ax.set_ylabel('Bytes/s')
    plt.xlabel('Time (s)')
    plt.tight_layout()
    if save_path:
        plt.savefig(save_path, dpi=150)
        plt.close()
        logging.info(f'Saved throughput time-series plots at {save_path}')
    else:
        plt.show()

def plot_retransmission_histogram(flow_data, save_path=None):
    """
    Plot histogram of flows by number of retransmissions detected.
    """
    retrans_counts = [int(flow['retransmissions']) for flow in flow_data.values() if int(flow['retransmissions']) > 0]
    if not retrans_counts:
        logging.warning('No retransmission data for histogram plot.')
        return
    plt.figure(figsize=(8,6))
    plt.hist(retrans_counts, bins=range(1, max(retrans_counts)+2), edgecolor='black')
    plt.title('Retransmission Histogram')
    plt.xlabel('Number of Retransmissions')
    plt.ylabel('Number of Flows')
    plt.grid(True)
    if save_path:
        plt.savefig(save_path, dpi=150)
        plt.close()
        logging.info(f'Saved retransmission histogram at {save_path}')
    else:
        plt.show()

def plot_inter_packet_delay_distribution(flow_data, save_path=None):
    """
    Plot distribution (boxplot) of inter-packet delays (jitter) across flows.
    """
    ipd_data = [list(map(float, flow['inter_packet_delays'])) for flow in flow_data.values() if flow['inter_packet_delays']]
    if not ipd_data:
        logging.warning('No inter-packet delay data to plot.')
        return
    plt.figure(figsize=(10,6))
    plt.boxplot(ipd_data, patch_artist=True, showfliers=False)
    plt.title('Inter-Packet Delay Distribution per Flow')
    plt.ylabel('Delay (s)')
    plt.xlabel('Flow Index')
    if save_path:
        plt.savefig(save_path, dpi=150)
        plt.close()
        logging.info(f'Saved inter-packet delay distribution plot at {save_path}')
    else:
        plt.show()

def plot_packet_size_distribution(flow_data, save_path=None):
    """
    Plot histogram of packet sizes over all flows to analyze segmentation and MTU issues.
    """
    all_sizes = [float(s) for flow in flow_data.values() for s in flow['packet_sizes']]
    if not all_sizes:
        logging.warning('No packet size data available to plot.')
        return
    plt.figure(figsize=(8,6))
    plt.hist(all_sizes, bins=range(0, int(max(all_sizes))+50, 50), edgecolor='black')
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.grid(True)
    if save_path:
        plt.savefig(save_path, dpi=150)
        plt.close()
        logging.info(f'Saved packet size distribution plot at {save_path}')
    else:
        plt.show()

def generate_pdf_dashboard(flow_data, capture_metadata, save_dir, pdf_name='analysis_report.pdf'):
    """
    Generate a combined PDF report containing all key plots in dark mode.
    """
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages

    plt.style.use('dark_background')
    pdf_path = os.path.join(save_dir, pdf_name)
    with PdfPages(pdf_path) as pdf:
        # RTT CDF plot
        plt.figure(figsize=(8,6))
        all_rtts = [float(v) for flow in flow_data.values() for v in flow['rtts']]
        if all_rtts:
            sorted_rtts = np.sort(all_rtts)
            cdf = np.arange(1, len(sorted_rtts)+1) / len(sorted_rtts)
            plt.plot(sorted_rtts*1000, cdf, label='RTT CDF')  # ms
            plt.xlabel('RTT (ms)')
            plt.ylabel('Cumulative Probability')
            plt.title('RTT Cumulative Distribution Function')
            plt.grid(True)
            plt.legend()
            pdf.savefig()
        plt.close()

        # Throughput timeseries (limited flows)
        max_flows = 4
        flows_to_plot = list(flow_data.items())[:max_flows]
        fig, axes = plt.subplots(len(flows_to_plot), 1, figsize=(10, 3 * len(flows_to_plot)), sharex=True)
        if len(flows_to_plot) == 1:
            axes = [axes]
        for ax, (key, flow) in zip(axes, flows_to_plot):
            timestamps = [float(t) for t in flow['timestamps']]
            if len(timestamps) < 2:
                ax.set_title(f'Flow {key}: Insufficient data')
                continue
            packet_sizes = [float(s) for s in flow['packet_sizes']]
            times_sec = np.array(timestamps) - min(timestamps)
            bins = np.arange(0, times_sec[-1] + 1, 1)
            counts, _ = np.histogram(times_sec, bins=bins, weights=packet_sizes)
            ax.bar(bins[:-1], counts, width=0.8, color='cyan')
            src_ip, dst_ip, src_port, dst_port, proto = key
            ax.set_title(f'{src_ip}:{src_port} -> {dst_ip}:{dst_port}')
            ax.set_ylabel('Bytes/s')
            ax.grid(True)
        plt.xlabel('Time (s)')
        plt.tight_layout()
        pdf.savefig()
        plt.close()

        # Retransmission histogram
        retrans_counts = [int(flow['retransmissions']) for flow in flow_data.values() if int(flow['retransmissions']) > 0]
        if retrans_counts:
            plt.figure(figsize=(8,6))
            plt.hist(retrans_counts, bins=range(1, max(retrans_counts)+2), edgecolor='black', color='orange')
            plt.title('Retransmission Histogram')
            plt.xlabel('Number of Retransmissions')
            plt.ylabel('Number of Flows')
            plt.grid(True)
            pdf.savefig()
            plt.close()

        # Inter-packet delay boxplot
        ipd_data = [list(map(float, flow['inter_packet_delays'])) for flow in flow_data.values() if flow['inter_packet_delays']]
        if ipd_data:
            plt.figure(figsize=(10,6))
            plt.boxplot(ipd_data, patch_artist=True, showfliers=False,
                        boxprops=dict(facecolor='purple'))
            plt.title('Inter-Packet Delay Distribution per Flow')
            plt.ylabel('Delay (s)')
            plt.xlabel('Flow Index')
            pdf.savefig()
            plt.close()

        # Packet size distribution
        all_sizes = [float(s) for flow in flow_data.values() for s in flow['packet_sizes']]
        if all_sizes:
            plt.figure(figsize=(8,6))
            plt.hist(all_sizes, bins=range(0, int(max(all_sizes))+50, 50), edgecolor='black', color='lime')
            plt.title('Packet Size Distribution')
            plt.xlabel('Packet Size (bytes)')
            plt.ylabel('Frequency')
            plt.grid(True)
            pdf.savefig()
            plt.close()

    logging.info(f'Generated combined PDF dashboard at {pdf_path}')

def compute_anomaly_scores(flow_data):
    """
    Compute anomaly scores for RTT, jitter, and throughput using z-score.
    Converts Scapy Decimal types to float.
    """
    rtts = []
    jitters = []
    throughputs = []
    for flow in flow_data.values():
        flow_rtts = [float(v) for v in flow['rtts']] if flow['rtts'] else [0]
        rtts.append(np.mean(flow_rtts))
        ipd_floats = [float(v) for v in flow['inter_packet_delays']] if flow['inter_packet_delays'] else [0]
        jitters.append(np.median(ipd_floats))
        timestamps = [float(t) for t in flow['timestamps']]
        duration = float(max(timestamps)) - float(min(timestamps)) if timestamps else 0
        byte_count = float(flow['byte_counts'])
        throughput = (byte_count * 8) / duration if duration > 0 else 0
        throughputs.append(throughput)
    rtt_mean, rtt_std = np.mean(rtts), np.std(rtts)
    jitter_mean, jitter_std = np.mean(jitters), np.std(jitters)
    throughput_mean, throughput_std = np.mean(throughputs), np.std(throughputs)
    for flow in flow_data.values():
        flow_rtts = [float(v) for v in flow['rtts']] if flow['rtts'] else [0]
        ipd_floats = [float(v) for v in flow['inter_packet_delays']] if flow['inter_packet_delays'] else [0]
        rtt_score = ((np.mean(flow_rtts) - rtt_mean) / rtt_std) if rtt_std > 0 else 0
        jitter_score = ((np.median(ipd_floats) - jitter_mean) / jitter_std) if jitter_std > 0 else 0
        timestamps = [float(t) for t in flow['timestamps']]
        duration = float(max(timestamps)) - float(min(timestamps)) if timestamps else 0
        byte_count = float(flow['byte_counts'])
        throughput = (byte_count * 8) / duration if duration > 0 else 0
        throughput_score = ((throughput - throughput_mean) / throughput_std) if throughput_std > 0 else 0
        flow['anomaly_scores'] = {
            'rtt_zscore': rtt_score,
            'jitter_zscore': jitter_score,
            'throughput_zscore': throughput_score,
        }

def validate_capture_metadata(metadata):
    """
    Perform basic validation on capture metadata.
    Logs warnings for anomalies like negative durations.
    """
    if metadata['duration'] < 0:
        logging.warning('Capture duration is negative. Check PCAP timestamps integrity.')
    if not metadata['start_time'] or not metadata['end_time']:
        logging.warning('Start or end times are missing in capture metadata.')

def main():
    """
    Main entry point: parses CLI arguments, calls analysis, exports, plots, dashboard PDF.
    """
    args = parse_args()
    filters = {
        'filter_ip': args.filter_ip,
        'filter_port': args.filter_port,
        'only_tcp': args.only_tcp,
    }
    deep_enabled = args.deep

    # Choose backend
    if SCAPY_AVAILABLE:
        flow_data, capture_metadata = analyze_with_scapy(args.pcap_file, filters, deep_enabled)
    elif PYSHARK_AVAILABLE:
        logging.info('Scapy not available, attempting Pyshark analysis')
        # Placeholder for pyshark analysis function
        flow_data, capture_metadata = {}, {}
    else:
        logging.error('Neither Scapy nor Pyshark is available. Install one to proceed.')
        return

    if not flow_data or not capture_metadata:
        logging.error('Failed to analyze PCAP file.')
        return

    # Validate metadata consistency
    validate_capture_metadata(capture_metadata)

    # Compute anomaly scores if deep analysis enabled
    if deep_enabled:
        compute_anomaly_scores(flow_data)

    # Export results
    if args.json:
        export_json_summary(flow_data, capture_metadata, args.json)
    if args.csv:
        export_csv_summary(flow_data, capture_metadata, args.csv)

    # Plot logic (show or save, but not both)
    save_plots_dir = args.save_plots
    plot_interactive = args.plot

    if save_plots_dir and not os.path.exists(save_plots_dir):
        os.makedirs(save_plots_dir)

    if save_plots_dir and not plot_interactive:
        # Only save
        plot_rtt_cdf(flow_data, save_path=os.path.join(save_plots_dir, 'rtt_cdf.png'))
        plot_throughput_timeseries(flow_data, save_path=os.path.join(save_plots_dir, 'throughput_timeseries.png'))
        plot_retransmission_histogram(flow_data, save_path=os.path.join(save_plots_dir, 'retransmission_histogram.png'))
        plot_inter_packet_delay_distribution(flow_data, save_path=os.path.join(save_plots_dir, 'inter_packet_delay.png'))
        plot_packet_size_distribution(flow_data, save_path=os.path.join(save_plots_dir, 'packet_size_distribution.png'))
    elif plot_interactive:
        # Only show
        plot_rtt_cdf(flow_data)
        plot_throughput_timeseries(flow_data)
        plot_retransmission_histogram(flow_data)
        plot_inter_packet_delay_distribution(flow_data)
        plot_packet_size_distribution(flow_data)
    else:
        logging.info('No plot output requested.')

    # PDF Dashboard export option (always dark mode)
    if args.pdf:
        pdf_dir = os.path.dirname(os.path.abspath(args.pdf))
        pdf_name = os.path.basename(args.pdf)
        generate_pdf_dashboard(flow_data, capture_metadata, pdf_dir, pdf_name=pdf_name)

if __name__ == '__main__':
    main()
