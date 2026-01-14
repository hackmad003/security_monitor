"""
Windows Security Event Monitor
Main Entry Point
"""

import sys
import argparse
from pathlib import Path

# Add security_monitor to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from security_monitor import SecurityMonitor, Config
from security_monitor.core.multi_target_monitor import MultiTargetMonitor


def main():
    """Main execution function"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Windows Security Event Monitor')
    
    parser.add_argument(
        '--mode',
        choices=['single', 'realtime', 'stats', 'multi'],
        default='single',
        help='Operating mode: single (one-time local), realtime (continuous multi-target), stats (view statistics), multi (one-time multi-target)'
    )
    
    parser.add_argument(
        '--events',
        type=int,
        default=100,  # Changed from 5000 to 100 for better performance
        help='Number of events to analyze per check'
    )
    
    parser.add_argument(
        '--interval',
        type=int,
        default=10,
        help='Check interval for realtime mode (seconds)'
    )
    
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days for statistics mode'
    )
    
    parser.add_argument(
        '--target',
        type=str,
        help='Specific target to monitor (for multi mode)'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = Config()
    
    # MULTI-TARGET MODE (one-time check)
    if args.mode == 'multi':
        print("\n🌐 Starting Multi-Target Monitoring...")
        multi_monitor = MultiTargetMonitor(config)
        results = multi_monitor.monitor_all_targets(parallel=True)
        
        # Process aggregated results
        print("\n📊 Aggregated Results:")
        print("-" * 60)
        for result in results:
            if result['success']:
                print(f"  ✅ {result['target']}: {result['events_found']} events")
            else:
                print(f"  ❌ {result['target']}: {result.get('error', 'Unknown error')}")
        print()
        return 0
    
    # REALTIME MODE (continuous multi-target monitoring)
    elif args.mode == 'realtime':
        print("\n🌐 Starting Real-Time Multi-Target Monitoring...")
        multi_monitor = MultiTargetMonitor(config)
        multi_monitor.start_realtime_monitoring(
            interval_seconds=args.interval
        )
        return 0
    
    # SINGLE MODE (one-time local analysis)
    elif args.mode == 'single':
        with SecurityMonitor(config) as monitor:
            results = monitor.run_analysis(num_events=args.events)
        return 0
    
    # STATS MODE (display statistics)
    elif args.mode == 'stats':
        with SecurityMonitor(config) as monitor:
            monitor.display_statistics(days=args.days)
        return 0
    
    return 0


if __name__ == "__main__":
    sys.exit(main())